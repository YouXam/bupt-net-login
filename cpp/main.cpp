// Author: YouXam (github.com/YouXam)
// License: GPL‑2.0+

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <vector>

//--------------------------------------------------------------------
// Global i18n helper
//--------------------------------------------------------------------
static bool isChineseEnv() {
    const char *vars[] = {"LC_ALL", "LC_MESSAGES", "LANG"};
    for (auto v : vars) {
        const char *e = getenv(v);
        if (e && strstr(e, "zh")) return true;
    }
    return false;
}
static bool gZH = false;  // set in main()

#define MSG_EN(en, zh) (gZH ? (zh) : (en))

//--------------------------------------------------------------------
// ANSI colours
//--------------------------------------------------------------------
static const char *CLR_RESET = "\033[0m";
static const char *CLR_CYAN = "\033[0;36m";
static const char *CLR_YELLOW = "\033[0;33m";
static const char *CLR_RED = "\033[0;31m";
static const char *CLR_GRAY = "\033[0;90m";

//--------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------
static std::string now() {
    time_t t = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
    return buf;
}
static bool fileExists(const std::string &p) {
    struct stat st{};
    return stat(p.c_str(), &st) == 0;
}
static off_t fileSize(const std::string &p) {
    struct stat st{};
    return stat(p.c_str(), &st) == 0 ? st.st_size : 0;
}

//--------------------------------------------------------------------
// Logger
//--------------------------------------------------------------------
bool debug_enabled = false;
class Logger {
   public:
    enum Level { INFO, WARN, ERRO, FATA };
    Logger(std::ostream &out, const std::string &file = "", off_t max = 0)
        : _out(out), _path(file), _max(max) {}
    void log(Level lv, const char *fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        vlog(lv, fmt, ap);
        va_end(ap);
    }

   private:
    std::ostream &_out;
    std::ofstream _f;
    std::string _path;
    off_t _max;
    static std::string stripAnsi(const std::string &s) {
        std::string r;
        for (size_t i = 0; i < s.size();) {
            if (s[i] == '\033' && i + 1 < s.size() && s[i + 1] == '[') {
                size_t j = i + 2;
                while (j < s.size() && s[j] != 'm') ++j;
                if (j < s.size())
                    i = j + 1;
                else
                    break;
            } else {
                r.push_back(s[i++]);
            }
        }
        return r;
    }
    void pruneHead() {
        if (_path.empty()) return;
        std::ifstream fin(_path);
        if (!fin) return;
        std::vector<std::string> lines;
        std::string l;
        while (std::getline(fin, l)) lines.push_back(l + '\n');
        fin.close();
        if (lines.empty()) return;
        size_t cut = (lines.size() + 2) / 3;
        std::ofstream fout(_path, std::ios::trunc);
        for (size_t i = cut; i < lines.size(); ++i) fout << lines[i];
        fout.close();
        _f.close();
    }
    void rotate() {
        if (!_max || _path.empty()) return;
        if (fileSize(_path) <= _max) return;
        pruneHead();
    }
    void vlog(Level lv, const char *fmt, va_list ap) {
        char buf[2048];
        vsnprintf(buf, sizeof(buf), fmt, ap);
        const char *tag = lv == INFO   ? "INFO"
                          : lv == WARN ? "WARN"
                          : lv == ERRO ? "ERRO"
                                       : "FATA";
        const char *clr = lv == INFO   ? CLR_CYAN
                          : lv == WARN ? CLR_YELLOW
                                       : CLR_RED;
        std::string coloured = std::string(clr) + tag + CLR_RESET + "[" +
                               now() + "] " + buf + "\n";
        _out << coloured;
        _out.flush();
        if (!_path.empty()) {
            rotate();
            _f.open(_path, std::ios::app);
            _f << stripAnsi(coloured);
            _f.close();
        }
        if (lv == FATA) exit(1);
    }
};

bool debug_start = true;
static void debug_chunk(const char *prefix, const std::string &content) {
    if (!debug_enabled || content.empty()) return;
    std::cerr << CLR_GRAY;
    if (debug_start) {
        std::cerr << prefix;
        debug_start = false;
    }
    bool next_prefix = false;
    for (auto c : content) {
        if (c == '\r') continue;
        if (next_prefix) {
            std::cerr << prefix;
            next_prefix = false;
        }
        std::cerr << c;
        if (c == '\n') {
            next_prefix = true;
        }
    }
    std::cerr << CLR_RESET;
    std::cerr << std::flush;
}
static void debug(const char *prefix, const std::string &content) {
    debug_start = true;
    debug_chunk(prefix, content);
}

//--------------------------------------------------------------------
// URL parsing
//--------------------------------------------------------------------
struct Url {
    std::string host, path;
    int port = 80;
    bool ok = false;
};
static Url parseUrl(const std::string &u) {
    Url r;
    if (u.compare(0, 7, "http://")) return r;
    std::string s = u.substr(7);
    size_t slash = s.find('/');
    std::string host =
        s.substr(0, slash == std::string::npos ? s.size() : slash);
    r.path = slash == std::string::npos ? "/" : s.substr(slash);
    size_t colon = host.find(':');
    if (colon == std::string::npos) {
        r.host = host;
    } else {
        r.host = host.substr(0, colon);
        r.port = atoi(host.substr(colon + 1).c_str());
    }
    r.ok = true;
    return r;
}

//--------------------------------------------------------------------
// Minimal HTTP
//--------------------------------------------------------------------

struct Response {
    int status = 0;
    std::map<std::string, std::string> hdr;
    std::string body;
};
static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}
static bool decodeChunked(const std::string &in, std::string &out) {
    size_t p = 0;
    while (true) {
        size_t nl = in.find("\r\n", p);
        if (nl == std::string::npos) return false;
        unsigned len;
        std::stringstream ss;
        ss << std::hex << in.substr(p, nl - p);
        ss >> len;
        p = nl + 2;
        if (len == 0) return true;
        if (p + len > in.size()) return false;
        out.append(in, p, len);
        p += len + 2;
    }
}
static std::string cookieHdr(const std::map<std::string, std::string> &c) {
    if (c.empty()) return "";
    std::string s = "Cookie: ";
    bool first = true;
    for (auto &kv : c) {
        if (!first) s += "; ";
        first = false;
        s += kv.first + "=" + kv.second;
    }
    return s + "\r\n";
}

static bool httpReq(const Url &url, const std::string &method,
                    const std::string &payload,
                    const std::map<std::string, std::string> &sendCk,
                    Response &resp,
                    std::map<std::string, std::string> *recvCk = nullptr) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (int e = getaddrinfo(url.host.c_str(), std::to_string(url.port).c_str(),
                            &hints, &res)) {
        std::cerr << "getaddrinfo(" << url.host << "): " << gai_strerror(e)
                  << "\n";
        return false;
    }
    debug("* ", "Host " + url.host + " resolved\n");
    int s = -1;
    for (auto p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        char ipbuf[INET6_ADDRSTRLEN] = {0};
        std::string ip;
        if (p->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)p->ai_addr)->sin_addr,
                      ipbuf, sizeof(ipbuf));
        } else if (p->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr,
                      ipbuf, sizeof(ipbuf));
        }
        ip = ipbuf;
        debug("* ", "  Trying " + ip + ":" + std::to_string(url.port) + "\n");
        if (connect(s, p->ai_addr, p->ai_addrlen) == 0) {
            debug("* ", "Connected to " + url.host + " (" + ip + ") port " +
                            std::to_string(url.port) + "\n");
            break;
        }
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    if (s < 0) {
        perror("connect");
        return false;
    }
    std::ostringstream rq;
    rq << method << " " << url.path << " HTTP/1.0\r\n"
       << "Host: " << url.host << "\r\n"
       << "User-Agent: bupt-net-login.cpp/1.0\r\n"
       << "Connection: close\r\n"
       << cookieHdr(sendCk);
    if (method == "POST") {
        rq << "Content-Type: application/x-www-form-urlencoded\r\n"
           << "Content-Length: " << payload.size() << "\r\n";
    }
    rq << "\r\n";
    if (method == "POST") rq << payload;
    std::string rqStr = rq.str();
    debug("> ", rqStr + (method == "POST" ? "\n\n" : ""));
    size_t sent = 0;
    while (sent < rqStr.size()) {
        ssize_t n = write(s, rqStr.data() + sent, rqStr.size() - sent);
        if (n <= 0) {
            perror("write");
            close(s);
            return false;
        }
        sent += n;
    }
    debug_start = true;
    std::string headerBuf;
    char ch;
    while (true) {
        ssize_t n = read(s, &ch, 1);
        if (n <= 0) {
            close(s);
            return false;
        }
        headerBuf.push_back(ch);
        if (headerBuf.size() >= 4 &&
            headerBuf.rfind("\r\n\r\n") == headerBuf.size() - 4)
            break;
    }
    debug_chunk("< ", headerBuf.data());
    // Parse header
    std::istringstream hs(headerBuf);
    std::string line;
    getline(hs, line);
    if (line.size() && line.back() == '\r') line.pop_back();
    {
        std::istringstream sl(line);
        std::string httpv;
        sl >> httpv >> resp.status;
    }
    while (std::getline(hs, line)) {
        if (line.size() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        size_t col = line.find(':');
        if (col == std::string::npos) continue;
        std::string k = lower(line.substr(0, col));
        std::string v = line.substr(col + 1);
        while (!v.empty() && isspace(v.front())) v.erase(v.begin());
        resp.hdr[k] = v;
        if (recvCk && k == "set-cookie") {
            size_t semi = v.find(';');
            std::string kv = v.substr(0, semi);
            size_t eq = kv.find('=');
            if (eq != std::string::npos)
                (*recvCk)[kv.substr(0, eq)] = kv.substr(eq + 1);
        }
    }
    size_t contentLen = 0;
    bool hasLen = false;
    if (resp.hdr.count("content-length")) {
        contentLen = std::stoul(resp.hdr["content-length"]);
        hasLen = true;
    }
    std::string body;
    char buf[4096];
    if (hasLen) {
        while (body.size() < contentLen) {
            ssize_t n =
                read(s, buf, std::min(sizeof(buf), contentLen - body.size()));
            if (n <= 0) {
                close(s);
                return false;
            }
            body.append(buf, n);
            debug_chunk("< ", buf);
        }
    } else if (resp.hdr.count("transfer-encoding") &&
               resp.hdr["transfer-encoding"].find("chunked") !=
                   std::string::npos) {
        std::string chunkRaw;
        while (true) {
            ssize_t n = read(s, buf, sizeof(buf));
            if (n <= 0) break;
            chunkRaw.append(buf, n);
            debug_chunk("< ", buf);
        }
        if (!decodeChunked(chunkRaw, body)) {
            close(s);
            return false;
        }
    } else {
        while (true) {
            ssize_t n = read(s, buf, sizeof(buf));
            if (n <= 0) break;
            body.append(buf, n);
            debug_chunk("< ", buf);
        }
    }
    close(s);
    resp.body = body;
    return true;
}

//--------------------------------------------------------------------
// Misc helpers
//--------------------------------------------------------------------
static std::string urlEncode(const std::string &s) {
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            out.push_back(c);
        else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 15]);
        }
    }
    return out;
}

//--------------------------------------------------------------------
// Credential handling
//--------------------------------------------------------------------
struct Credential {
    std::string user, pass;
};
static std::string promptHidden(const char *prompt) {
    std::cerr << prompt;
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::string s;
    std::getline(std::cin, s);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cerr << "\n";
    return s;
}
static Credential askCredential(Logger &log) {
    Credential c;
    std::string cfg = std::string(getenv("HOME")) + "/.bupt-net-login";
    const char *u = getenv("BUPT_USERNAME"), *p = getenv("BUPT_PASSWORD");
    if (u && p) {
        c.user = u;
        c.pass = p;
        return c;
    }
    if (fileExists(cfg)) {
        std::ifstream in(cfg);
        std::string line;
        while (std::getline(in, line)) {
            if (line.find("BUPT_USERNAME") != std::string::npos) {
                size_t q = line.find("'");
                size_t q2 = line.rfind("'");
                if (q != std::string::npos && q2 > q)
                    c.user = line.substr(q + 1, q2 - q - 1);
            }
            if (line.find("BUPT_PASSWORD") != std::string::npos) {
                size_t q = line.find("'");
                size_t q2 = line.rfind("'");
                if (q != std::string::npos && q2 > q)
                    c.pass = line.substr(q + 1, q2 - q - 1);
            }
        }
        return c;
    }
    if (c.user.empty()) {
        std::cerr << MSG_EN("Username (student ID): ", "请输入学号: ");
        std::getline(std::cin, c.user);
    }
    if (c.pass.empty()) {
        c.pass = promptHidden(
            MSG_EN("Campus network password: ", "请输入校园网密码: "));
    }
    // Ask to save
    std::cerr << MSG_EN("Save credentials to ", "是否保存凭据到 ") << cfg
              << MSG_EN(" for future auto‑login? [y/N] ",
                        " 以便下次自动登录？[y/N] ");
    char ch;
    std::cin >> ch;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    if (ch == 'y' || ch == 'Y') {
        std::ofstream o(cfg, std::ios::trunc);
        o << "BUPT_USERNAME='" << c.user << "'\n"
          << "BUPT_PASSWORD='" << c.pass << "'\n";
        o.close();
        chmod(cfg.c_str(), 0600);
        log.log(Logger::INFO,
                MSG_EN("Credentials saved to %s", "凭据已保存到 %s"),
                cfg.c_str());
    }
    return c;
}

//--------------------------------------------------------------------
// Config
//--------------------------------------------------------------------
struct Config {
    std::string logFile;
    off_t maxSize = 0;
    int intervalSec = 0;
    std::string testURL =
        "http://connect.rom.miui.com/generate_204?cmd=redirect&arubalp=12345";
};

//--------------------------------------------------------------------
// Workflow
//--------------------------------------------------------------------
static bool doLogin(Logger &log, const Config &cfg, const Credential &cred,
                    const std::string &authURL) {
    Url url = parseUrl(authURL);
    if (!url.ok) {
        log.log(Logger::ERRO,
                MSG_EN("Invalid auth URL %s", "无效的认证地址 %s"),
                authURL.c_str());
        return false;
    }
    std::map<std::string, std::string> cookies;
    Response r;
    if (!httpReq(url, "GET", "", {}, r, &cookies)) {
        log.log(Logger::ERRO,
                MSG_EN("Failed to fetch cookie", "获取 Cookie 失败"));
        return false;
    }
    std::string loginURL = authURL;
    size_t p = loginURL.find("index");
    if (p != std::string::npos) loginURL.replace(p, 5, "login");
    Url lurl = parseUrl(loginURL);
    std::string payload =
        "user=" + urlEncode(cred.user) + "&pass=" + urlEncode(cred.pass);
    Response r2;
    if (!httpReq(lurl, "POST", payload, cookies, r2)) {
        log.log(Logger::ERRO, MSG_EN("POST login failed", "发送登录请求失败"));
        return false;
    }
    Url t = parseUrl(cfg.testURL);
    Response tResp;
    return httpReq(t, "GET", "", {}, tResp) && tResp.status == 204;
}
static void runOnce(const Config &cfg, Logger &log) {
    Url t = parseUrl(cfg.testURL);
    if (!t.ok) {
        log.log(Logger::ERRO, MSG_EN("Bad test URL", "探测 URL 无效"));
        return;
    }
    Response resp;
    if (!httpReq(t, "GET", "", {}, resp)) {
        log.log(Logger::ERRO, MSG_EN("Probe failed", "网络探测失败"));
        return;
    }
    if (resp.status == 204) {
        log.log(Logger::INFO, MSG_EN("You are already logged in.",
                                     "您已经登录，无需重新认证。"));
        return;
    }
    if (resp.status >= 300 && resp.status < 400 && resp.hdr.count("location")) {
        std::string loc = resp.hdr["location"];
        if (loc.find("10.3.8") != std::string::npos) {
            Credential cred = askCredential(log);
            log.log(Logger::INFO,
                    MSG_EN("Not logged in, authenticating %s ...",
                           "检测到未登录，正在使用账号 %s 认证 ..."),
                    cred.user.c_str());
            if (doLogin(log, cfg, cred, loc))
                log.log(Logger::INFO,
                        MSG_EN("User %s authenticated successfully.",
                               "账号 %s 认证成功。"),
                        cred.user.c_str());
            else
                log.log(Logger::ERRO,
                        MSG_EN("Authentication failed for %s.",
                               "账号 %s 认证失败。"),
                        cred.user.c_str());
            return;
        }
    }
    log.log(Logger::ERRO,
            MSG_EN("Unknown response, login failed.", "未知响应，认证失败。"));
}

//--------------------------------------------------------------------
// Usage
//--------------------------------------------------------------------
static void usage(const char *prog) {
    std::cout
        << MSG_EN(
               "bupt-net-login\n\n"
               "  A simple tool to login BUPT net using student ID and password.\n"
               "  Credential precedence: env vars -> config file (~/.bupt-net-login) -> interactive prompt.\n\n"
               "  Copyright by YouXam (github.com/YouXam/bupt-net-login).\n\n",
               "bupt-net-login\n\n"
               "  登录北邮校园网的命令行工具\n"
               "  凭据读取顺序: 环境变量 -> 配置文件 (~/.bupt-net-login) -> 交互输入。\n\n"
               "  版权所有: YouXam (github.com/YouXam/bupt-net-login)\n\n"
            )
        << MSG_EN("Usage:", "使用方式:") << " " << prog << " [OPTIONS]\n\n"
        << MSG_EN("Options:", "选项:") << "\n"
        << MSG_EN(
               "  -o, --log-file FILE    write logs to FILE\n"
               "  -s, --max-size SIZE    rotate log at SIZE (e.g. 1M)\n"
               "  -i, --interval SEC     loop every SEC seconds (default "
               "once)\n"
               "  -d, --debug            output debug info\n"
               "  -h, --help             show this help\n\n",
               "  -o, --log-file FILE    将日志写入 FILE\n"
               "  -s, --max-size SIZE    日志轮转大小 (如 1M)\n"
               "  -i, --interval SEC     每 SEC 秒循环一次（默认单次运行）\n"
               "  -d, --debug            输出调试信息\n"
               "  -h, --help             显示此帮助\n\n");
}

static off_t parseSize(const std::string &s) {
    if (s.empty()) return 0;
    char u = s.back();
    long long m = 1;
    std::string num = s;
    if (!isdigit(u)) {
        num = s.substr(0, s.size() - 1);
        if (u == 'K' || u == 'k')
            m = 1024;
        else if (u == 'M' || u == 'm')
            m = 1024 * 1024;
        else if (u == 'G' || u == 'g')
            m = 1024LL * 1024 * 1024;
    }
    return atoll(num.c_str()) * m;
}

//--------------------------------------------------------------------
int main(int argc, char *argv[]) {
    gZH = isChineseEnv();
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-o" || a == "--log-file") {
            if (i + 1 < argc)
                cfg.logFile = argv[++i];
            else {
                usage(argv[0]);
                return 1;
            }
        } else if (a == "-s" || a == "--max-size") {
            if (i + 1 < argc)
                cfg.maxSize = parseSize(argv[++i]);
            else {
                usage(argv[0]);
                return 1;
            }
        } else if (a == "-i" || a == "--interval") {
            if (i + 1 < argc)
                cfg.intervalSec = atoi(argv[++i]);
            else {
                usage(argv[0]);
                return 1;
            }
        } else if (a == "-d" || a == "--debug") {
            debug_enabled = true;
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else {
            std::cerr << MSG_EN("Unknown option ", "未知参数 ") << a << "\n\n";
            usage(argv[0]);
            return 1;
        }
    }
    Logger log(std::cerr, cfg.logFile, cfg.maxSize);
    if (cfg.intervalSec <= 0) {
        runOnce(cfg, log);
    } else {
        log.log(Logger::INFO,
                MSG_EN("Running every %d seconds ...", "每 %d 秒运行一次 ..."),
                cfg.intervalSec);
        while (true) {
            runOnce(cfg, log);
            sleep(cfg.intervalSec);
        }
    }
    return 0;
}
