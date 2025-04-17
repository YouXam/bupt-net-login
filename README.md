# bupt-net-login

登录北邮校园网的命令行工具

## 安装

### C++ 版本

适用于 Linux 系统，可在 openwrt 上运行。

1. 从 GitHub Releases 安装

    在 [releases](https://github.com/YouXam/bupt-net-login/releases) 页面下载最新版本的的以 `bupt-net-login_cpp` 开头的压缩包。
2. 从源码编译

    如果需要在对应的 OpenWrt 路由器上运行，需要先下载对应的 OpenWrt SDK。

    然后修改 cpp/makefile 添加必要的编译参数，编译。例如：

    ```shell
    make TOOLCHAIN=mipsel-linux-musl-cross/bin/mipsel-linux-musl
    ```

### Rust 版本

适用于 arm 和 x86_64 架构的 Linux、 macOS 和 Windows 系统。


1. 从 crates.io 安装

    ```
    cargo install bupt-net-login
    ```
2. 从 GitHub Releases 安装
    
    在 [releases](https://github.com/YouXam/bupt-net-login/releases) 页面下载最新版本的的以 `
    bupt-net-login_rust` 开头的压缩包。

## Usage

### C++ 版本

```shell
$ bupt-net-login -h
bupt-net-login

  登录北邮校园网的命令行工具
  凭据读取顺序: 环境变量 -> 配置文件 (~/.bupt-net-login) -> 交互输入。

  版权所有: YouXam (github.com/YouXam/bupt-net-login)

使用方式: cpp/bupt-net-login [OPTIONS]

选项:
  -o, --log-file FILE    将日志写入 FILE
  -s, --max-size SIZE    日志轮转大小 (如 1M)
  -i, --interval SEC     每 SEC 秒循环一次（默认单次运行）
  -d, --debug            输出调试信息
  -h, --help             显示此帮助
```

### Rust 版本

```shell
bupt-net-login

  A simple tool to login BUPT net using student ID and password.

  Copyright by YouXam (github.com/YouXam/bupt-net-login).

Usage: bupt-net-login [OPTIONS]

Options:
  -u, --student-id <STUDENT_ID>  BUPT student ID
  -p, --password <PASSWORD>      BUPT netaccount password
  -s, --save                     Whether to save password
  -k, --keep-alive               Whether to keep alive
  -i, --interval <INTERVAL>      Interval to keep alive in seconds [default: 1800]
  -h, --help                     Print help
  -V, --version                  Print version
```
