use std::process::exit;

use chrono;
use clap::Parser;
use dirs_next::config_dir;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use url::Url;

static mut PRINT_TIME: bool = false;
const TEST_URL: &str = "http://connect.rom.miui.com/generate_204";

fn log(message: &str) {
    unsafe {
        if PRINT_TIME {
            println!(
                "[{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                message
            );
        } else {
            println!("{}", message);
        }
    }
}

macro_rules! log {
    ($($arg:tt)*) => {{
        let formatted_message = format!($($arg)*);
        log(&formatted_message);
    }};
}

fn auth(login_url: Url, cookies: &str, username: &str, password: &str) -> bool {
    log!(
        "Authenticating to URL {} using account {}...",
        login_url,
        username
    );
    let body = serde_urlencoded::to_string([("user", username), ("pass", password)]).unwrap();
    let resp = minreq::post(login_url.as_str())
        .with_header("Cookie", cookies)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_body(body)
        .send();

    match resp {
        Ok(r) => {
            if r.status_code == 200 {
                if check_status(TEST_URL) {
                    log!("Successfully logged in.");
                    return true;
                }
                let body = r.as_str().unwrap_or_default();
                let reason = body
                    .find("<div class=\"ui error message\">")
                    .and_then(|start| {
                        body[start..]
                            .find("</div>")
                            .map(|end| body[start + 30..start + end].trim().to_string())
                    })
                    .unwrap_or_else(|| "Unknown error".into());
                log!("\tError: {}", reason);
                log!("Failed to login. Please check username and password.");
                false
            } else {
                log!("Login request failed: HTTP {}", r.status_code);
                false
            }
        }
        Err(e) => {
            log!("Failed to send login request: {}", e);
            false
        }
    }
}

fn check_status(url: &str) -> bool {
    let resp = minreq::get(url)
        .send();
    matches!(resp, Ok(r) if r.status_code==204)
}

fn login(redirected_auth_url: &str, username: &str, password: &str, retry: bool) -> bool {
    let resp = minreq::get(redirected_auth_url)
        .send();

    match resp {
        Ok(r) => {
            if r.status_code == 204 {
                log!("Already logged in");
                return true;
            }
            let cookies = &r
                .headers
                .get("set-cookie")
                .expect("Failed to get cookies");
            let mut url = url::Url::parse(&r.url.to_string()).unwrap();
            url.set_path("/login");
            url.set_query(None);
            auth(url, cookies, username, password)
        }
        Err(e) => {
            log!("Encountered an error: {}", e);
            if retry {
                false
            } else {
                login(
                    "http://1.2.3.4/?cmd=redirect&arubalp=12345",
                    username,
                    password,
                    true,
                )
            }
        }
    }
}

fn try_login(username: &str, password: &str) -> Result<(), ()> {
    log!("Trying to login...");
    if login(
        &(TEST_URL.to_owned() + "?cmd=redirect&arubalp=12345"),
        username,
        password,
        false,
    ) {
        Ok(())
    } else {
        Err(())
    }
}

#[derive(Serialize, Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

fn get_config_path() -> io::Result<PathBuf> {
    let mut path = config_dir().ok_or(io::Error::new(
        io::ErrorKind::NotFound,
        "Cannot find config directory",
    ))?;
    path.push("bupt-net-login");
    fs::create_dir_all(&path)?;
    path.push("credentials.json");
    Ok(path)
}

fn save_credentials(username: &str, password: &str) -> io::Result<()> {
    let credentials = Credentials {
        username: username.into(),
        password: password.into(),
    };
    let path = get_config_path()?;
    let mut file = File::create(&path)?;
    file.write_all(serde_json::to_string_pretty(&credentials)?.as_bytes())?;
    println!("Credentials saved to {}", path.to_string_lossy());
    Ok(())
}

fn load_credentials() -> io::Result<Credentials> {
    let path = get_config_path()?;
    let mut contents = String::new();
    File::open(path)?.read_to_string(&mut contents)?;
    Ok(serde_json::from_str(&contents)?)
}

#[derive(Parser, Debug)]
#[command(version, about = format!(
    "{}\n\n  A simple tool to login BUPT net using student ID and password.\n\n  Copyright by {} (github.com/YouXam/bupt-net-login).",
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_AUTHORS")
))]
struct Args {
    /// BUPT student ID
    #[arg(short = 'u', long)]
    student_id: Option<String>,

    /// BUPT netaccount password
    #[arg(short = 'p', long)]
    password: Option<String>,

    /// Whether to save password
    #[arg(short = 's', long)]
    save: bool,

    /// Whether to keep alive
    #[arg(short, long)]
    keep_alive: bool,

    /// Interval to keep alive in seconds
    #[arg(short, long, default_value = "1800")]
    interval: u64,
}

fn input(prompt: &str, default: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("stdin error");
    if input.trim().is_empty() { default.to_owned() } else { input.trim().into() }
}

fn main() -> Result<(), ()> {
    let args = Args::parse();
    let mut saved_credentials = false;

    let mut student_id = args.student_id;
    let mut password = args.password;

    if let Ok(c) = load_credentials() {
        saved_credentials = true;
        if student_id.is_none() && password.is_none() {
            student_id = Some(c.username);
            password = Some(c.password);
        }
    }

    if student_id.is_none() && password.is_none() {
        log!("Checking network...");
        if check_status(TEST_URL) {
            println!("Already logged in");
            return Ok(());
        }
    }

    while student_id.is_none() {
        let in_id = input("Enter your student ID: ", "");
        if !in_id.is_empty() { student_id = Some(in_id); }
    }

    let password = match password {
        Some(p) => p,
        None => prompt_password("Password: ").unwrap_or_else(|e| {
            println!("Failed to read password: {}", e);
            exit(1);
        }),
    };
    if password.is_empty() { println!("Password cannot be empty."); exit(1); }

    if let Some(user) = student_id {
        if args.keep_alive { unsafe { PRINT_TIME = true; } }
        try_login(&user, &password)?;
        if args.save {
            if save_credentials(&user, &password).is_err() { println!("Save failed"); exit(1); }
        } else if !saved_credentials && input("Save password ([y]/n)? ", "y").to_lowercase() == "y" {
            if save_credentials(&user, &password).is_err() { println!("Save failed"); exit(1); }
        }
        if args.keep_alive {
            loop {
                thread::sleep(Duration::from_secs(args.interval));
                try_login(&user, &password)?;
            }
        }
    }
    Ok(())
}
