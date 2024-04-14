use std::process::exit;

use async_recursion::async_recursion;
use chrono;
use clap::Parser;
use dirs_next::config_dir;
use reqwest::header::{HeaderValue, COOKIE, SET_COOKIE};
use reqwest::{Client, Error};
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use url::Url;

static mut PRINT_TIME: bool = false;

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

async fn auth(
    client: &Client,
    login_url: Url,
    cookies: &str,
    username: &str,
    password: &str,
) -> Result<bool, Error> {
    log!(
        "Authenticating to URL {} using account {}...",
        login_url.to_string(),
        username
    );
    let response = client
        .post(&login_url.to_string())
        .header(COOKIE, cookies)
        .form(&[("user", username), ("pass", password)])
        .send()
        .await?;

    if response.status().is_success() {
        if check_status("http://captive.apple.com/").await {
            log!("Successfully logged in.");
            Ok(true)
        } else {
            let body = response.text().await?;
            let reason =
                body.find("<div class=\"ui error message\">")
                    .map_or("Unknown error", |start| {
                        &body[start..].find("</div>").map_or("Unknown error", |end| {
                            &body[(start + 30)..(start + end)].trim()
                        })
                    });
            log!("\tError: {}", reason);
            log!("Failed to login. Please check username and password.");
            Ok(false)
        }
    } else {
        log!("Failed to send login request. Please check network connection");
        match response.error_for_status() {
            Ok(_res) => exit(1),
            Err(e) => Err(e),
        }
    }
}

async fn check_status(check_url: &str) -> bool {
    let client = Client::new();
    match client.get(check_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                let body = response.text().await.unwrap_or_else(|_| "".to_string());
                body.contains("Success")
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

#[async_recursion]
async fn login(
    client: &Client,
    redirected_auth_url: &str,
    username: &str,
    password: &str,
    retry: bool,
) -> Result<bool, Error> {
    match client.get(redirected_auth_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                let cookies = response
                    .headers()
                    .get(SET_COOKIE)
                    .cloned()
                    .unwrap_or_else(|| HeaderValue::from_static(""));

                let mut url = response.url().clone();
                url.set_query(None);
                url.set_path("/login");

                let body = response.text().await?;
                if body.contains("Success") {
                    log!("Already logged in");
                    Ok(true)
                } else {
                    auth(
                        client,
                        url,
                        cookies.to_str().unwrap_or(""),
                        username,
                        password,
                    )
                    .await
                }
            } else {
                log!("Failed to check login status. Please check network connection");
                Ok(false)
            }
        }
        Err(e) => {
            if retry {
                Err(e)
            } else {
                log!("{}", e);
                login(
                    client,
                    "http://1.2.3.4/?cmd=redirect&arubalp=12345",
                    username,
                    password,
                    true,
                )
                .await
            }
        }
    }
}

async fn try_login(username: &str, password: &str) -> Result<(), ()> {
    let client = Client::new();

    match login(
        &client,
        "http://captive.apple.com/?cmd=redirect&arubalp=12345",
        username,
        password,
        false,
    )
    .await
    {
        Ok(succeed) => {
            if succeed {
                Ok(())
            } else {
                Err(())
            }
        }
        Err(_) => Err(()),
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
        username: username.to_string(),
        password: password.to_string(),
    };
    let path = get_config_path()?;
    let mut file = File::create(path.clone())?;
    let data = serde_json::to_string_pretty(&credentials)?;
    file.write_all(data.as_bytes())?;
    println!("Credentials saved to {}", path.to_string_lossy());
    Ok(())
}

fn load_credentials() -> io::Result<Credentials> {
    let path = get_config_path()?;
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let credentials = serde_json::from_str(&contents)?;
    Ok(credentials)
}

#[derive(Parser, Debug)]
#[command(version, about = format!("{}

  A simple tool to login BUPT net using student ID and password.

  Copyright by {}.", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_AUTHORS")), long_about = None)]
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
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read from stdin");
    input.trim().is_empty().then(|| input = default.to_owned());
    input
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args = Args::parse();
    let mut saved_credentials = false;

    let mut student_id = args.student_id;
    let mut password = args.password;

    match load_credentials() {
        Ok(credentials) => {
            saved_credentials = true;
            if student_id.is_none() && password.is_none() {
                student_id = Some(credentials.username);
                password = Some(credentials.password);
            }
        }
        Err(_) => {}
    }

    if student_id.is_none() && password.is_none() && check_status("http://captive.apple.com/").await
    {
        println!("Already logged in");
        return Ok(());
    }

    while student_id.is_none() {
        let student_id_input = input("Enter your student ID: ", "");
        if !student_id_input.is_empty() {
            student_id = Some(student_id_input);
        }
    }

    let password = match password {
        Some(p) => p,
        None => prompt_password("Password: ").unwrap_or_else(|e| {
            println!("Failed to read password from stdin: {}", e);
            exit(1);
        }),
    };

    if password.is_empty() {
        println!("Password cannot be empty.");
        exit(1);
    }

    if let Some(user) = student_id {
        if args.keep_alive {
            unsafe {
                PRINT_TIME = true;
            }
        }
        try_login(&user, &password).await?;
        if args.save {
            save_credentials(&user, &password).is_err().then(|| {
                println!("Failed to save credentials");
                exit(1);
            });
        } else if !saved_credentials
            && input("Save password ([y]/n)? ", "y").trim().to_lowercase() == "y"
        {
            save_credentials(&user, &password).is_err().then(|| {
                println!("Failed to save credentials");
                exit(1);
            });
        }
        if args.keep_alive {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(args.interval)).await;
                try_login(&user, &password).await?;
            }
        }
    }

    Ok(())
}
