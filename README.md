# bupt-net-login

登录北邮校园网的命令行工具

## 安装

### C++ 版本

适用于 Linux 系统，可在 openwrt 上运行。

1. 从 GitHub Releases 安装

    在 [releases](https://github.com/YouXam/bupt-net-login/releases) 页面下载最新版本的的以 `bupt-net-login_cpp` 开头的压缩包。
2. 从源码编译

    如果需要在对应的 OpenWrt 路由器上运行，需要先下载对应的 OpenWrt SDK。

    然后修改 cpp/makefile 添加必要的编译参数，编译。
    
    例如：

    ```makefile
    CXXFLAGS := -std=c++17 -Os -static-libstdc++ -march=mips32r2 -fPIE -pie -Wl,--dynamic-linker=/lib/ld-musl-mipsel-sf.so.1
    # ...
    ```

    ```shell
    make TOOLCHAIN=mipsel-linux-musl-cross/bin/mipsel-linux-musl
    ```
3. 安装
    以 OpenWrt 为例，创建 `/etc/init.d/bupt-net-login` 文件，内容如下：

    ```shell
    #!/bin/sh /etc/rc.common
    # Copyright (C) 2025 YouXam
    # bupt-net-login OpenWrt service

    START=90
    STOP=10
    USE_PROCD=1

    start_service() {
        procd_open_instance
        procd_set_param command /usr/bin/bupt-net-login.cpp -o /root/.bupt-net-login.log -s 128K -i 300
        procd_set_param stdout 1
        procd_set_param stderr 1
        procd_set_param respawn
        procd_close_instance
    }

    stop() {
        procd_killall
    }
    ```

    然后 enable 并启动服务：

    ```shell
    chmod +x /etc/init.d/bupt-net-login
    /etc/init.d/bupt-net-login enable
    /etc/init.d/bupt-net-login start
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

使用方式: bupt-net-login [OPTIONS]

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
