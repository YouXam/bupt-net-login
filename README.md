# bupt-net-login

A simple tool to login BUPT net using student ID and password.

## Installation

### From crates.io

```
cargo install bupt-net-login
```

### From release

Download the latest release from [releases](https://github.com/YouXam/bupt-net-login/releases).

## Usage

```shell
$ bupt-net-login -h
bupt-net-login

  A simple tool to login BUPT net using student ID and password.

  Copyright by YouXam.

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
