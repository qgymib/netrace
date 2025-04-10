# netrace

## Introduction

Trace and redirect program's network traffic to socks5 proxy, inspired by [graftcp](https://github.com/hmgle/graftcp).

## Features

1. Support both TCP and UDP.
2. Special support for DNS.

### Comparison

|                             | netrace | graftcp | proxychains |
|-----------------------------|---------|---------|-------------|
| TCP                         | Y       | Y       | Y           |
| UDP                         | Y       | N       | N           |
| DNS                         | Y       | N       | N           |
| dynamically linked programs | Y       | Y       | Y           |
| statically linked programs  | Y       | Y       | N           |
| Socks5 Proxy                | Y       | Y       | Y           |
| HTTP Proxy                  | N       | Y       | Y           |

### TCP and UDP redirection.

`netrace` has builtin redirect rules, which ignore all traffics to LAN and loopback.
It can be customized by option `--bypass`.

### DNS Proxy

`netrace` has builtin DNS proxy support. To enable this feature, add `--dns=udp://8.8.8.8` command line option.

## Usage

```console
$ netrace -h
netrace - Trace and redirect network traffic
Usage: netrace [options] prog [prog-args]
Options:
  --proxy=socks5://[user[:pass]@][host[:port]]
      Set socks5 address.

  --dns=udp://ip[:port]
      End DNS redirection. If this option is enabled, netrace start a builtin
      DNS proxy, and redirect DNS request to the server.

      The `port` is optional. If it is not set, treat as `53`.

  --bypass=RULE_LIST
      Syntax:
        RULE_LIST    := [RULE[,RULE,...]]
        RULE         := [default]
                        [TYPE://ip[:port][/?OPTIONS]]
        TYPE         := [tcp | udp]
        OPTIONS      := [OPTION[&OPTION&...]]
        OPTION       := [mask=NUMBER]

      Description:
        Do not redirect any traffic if it match any of the rules. By default
        all traffics to LAN and loopback are ignored. By using this option,
        the builtin filter rules are overwritten, however you can use `default`
        keyword to add these rules again.

        The `port` is optional. If it is set to non-zero, only traffic send to
        that port is ignored.

        The `mask` is optional. If it is not set, treat as `32` for IPv4 or
        `128` for IPv6.

      Example:
        --bypass=,
            Redirect anything.
        --bypass=udp://127.0.0.1
            Only ignore udp packets send to 127.0.0.1, no matter which
            destination port is.
        --bypass=tcp://192.168.0.1:1234
            Only ignore tcp transmissions connect to 192.168.0.1:1234
        --bypass=default,udp://0.0.0.0/?mask=0
            In addition to the default rules, ignore all IPv4 UDP transmissions.
        --bypass=default,udp://0.0.0.0/?mask=0,udp://:::53/?mask=0
            In addition to the default rules, ignore all IPv4 UDP transmissions,
            ignore all IPv6 UDP transmissions whose destination port is 53.

  --loglevel=[debug|info|warn|error]
      Set log level, case insensitive. By default set to `info`.

  -h, --help
      Show this help and exit.
```
