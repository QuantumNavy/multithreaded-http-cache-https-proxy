# Multithreaded HTTP/HTTPS Cache Proxy Server

## Overview
This project implements a multithreaded forward HTTP/HTTPS proxy server in C++ using POSIX sockets.  
The proxy supports concurrent client connections, HTTP request forwarding, HTTPS tunneling via the CONNECT method, response caching with an LRU eviction policy, domain-based filtering, and detailed request logging.

The implementation demonstrates core systems and networking concepts including socket programming, concurrency, synchronization, request parsing, and efficient in-memory caching.

---

## Features
- Multithreaded server using a thread-per-connection model
- HTTP GET request forwarding
- HTTPS CONNECT tunneling with transparent TCP relaying
- In-memory HTTP response caching with LRU eviction
- Domain-based filtering using a blacklist file
- Thread-safe logging with timestamps and traffic metrics
- Configurable runtime parameters via external configuration file
- Connection limiting using semaphores

---

## Project Structure
```
multithreaded-http-cache-https-proxy/
├── src/
│ └── proxy.cpp
├── config/
│ ├── proxy.conf
│ └── domainfilter.txt
├── logs/
│ └── proxy.log
├── cache/
│ └── .gitkeep
├── docs/
│ └── DESIGN.md
├── tests/
│ └── test_commands.md
├── Makefile
└── README.md

```


---

## Build Instructions

### Requirements
- Linux or macOS
- C++17 compatible compiler (g++)
- POSIX socket support

### Build
From the project root directory:
```bash
make
