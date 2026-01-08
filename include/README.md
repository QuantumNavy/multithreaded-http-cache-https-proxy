# Multithreaded HTTP/HTTPS Cache(HTTP Only) Proxy Server

## Overview
This project implements a multithreaded forward HTTP/HTTPS proxy server in C++ using POSIX sockets.  
The proxy supports concurrent client connections, HTTP request forwarding, HTTPS tunneling via the CONNECT method, response caching with an LRU eviction policy, domain-based filtering, and detailed request logging.

The implementation demonstrates core systems and networking concepts including socket programming, concurrency, synchronization, request parsing, and efficient in-memory caching.

---

## Features
- Multithreaded server using a thread-per-connection model(100 connections)
- HTTP GET request forwarding
- HTTPS CONNECT tunneling with transparent TCP relaying
- In-memory HTTP response caching with LRU eviction(50 capacity default)
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
├── Docs/
│ └── videolink.txt
├── config/
│ ├── proxy.conf
│ └── domainfilter.txt
├── logs/
│ └── proxy.log
├── tests/
│ └── test_proxy.py
├── Makefile
├── .gitignore
├── LICENSE
└── README.md

```


---

## Build Instructions

### Requirements
- Linux or macOS
- C++17 compatible compiler (g++)
- POSIX socket support

### Build
From the project root directory after clone using 
```bash
git clone https://github.com/QuantumNavy/multithreaded-http-cache-https-proxy
```
Use the command below
```bash
make
```
After that run the proxy using
```bash
./proxy
```
Expected output unless the config file is changed:
```bash
[CONFIG] Loaded configuration from config/proxy.conf

Proxy Configuration :
Listen Address: 0.0.0.0
Port: 8080
Max Clients: 100
Buffer Size: 8192
Cache Capacity: 50
Tunnel Timeout: 300000 ms
Blocked Domains File: config/domainfilter.txt
Log File: logs/proxy.log
Cache Directory: cache


HTTP/HTTPS Proxy listening on 0.0.0.0:8080
PID: 80101
Filters are now Loaded 1 blocked domains
```
## Architecture Diagram
```
+--------+        +--------------------+        +----------------+
| Client | -----> |   Proxy Server     | -----> | Remote Server  |
| (curl) | <----- | (This Project)     | <----- | (HTTP / HTTPS) |
+--------+        +--------------------+        +----------------+
                         |
                         |-- Domain Filter
                         |-- LRU Cache
                         |-- Logger
```
## Testing 
for testing a python script is provided as tests/test_proxy.py this tests all the features of the proxy and informs if any errors are found

## Component Description

### 1. Proxy Server Core
- Initializes a TCP listening socket on a configurable address and port
- Accepts incoming client connections
- Spawns a detached thread for each client request
- Limits concurrent connections using a semaphore to avoid overload

---

### 2. Configuration Manager
- Loads runtime parameters from `config/proxy.conf`
- Supports configuration of:
  - Listening address and port
  - Maximum concurrent clients
  - Buffer size
  - Cache capacity
  - Tunnel timeout
  - Paths for logs and domain filters
- Provides centralized configuration access throughout the proxy

---

### 3. HTTP Request Parser
- Parses incoming HTTP requests from clients
- Extracts request method, host, and resource path
- Supports:
  - Absolute-form URLs (proxy-style requests)
  - Origin-form URLs with `Host` headers
- Identifies CONNECT requests for HTTPS tunneling

---

### 4. Domain Filtering Module
- Loads blocked domains from `config/domainfilter.txt`
- Performs case-insensitive hostname matching
- Supports parent-domain blocking (e.g., blocking `example.com` blocks `www.example.com`)
- Returns HTTP 403 Forbidden for blocked requests
- Logs all blocked access attempts

---

### 5. Forwarding Engine
- Establishes TCP connections to destination servers
- Forwards HTTP requests from clients to remote servers
- Relays server responses back to clients
- Handles socket errors and timeouts gracefully

---

### 6. HTTPS CONNECT Tunnel Handler
- Handles HTTPS requests using the CONNECT method
- Establishes a transparent TCP tunnel between client and remote server
- Sends `HTTP/1.1 200 Connection Established` upon success
- Uses `poll()` to relay encrypted traffic bidirectionally
- Does not inspect or modify TLS-encrypted data

---

### 7. LRU Cache
- Implements an in-memory cache for HTTP GET responses
- Uses:
  - Hash map for constant-time lookup
  - Doubly linked list for LRU eviction
- Evicts the least recently used entry when cache capacity is exceeded
- Improves performance by reducing redundant network requests
- HTTPS responses are not cached

---

### 8. Logging Module
- Provides thread-safe logging of proxy activity
- Logs include:
  - Timestamp
  - Client IP address
  - Requested host
  - Request method (GET / CONNECT)
  - Status (allowed, blocked, cached)
  - Bytes transferred
- Writes logs to `logs/proxy.log`

---

### 9. Error Handling
- Detects malformed or unsupported requests
- Handles connection failures and unreachable servers
- Returns appropriate HTTP error responses (403, 502)
- Ensures sockets and resources are properly released on errors

## Pitfalls and Future Work

### Pitfalls
- The cache is updated only when a complete response is received and processed by a thread.
- When multiple client requests for the same resource arrive simultaneously, they may be handled by parallel threads before any one thread inserts the response into the cache.
- As a result, concurrent identical requests can lead to multiple cache misses and redundant fetches from the remote server.
- This behavior occurs because the current design does not coordinate cache population across threads for in-flight requests.
- The cache is in-memory only and is cleared when the proxy process terminates.

---

### Future Work
- Implement **cache coalescing** to handle concurrent identical requests efficiently.
- With cache coalescing, when a request for a resource is already being fetched by one thread, subsequent threads would wait for the in-progress fetch instead of issuing duplicate requests.
- Once the initial fetch completes, all waiting threads would be served from the newly populated cache entry.
- This enhancement would reduce redundant network traffic, improve cache efficiency, and enhance performance under high concurrency.
- Extend the cache design to support disk-based persistence and cache validation using HTTP headers.
