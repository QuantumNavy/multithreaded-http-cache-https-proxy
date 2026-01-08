#include <iostream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <mutex>
#include <string>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <ctime>

#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>

#include <dispatch/dispatch.h>   

using namespace std;

/* Config Class */

class Config {
public:
    string listen_address;
    int port;
    int max_clients;
    int buffer_size;
    size_t cache_capacity;
    int tunnel_timeout;
    string blocked_domains_file;
    string log_file;
    string cache_dir;

    Config() {
        // Default values
        listen_address = "0.0.0.0";
        port = 8080;
        max_clients = 100;
        buffer_size = 8192;
        cache_capacity = 50;
        tunnel_timeout = 300000;
        blocked_domains_file = "domainfilter.txt";
        log_file = "proxy.log";
        cache_dir = "./cache";
    }

    bool load(const string& filename) {
        ifstream file(filename);
        if (!file.is_open()) {
            cout << "No config file found, using defaults" << endl;
            return false;
        }

        string line;
        while (getline(file, line)) {

            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            

            if (line.empty() || line[0] == '#') continue;
            

            size_t eq_pos = line.find('=');
            if (eq_pos == string::npos) continue;
            
            string key = line.substr(0, eq_pos);
            string value = line.substr(eq_pos + 1);
            

            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            

            if (key == "listen_address") {
                listen_address = value;
            } else if (key == "port") {
                port = stoi(value);
            } else if (key == "max_clients") {
                max_clients = stoi(value);
            } else if (key == "buffer_size") {
                buffer_size = stoi(value);
            } else if (key == "cache_capacity") {
                cache_capacity = stoull(value);
            } else if (key == "tunnel_timeout") {
                tunnel_timeout = stoi(value);
            } else if (key == "blocked_domains_file") {
                blocked_domains_file = value;
            } else if (key == "log_file") {
                log_file = value;
            } else if (key == "cache_dir") {
                cache_dir = value;
            }
        }
        
        file.close();
        cout << "[CONFIG] Loaded configuration from " << filename << endl;
        return true;
    }

    void print() {
        cout << "\nProxy Configuration :" << endl;
        cout << "Listen Address: " << listen_address << endl;
        cout << "Port: " << port << endl;
        cout << "Max Clients: " << max_clients << endl;
        cout << "Buffer Size: " << buffer_size << endl;
        cout << "Cache Capacity: " << cache_capacity << endl;
        cout << "Tunnel Timeout: " << tunnel_timeout << " ms" << endl;
        cout << "Blocked Domains File: " << blocked_domains_file << endl;
        cout << "Log File: " << log_file << endl;
        cout << "Cache Directory: " << cache_dir << endl;
        cout<<endl<<endl;
    }
};



dispatch_semaphore_t client_sem;

/* Logger Class */

class Logger {
    ofstream log_file;
    mutex mtx;
    string log_filename;

public:
    Logger(const string& filename) : log_filename(filename) {
        log_file.open(log_filename, ios::app);
        if (!log_file.is_open()) {
            cerr << "Error response- Could not open log file: " << log_filename << endl;
        }
    }

    ~Logger() {
        if (log_file.is_open()) {
            log_file.close();
        }
    }

    string get_timestamp() {
        auto now = chrono::system_clock::now();
        auto time = chrono::system_clock::to_time_t(now);
        auto ms = chrono::duration_cast<chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        stringstream ss;
        ss << put_time(localtime(&time), "%Y-%m-%d %H:%M:%S");
        ss << "." << setfill('0') << setw(3) << ms.count();
        return ss.str();
    }

    void log(const string& client_ip, const string& host, const string& action,
             const string& status, size_t bytes_transferred) {
        lock_guard<mutex> lock(mtx);
        
        if (!log_file.is_open()) return;

        log_file << get_timestamp() << " || "
                 << client_ip << " || "
                 << host << " || "
                 << action << " || "
                 << status << " || "
                 << bytes_transferred << " bytes"
                 << endl;
        
        log_file.flush();
    }
};

/* Filtering Class */

class DomainFilter {
    unordered_set<string> blocked_domains;
    mutex mtx;
    string domains_file;

public:
    DomainFilter(const string& filename) : domains_file(filename) {
        load_blocked_domains();
    }

    void load_blocked_domains() {
        lock_guard<mutex> lock(mtx);
        
        ifstream file(domains_file);
        if (!file.is_open()) {
            cout << "Filter No " << domains_file << " found, allowing all domains" << endl;
            return;
        }

        string line;
        int count = 0;
        while (getline(file, line)) {

            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            

            if (line.empty() || line[0] == '#') continue;
            

            transform(line.begin(), line.end(), line.begin(), ::tolower);
            
            blocked_domains.insert(line);
            count++;
        }
        
        file.close();
        cout << "Filters are now Loaded " << count << " blocked domains" << endl;
    }

    bool is_blocked(const string& host) {
        lock_guard<mutex> lock(mtx);
        

        string lower_host = host;
        transform(lower_host.begin(), lower_host.end(), lower_host.begin(), ::tolower);
        

        size_t colon_pos = lower_host.find(':');
        if (colon_pos != string::npos) {
            lower_host = lower_host.substr(0, colon_pos);
        }
        
        // Check exact match
        if (blocked_domains.count(lower_host) > 0) {
            return true;
        }
        
        // Check if any parent domain is blocked 
        size_t dot_pos = lower_host.find('.');
        while (dot_pos != string::npos) {
            string parent = lower_host.substr(dot_pos + 1);
            if (blocked_domains.count(parent) > 0) {
                return true;
            }
            dot_pos = lower_host.find('.', dot_pos + 1);
        }
        
        return false;
    }
};

/* LRU Cache Class */

class LRUCache {
    struct Entry {
        string key;
        string value;
    };

    list<Entry> lru;
    unordered_map<string, list<Entry>::iterator> mp;
    mutable mutex mtx;
    size_t capacity;

public:
    LRUCache(size_t cap) : capacity(cap) {}

    bool get(const string& key, string& value) {
        lock_guard<mutex> lock(mtx);
        auto it = mp.find(key);
        if (it == mp.end()) return false;
        lru.splice(lru.begin(), lru, it->second);
        value = it->second->value;
        return true;
    }

    void put(const string& key, const string& value) {
        lock_guard<mutex> lock(mtx);

        auto it = mp.find(key);
        if (it != mp.end()) {
            it->second->value = value;
            lru.splice(lru.begin(), lru, it->second);
            return;
        }

        if (mp.size() >= capacity) {
            mp.erase(lru.back().key);
            lru.pop_back();
        }

        lru.push_front({key, value});
        mp[key] = lru.begin();
    }

    size_t size() const {
        lock_guard<mutex> lock(mtx);
        return mp.size();
    }
};

/* Http Parse function */

bool parse_request(const string& req, string& method, string& host, string& path) {
    istringstream iss(req);
    iss >> method >> path;

    // Handle absolute-form URL (proxy requests)
    if (path.find("http://") == 0) {
        size_t host_start = 7; 
        size_t path_start = path.find('/', host_start);

        host = path.substr(host_start, path_start - host_start);
        path = (path_start == string::npos) ? "/" : path.substr(path_start);
    } 
    else {
//GET /path HTTP/1.1
        size_t pos = req.find("Host:");
        if (pos == string::npos) return false;

        size_t start = pos + 5;
        size_t end = req.find("\r\n", start);
        host = req.substr(start, end - start);


        while (!host.empty() && (host[0] == ' ' || host[0] == '\t'))
            host.erase(0, 1);
        

        while (!host.empty() && (host.back() == ' ' || host.back() == '\t'))
            host.pop_back();
    }

    if (path.empty())
        path = "/";

    return true;
}

bool parse_connect(const string& req, string& host, int& port) {
    istringstream iss(req);
    string method, target;
    iss >> method >> target;

    if (method != "CONNECT") return false;

    size_t colon = target.find(':');
    if (colon == string::npos) {
        host = target;
        port = 443;
    } else {
        host = target.substr(0, colon);
        port = stoi(target.substr(colon + 1));
    }

    return true;
}



int connect_server(const string& host, int port) {
    addrinfo hints{}, *res;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), to_string(port).c_str(), &hints, &res) != 0)
        return -1;

    int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    if (::connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return fd;
}

/* Getting Client IP*/

string get_client_ip(int client_fd) {
    sockaddr_in addr;
    socklen_t len = sizeof(addr);
    
    if (getpeername(client_fd, (sockaddr*)&addr, &len) < 0) {
        return "unknown";
    }
    
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    return string(ip);
}

/* HTTPS TUNNELING */

size_t handle_tunnel(int client_fd, int server_fd, int tunnel_timeout) {
    pollfd fds[2];
    fds[0].fd = client_fd;
    fds[0].events = POLLIN;
    fds[1].fd = server_fd;
    fds[1].events = POLLIN;

    char* buffer = new char[8192];
    size_t total_bytes = 0;

    while (true) {
        int ret = poll(fds, 2, tunnel_timeout);
        
        if (ret < 0) {
            break; 
        } else if (ret == 0) {
            break; // Timeout
        }

        
        if (fds[0].revents & POLLIN) {
            int n = recv(client_fd, buffer, 8192, 0);
            if (n <= 0) break;
            if (send(server_fd, buffer, n, 0) <= 0) break;
            total_bytes += n;
        }

        // Data from server to client
        if (fds[1].revents & POLLIN) {
            int n = recv(server_fd, buffer, 8192, 0);
            if (n <= 0) break;
            if (send(client_fd, buffer, n, 0) <= 0) break;
            total_bytes += n;
        }


        if ((fds[0].revents & (POLLERR | POLLHUP)) || 
            (fds[1].revents & (POLLERR | POLLHUP))) {
            break;
        }
    }
    
    delete[] buffer;
    return total_bytes;
}

/*Handle Clients */

void handle_client(int client_fd, LRUCache& cache, DomainFilter& filter, Logger& logger, Config& config) {
    dispatch_semaphore_wait(client_sem, DISPATCH_TIME_FOREVER);

    string client_ip = get_client_ip(client_fd);
    string request;
    char* buffer = new char[config.buffer_size];
    int n;

    // Read until end of HTTP headers
    while (request.find("\r\n\r\n") == string::npos) {
        n = recv(client_fd, buffer, config.buffer_size, 0);
        if (n <= 0) {
            delete[] buffer;
            close(client_fd);
            dispatch_semaphore_signal(client_sem);
            return;
        }
        request.append(buffer, n);
    }

    string method, host, path;
    
    // Check if this is a CONNECT request (HTTPS tunneling)
    if (request.find("CONNECT") == 0) {
        int port;
        if (!parse_connect(request, host, port)) {
            delete[] buffer;
            close(client_fd);
            dispatch_semaphore_signal(client_sem);
            return;
        }

        string full_host = host + ":" + to_string(port);

        // Check if domain is blocked
        if (filter.is_blocked(host)) {
            cout << "[BLOCKED] " << full_host << " from " << client_ip << endl;
            
            string error_response = "HTTP/1.1 403 Forbidden\r\n"
                                  "Content-Type: text/html\r\n"
                                  "Content-Length: 119\r\n"
                                  "Connection: close\r\n\r\n"
                                  "<html><body><h1>403 Forbidden</h1>"
                                  "<p>Access to this domain is blocked by proxy.</p></body></html>";
            
            size_t sent = send(client_fd, error_response.c_str(), error_response.size(), 0);
            logger.log(client_ip, full_host, "CONNECT", "403 FORBIDDEN Website is blocked", sent);
            
            delete[] buffer;
            close(client_fd);
            dispatch_semaphore_signal(client_sem);
            return;
        }

        cout << "[HTTPS TUNNELING} " << full_host << " from " << client_ip << endl;

        int server_fd = connect_server(host, port);
        if (server_fd < 0) {
            string error_response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            size_t sent = send(client_fd, error_response.c_str(), error_response.size(), 0);
            logger.log(client_ip, full_host, "CONNECT", "502 Bad Gateway Request Unable to process", sent);
            
            delete[] buffer;
            close(client_fd);
            dispatch_semaphore_signal(client_sem);
            return;
        }

        // Send 200 Connection Established
        string success = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(client_fd, success.c_str(), success.size(), 0);

        delete[] buffer;
        
        // Start bidirectional tunnel
        size_t bytes_transferred = handle_tunnel(client_fd, server_fd, config.tunnel_timeout);
        logger.log(client_ip, full_host, "CONNECT", "200 Connection OK", bytes_transferred);

        close(server_fd);
        close(client_fd);
        dispatch_semaphore_signal(client_sem);
        return;
    }

    // Regular HTTP GET request handling
    if (!parse_request(request, method, host, path) || method != "GET") {
        delete[] buffer;
        close(client_fd);
        dispatch_semaphore_signal(client_sem);
        return;
    }

    string full_url = host + path;

    // Check if domain is blocked
    if (filter.is_blocked(host)) {
        cout << "[BLOCKED] " << full_url << " from " << client_ip << endl;
        
        string error_response = "HTTP/1.1 403 Forbidden\r\n"
                              "Content-Type: text/html\r\n"
                              "Content-Length: 119\r\n"
                              "Connection: close\r\n\r\n"
                              "<html><body><h1>403 Forbidden</h1>"
                              "<p>Access to this domain is blocked by proxy Filtering.</p></body></html>";
        
        size_t sent = send(client_fd, error_response.c_str(), error_response.size(), 0);
        logger.log(client_ip, full_url, "GET", "403 FORBIDDEN Website Is Blocked", sent);
        
        delete[] buffer;
        close(client_fd);
        dispatch_semaphore_signal(client_sem);
        return;
    }

    // Create cache key
    string cache_key = method + " http://" + host + path;
    cout << "[REQUEST] " << full_url << " from " << client_ip << endl;

    string response;

    // Check cache
    if (cache.get(cache_key, response)) {
        cout << "[CACHE HIT]" << endl;
        size_t sent = send(client_fd, response.c_str(), response.size(), 0);
        logger.log(client_ip, full_url, "GET", "200 OK (cached)", sent);
        
        delete[] buffer;
        close(client_fd);
        dispatch_semaphore_signal(client_sem);
        return;
    }

    cout << "[CACHE MISS]" << endl;

    // Connect to remote server
    int server_fd = connect_server(host, 80);
    if (server_fd < 0) {
        logger.log(client_ip, full_url, "GET", "Connection Failed", 0);
        delete[] buffer;
        close(client_fd);
        dispatch_semaphore_signal(client_sem);
        return;
    }

    // Set socket timeout to prevent hanging
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Forward request to server
    send(server_fd, request.c_str(), request.size(), 0);

    // Receive response and forward to client
    size_t total_bytes = 0;
    while ((n = recv(server_fd, buffer, config.buffer_size, 0)) > 0) {
        response.append(buffer, n);
        send(client_fd, buffer, n, 0);
        total_bytes += n;
    }

    // Store in cache
    cache.put(cache_key, response);
    
    logger.log(client_ip, full_url, "GET", "200 OK", total_bytes);

    delete[] buffer;
    close(server_fd);
    close(client_fd);
    dispatch_semaphore_signal(client_sem);
}

/* MAIN FUNCTION */

int main() {
// loading config file
    Config config;
    config.load("config/proxy.conf");
    config.print();

    client_sem = dispatch_semaphore_create(config.max_clients);

    int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    

    if (config.listen_address == "0.0.0.0" || config.listen_address == "any") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, config.listen_address.c_str(), &addr.sin_addr);
    }
    
    addr.sin_port = htons(config.port);

    if (::bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("binding failed");
        return 1;
    }

    if (::listen(server_fd, config.max_clients) < 0) {
        perror("listening failed");
        return 1;
    }

    cout << "HTTP/HTTPS Proxy listening on " << config.listen_address << ":" << config.port << endl;
    cout << "PID: " << getpid() << endl;
  
    LRUCache cache(config.cache_capacity);
    DomainFilter filter(config.blocked_domains_file);
    Logger logger(config.log_file);

    while (true) {
        int client_fd = ::accept(server_fd, nullptr, nullptr);
        if (client_fd >= 0) {
            thread(handle_client, client_fd, ref(cache), ref(filter), ref(logger), ref(config)).detach();
        }
    }

    close(server_fd);
    return 0;
}
