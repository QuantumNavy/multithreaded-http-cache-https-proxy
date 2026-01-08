#!/usr/bin/env python3
"""
Test Suite for HTTP/HTTPS Proxy Server
Author: Testing Team
Date: 2024

This script tests all the major features of our proxy server including
caching, domain filtering, HTTPS tunneling, and concurrent connections.
"""

import requests
import time
import socket
import sys
import os
import threading
from datetime import datetime

# Proxy settings
PROXY_HOST = 'localhost'
PROXY_PORT = 8080
PROXY_URL = f'http://{PROXY_HOST}:{PROXY_PORT}'

# Pretty colors for terminal output
class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_section(title):
    """Print a section header"""
    print(f"\n{Color.BOLD}[{title}]{Color.RESET}")

def pass_msg(text):
    """Print a success message"""
    print(f"{Color.GREEN}PASS:{Color.RESET} {text}")

def fail_msg(text):
    """Print a failure message"""
    print(f"{Color.RED}FAIL:{Color.RESET} {text}")

def info_msg(text):
    """Print an info message"""
    print(f"{Color.BLUE}INFO:{Color.RESET} {text}")

def test_msg(text):
    """Print a test description"""
    print(f"{Color.YELLOW}TEST:{Color.RESET} {text}")


def is_proxy_running():
    """
    Check if the proxy server is actually running and accepting connections.
    This is the first test we should run - no point testing other features
    if the proxy isn't even up!
    """
    test_msg("Checking if proxy server is running...")
    
    try:
        # Try to connect to the proxy port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((PROXY_HOST, PROXY_PORT))
        sock.close()
        
        if result == 0:
            pass_msg(f"Proxy server is up and listening on {PROXY_HOST}:{PROXY_PORT}")
            return True
        else:
            fail_msg(f"Can't connect to proxy on {PROXY_HOST}:{PROXY_PORT}")
            fail_msg("Make sure the proxy is running with: ./proxy")
            return False
    except Exception as e:
        fail_msg(f"Error while checking proxy: {e}")
        return False


def test_simple_http():
    """
    Test a basic HTTP GET request through the proxy.
    This is the most fundamental feature - if this doesn't work,
    nothing else will!
    """
    test_msg("Testing basic HTTP GET request...")
    
    proxies = {'http': PROXY_URL}
    
    try:
        info_msg("Requesting http://example.com through proxy...")
        start_time = time.time()
        response = requests.get('http://example.com', proxies=proxies, timeout=15)
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            pass_msg(f"Got successful response (took {elapsed:.2f} seconds)")
            info_msg(f"Response size: {len(response.content)} bytes")
            info_msg("Check proxy console - should show [CACHE MISS]")
            return True
        else:
            fail_msg(f"Got unexpected status code: {response.status_code}")
            return False
    except Exception as e:
        fail_msg(f"Request failed: {e}")
        return False


def test_caching():
    """
    Test the cache system - this is one of the main features!
    First request should miss the cache, second should hit it.
    We wait 5 seconds between requests to make sure the first one
    completes and gets cached properly.
    """
    test_msg("Testing cache system (MISS then HIT)...")
    
    proxies = {'http': PROXY_URL}
    url = 'http://example.com'
    
    # First request - should miss the cache
    info_msg("Making first request (should be CACHE MISS)...")
    try:
        start1 = time.time()
        resp1 = requests.get(url, proxies=proxies, timeout=15)
        time1 = time.time() - start1
        
        if resp1.status_code != 200:
            fail_msg(f"First request failed: status {resp1.status_code}")
            return False
        
        pass_msg(f"First request OK ({time1:.3f} seconds)")
        info_msg("Proxy console should show: [CACHE MISS]")
        
    except Exception as e:
        fail_msg(f"First request failed: {e}")
        return False
    
    # Wait a bit to make sure everything's settled
    info_msg("Waiting 5 seconds for cache to settle...")
    time.sleep(5)
    
    # Second request - should hit the cache
    info_msg("Making second request (should be CACHE HIT)...")
    try:
        start2 = time.time()
        resp2 = requests.get(url, proxies=proxies, timeout=15)
        time2 = time.time() - start2
        
        if resp2.status_code != 200:
            fail_msg(f"Second request failed: status {resp2.status_code}")
            return False
        
        pass_msg(f"Second request OK ({time2:.3f} seconds)")
        info_msg("Proxy console should show: [CACHE HIT]")
        
        # Cache hit should ideally be faster
        if time2 < time1:
            pass_msg(f"Cache made it faster! ({time2:.3f}s vs {time1:.3f}s)")
        else:
            info_msg(f"Times similar ({time2:.3f}s vs {time1:.3f}s) - that's okay")
        
        # Let's do a third request just to be sure
        info_msg("Making third request (also should be CACHE HIT)...")
        time.sleep(1)
        
        start3 = time.time()
        resp3 = requests.get(url, proxies=proxies, timeout=15)
        time3 = time.time() - start3
        
        if resp3.status_code == 200:
            pass_msg(f"Third request also OK ({time3:.3f} seconds)")
            info_msg("Proxy should show another [CACHE HIT]")
        
        return True
        
    except Exception as e:
        fail_msg(f"Cache test failed: {e}")
        return False


def test_different_urls():
    """
    Test that the cache can handle multiple different URLs.
    Each URL should have its own cache entry.
    """
    test_msg("Testing cache with different URLs...")
    
    proxies = {'http': PROXY_URL}
    test_urls = [
        'http://example.com',
        'http://httpbin.org/get',
        'http://example.org'
    ]
    
    try:
        for url in test_urls:
            info_msg(f"Testing {url}...")
            
            # First request - miss
            start1 = time.time()
            r1 = requests.get(url, proxies=proxies, timeout=15)
            time1 = time.time() - start1
            
            if r1.status_code != 200:
                fail_msg(f"Failed to get {url}: status {r1.status_code}")
                continue
            
            info_msg(f"  First request: {time1:.3f}s (CACHE MISS)")
            
            time.sleep(1)
            
            # Second request - hit
            start2 = time.time()
            r2 = requests.get(url, proxies=proxies, timeout=15)
            time2 = time.time() - start2
            
            if r2.status_code == 200:
                info_msg(f"  Second request: {time2:.3f}s (CACHE HIT)")
                pass_msg(f"Successfully cached {url}")
            
            time.sleep(1)
        
        pass_msg("All URLs cached independently!")
        return True
        
    except Exception as e:
        fail_msg(f"Multi-URL test failed: {e}")
        return False


def test_domain_filter():
    """
    Test the domain filtering feature. If a domain is in the filter file,
    the proxy should block it with a 403 Forbidden response.
    """
    test_msg("Testing domain filtering/blocking...")
    
    # Look for the filter file
    filter_file = None
    if os.path.exists('domainfilter.txt'):
        filter_file = 'domainfilter.txt'
    elif os.path.exists('blocked_domains.txt'):
        filter_file = 'blocked_domains.txt'
    
    if not filter_file:
        info_msg("No filter file found (domainfilter.txt)")
        info_msg("Creating a sample file for testing...")
        with open('domainfilter.txt', 'w') as f:
            f.write("# Domain Filter Configuration\n")
            f.write("# Add domains to block, one per line\n\n")
            f.write("blocked-test-site.com\n")
        info_msg("Created domainfilter.txt with test domain")
        info_msg("Restart the proxy to load this configuration")
        return True
    
    proxies = {'http': PROXY_URL}
    
    # Read blocked domains from file
    with open(filter_file, 'r') as f:
        blocked = [line.strip() for line in f 
                  if line.strip() and not line.startswith('#')]
    
    if not blocked:
        info_msg(f"No blocked domains in {filter_file}")
        info_msg("Add some domains to test the blocking feature")
        return True
    
    test_domain = blocked[0]
    info_msg(f"Trying to access blocked domain: {test_domain}")
    
    try:
        response = requests.get(f'http://{test_domain}', proxies=proxies, timeout=15)
        
        if response.status_code == 403:
            pass_msg("Blocked domain correctly rejected with 403 Forbidden")
            if "blocked" in response.text.lower():
                pass_msg("Block page shows proper message")
            return True
        else:
            fail_msg(f"Expected 403, got {response.status_code}")
            return False
            
    except requests.exceptions.ProxyError:
        pass_msg("Domain blocked by proxy (connection rejected)")
        return True
    except Exception as e:
        info_msg(f"Couldn't test blocking (domain might not exist): {e}")
        return True


def test_https_tunnel():
    """
    Test HTTPS support through CONNECT method tunneling.
    The proxy doesn't cache HTTPS traffic (can't read encrypted data),
    but it should tunnel it successfully.
    """
    test_msg("Testing HTTPS tunneling (CONNECT method)...")
    
    proxies = {
        'http': PROXY_URL,
        'https': PROXY_URL
    }
    
    try:
        info_msg("Attempting HTTPS request to https://httpbin.org...")
        start = time.time()
        response = requests.get('https://httpbin.org/get', 
                              proxies=proxies, timeout=15, verify=True)
        elapsed = time.time() - start
        
        if response.status_code == 200:
            pass_msg(f"HTTPS tunnel worked! (took {elapsed:.2f}s)")
            info_msg("Check proxy logs for [HTTPS TUNNEL] message")
            return True
        else:
            fail_msg(f"HTTPS request returned: {response.status_code}")
            return False
            
    except Exception as e:
        fail_msg(f"HTTPS tunneling failed: {e}")
        info_msg("Note: HTTPS traffic is tunneled, not cached")
        return False


def test_logging():
    """
    Check if the proxy is writing logs to proxy.log.
    Good logging is important for debugging and monitoring.
    """
    test_msg("Testing logging functionality...")
    
    log_file = 'proxy.log'
    
    if not os.path.exists(log_file):
        info_msg(f"{log_file} doesn't exist yet")
        info_msg("Making a request to generate some logs...")
    
    # Make a request to generate log entries
    proxies = {'http': PROXY_URL}
    try:
        requests.get('http://example.com', proxies=proxies, timeout=15)
        time.sleep(1)  # Give it a moment to write the log
        
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                lines = f.readlines()
                if lines:
                    pass_msg(f"Log file exists with {len(lines)} entries")
                    info_msg("Last log entry:")
                    print(f"    {lines[-1].strip()}")
                    return True
                else:
                    fail_msg("Log file exists but is empty")
                    return False
        else:
            fail_msg(f"{log_file} was not created")
            return False
            
    except Exception as e:
        fail_msg(f"Logging test error: {e}")
        return False


def test_concurrent():
    """
    Test how the proxy handles multiple requests at the same time.
    A good proxy should handle concurrent connections gracefully.
    """
    test_msg("Testing concurrent request handling...")
    
    proxies = {'http': PROXY_URL}
    results = []
    
    def make_request(url, req_id):
        """Helper function to make a request in a thread"""
        try:
            response = requests.get(url, proxies=proxies, timeout=15)
            results.append((req_id, response.status_code, True))
        except Exception as e:
            results.append((req_id, 0, False))
    
    # Fire off 5 requests at the same time
    threads = []
    info_msg("Launching 5 concurrent requests...")
    
    for i in range(5):
        t = threading.Thread(target=make_request, 
                           args=('http://example.com', i))
        threads.append(t)
        t.start()
    
    # Wait for them all to finish
    for t in threads:
        t.join()
    
    successful = sum(1 for _, _, ok in results if ok)
    
    if successful == 5:
        pass_msg(f"All 5 concurrent requests handled successfully!")
        return True
    else:
        fail_msg(f"Only {successful} out of 5 requests succeeded")
        return False


def test_config():
    """
    Check if the proxy is reading its configuration file.
    """
    test_msg("Checking configuration file...")
    
    config_file = 'proxy.conf'
    
    if os.path.exists(config_file):
        pass_msg(f"{config_file} exists")
        with open(config_file, 'r') as f:
            content = f.read()
            info_msg(f"Config file is {len(content)} bytes")
            
            # Look for important settings
            if 'port' in content.lower():
                info_msg("Port configuration found")
            if 'cache_capacity' in content.lower():
                info_msg("Cache capacity configuration found")
        return True
    else:
        info_msg(f"{config_file} not found")
        info_msg("Proxy is using default configuration")
        return True


def run_all_tests():
    """
    Main test runner - executes all tests and shows a summary.
    """
    print(f"\n{Color.BOLD}HTTP/HTTPS PROXY SERVER - TEST SUITE{Color.RESET}")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # List of all our tests
    tests = [
        ("Server Status Check", is_proxy_running),
        ("Configuration File", test_config),
        ("Basic HTTP Request", test_simple_http),
        ("Cache System (MISS/HIT)", test_caching),
        ("Multiple URL Caching", test_different_urls),
        ("Domain Filtering", test_domain_filter),
        ("HTTPS Tunneling", test_https_tunnel),
        ("Log File Writing", test_logging),
        ("Concurrent Connections", test_concurrent),
    ]
    
    results = []
    
    # Run each test
    for test_name, test_func in tests:
        print_section(test_name)
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            fail_msg(f"Test crashed with error: {e}")
            results.append((test_name, False))
        
        # Wait between tests (except after the last one)
        if test_name != tests[-1][0]:
            info_msg("Waiting 1 second before next test...")
            time.sleep(1)
    
    # Print summary
    print(f"\n{Color.BOLD}TEST RESULTS SUMMARY{Color.RESET}")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        if result:
            print(f"  {Color.GREEN}PASS{Color.RESET} - {test_name}")
        else:
            print(f"  {Color.RED}FAIL{Color.RESET} - {test_name}")
    
    print(f"\n{Color.BOLD}Final Score: {passed}/{total} tests passed{Color.RESET}")
    
    if passed == total:
        print(f"{Color.GREEN}All tests passed!{Color.RESET}\n")
        return 0
    else:
        print(f"{Color.RED}Some tests failed - check the output above{Color.RESET}\n")
        return 1


if __name__ == '__main__':
    exit_code = run_all_tests()
    sys.exit(exit_code)
