import argparse
import http.client
import json
import re
import ssl
from urllib.parse import urlparse, urlunparse, urljoin, quote

import requests
import urllib3

from ansi_colors import *
from banner import print_banner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_json(data):
    """Check if the provided data is a valid JSON."""
    try:
        json.loads(data)
        return True
    except (ValueError, TypeError):
        return False


def perform_headers_bypass(url, args, headers_bypass, custom_headers=None, custom_data=None):
    print(f"{YELLOW}[INFO] Trying to bypass with headers...{RESET}")

    user_method = args.method.upper() if args.method else "GET"
    data = custom_data if custom_data is not None else {}

    for header_line in headers_bypass:
        header_parts = header_line.strip().split(": ")
        if len(header_parts) == 2:
            header_key, header_value = header_parts
            headers = {}
            if custom_headers is not None:
                headers |= custom_headers

            headers[header_key] = header_value

            if "X-Original-URL" in headers or "X-Rewrite-URL" in headers:
                parsed_url = requests.utils.urlparse(url)
                url = requests.utils.urlunparse(parsed_url._replace(path="/"))

            r = requests.request(user_method, url, headers=headers, data=data, verify=False, allow_redirects=False)
        if user_method == "POST":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.post(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.post(url, verify=False, data=data, headers=headers, allow_redirects=False)
            else:
                r = requests.post(url, verify=False, headers=headers, allow_redirects=False)
        elif user_method == "PUT":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)
            else:
                r = requests.put(url, verify=False, headers=headers, allow_redirects=False)
        elif user_method == "PATCH":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)
            else:
                r = requests.put(url, verify=False, headers=headers, allow_redirects=False)
        elif user_method == "DELETE":
            r = requests.delete(url, verify=False, data=data, headers=headers, allow_redirects=False)
        else:
            r = requests.get(url, verify=False, data=data, headers=headers, allow_redirects=False)

        if args.proxy:
            r = requests.request(user_method, url, proxies={"http": args.proxy, "https": args.proxy}, headers=headers,
                                 data=data, verify=False, allow_redirects=False)

        status_code = r.status_code
        if status_code == 200:
            status_color = GREEN
        elif status_code in (401, 403):
            status_color = RED
        else:
            status_color = RESET
        print(f"{status_color}{user_method} {url} with header {header_key}: {status_code}{RESET}")


def perform_method_bypass(url, args, headers_bypass, method_bypass, custom_headers=None, custom_data=None):
    print(f"\n{YELLOW}[INFO] Trying to bypass with HTTP methods...{RESET}")

    for method in method_bypass:
        user_method = args.method.upper() if args.method else "GET"
        if user_method == method:
            continue

        headers = {}

        if custom_headers is not None:
            headers |= custom_headers

        data = custom_data if custom_data is not None else {}

        if method == "POST":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.post(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.post(url, verify=False, data=data, headers=headers, allow_redirects=False)
            else:
                r = requests.post(url, verify=False, headers=headers, allow_redirects=False)
        elif method == "PUT":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)
            else:
                r = requests.put(url, verify=False, headers=headers, allow_redirects=False)
        elif method == "PATCH":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)
            else:
                r = requests.put(url, verify=False, headers=headers, allow_redirects=False)
        elif method == "DELETE":
            r = requests.delete(url, verify=False, data=data, headers=headers, allow_redirects=False)
        else:
            r = requests.get(url, verify=False, data=data, headers=headers, allow_redirects=False)

        if args.proxy:
            r = requests.request(method, url, proxies={"http": args.proxy, "https": args.proxy}, headers=headers,
                                 data=data, verify=False, allow_redirects=False)

        status_code = r.status_code
        if status_code == 200:
            status_color = GREEN
        elif status_code in (401, 403):
            status_color = RED
        else:
            status_color = RESET
        print(f"{status_color}{method} {url}: {status_code}{RESET}")


def generate_path_variants(path):
    return [
        path,
        path.upper(),
        f"{path}/",
        f"{path}/.",
        f"//{path}//",
        f".{path}/..",
        f"/;{path}",
        f"/.;{path}",
        f"//;/{path}",
        path.split('/')[-1] + ".json",
    ]


def perform_path_bypass(url, path, args, user_method, custom_headers=None, custom_data=None):
    print(f"\n{YELLOW}[INFO] Trying to bypass with path fuzzing...{RESET}")

    base_url = url

    data = custom_data if custom_data is not None else {}

    for path_variant in generate_path_variants(path):
        path_variant = path_variant.lstrip('/')

        parsed_url = urlparse(urljoin(base_url, path_variant))
        parsed_url._replace(path=parsed_url.path.lstrip('/'))
        request_url = urlunparse(parsed_url._replace(path=path_variant))

        headers = {}
        if custom_headers is not None:
            headers |= custom_headers

        if user_method == "POST":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.post(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.post(url, verify=False, data=data, headers=headers, allow_redirects=False)
            else:
                r = requests.post(url, verify=False, headers=headers, allow_redirects=False)
        elif user_method == "PUT":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)
            else:
                r = requests.put(url, verify=False, headers=headers, allow_redirects=False)
        elif user_method == "PATCH":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)
        elif user_method == "DELETE":
            r = requests.delete(request_url, verify=False, headers=headers, data=data, allow_redirects=False)
        else:
            r = requests.get(request_url, verify=False, headers=headers, data=data, allow_redirects=False)

        if args.proxy:
            r = requests.request(user_method, request_url, headers=headers, data=data,
                                 proxies={"http": args.proxy, "https": args.proxy}, verify=False, allow_redirects=False)

        status_code = r.status_code
        if status_code == 200:
            status_color = GREEN
        elif status_code in (401, 403):
            status_color = RED
        else:
            status_color = RESET
        print(f"{status_color}{user_method} {request_url}: {r.status_code}{RESET}")


def perform_unicode_bypass(url, path, user_method, args, custom_headers=None, custom_data=None):
    print(f"\n{YELLOW}[INFO] Trying to bypass path with unicode fuzzing...{RESET}")

    headers = {}
    if custom_headers is not None:
        headers |= custom_headers

    base_url = url.rstrip('/')

    data = custom_data if custom_data is not None else {}

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
                if data:
                    if is_json(data):
                        headers['Content-Type'] = 'application/json'
                        r = requests.post(url, verify=False, json=data, headers=headers, allow_redirects=False)
                    else:
                        headers['Content-Type'] = 'application/x-www-form-urlencoded'
                        r = requests.post(url, verify=False, data=data, headers=headers, allow_redirects=False)
                else:
                    r = requests.post(url, verify=False, headers=headers, allow_redirects=False)
            elif user_method == "PUT":
                if data:
                    if is_json(data):
                        headers['Content-Type'] = 'application/json'
                        r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                    else:
                        headers['Content-Type'] = 'application/x-www-form-urlencoded'
                        r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)
                else:
                    r = requests.put(url, verify=False, headers=headers, allow_redirects=False)
            elif user_method == "PATCH":
                if data:
                    if is_json(data):
                        headers['Content-Type'] = 'application/json'
                        r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                    else:
                        headers['Content-Type'] = 'application/x-www-form-urlencoded'
                        r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)

            elif user_method == "DELETE":
                r = requests.delete(request_url, verify=False, headers=headers, data=data, allow_redirects=False)
            else:
                r = requests.get(request_url, verify=False, headers=headers, data=data, allow_redirects=False)

            if args.proxy:
                r = requests.request(user_method, request_url, headers=headers, data=data,
                                     proxies={"http": args.proxy, "https": args.proxy}, verify=False,
                                     allow_redirects=False)

            status_code = r.status_code
            if status_code == 200:
                status_color = GREEN
            elif status_code in (401, 403):
                status_color = RED
            else:
                status_color = RESET
            print(f"{status_color}{user_method} {request_url}: {status_code}{RESET}")


def perform_user_agent_bypass(url, args, user_method, custom_headers=None, custom_data=None):
    print(f"{YELLOW}\n[INFO] Trying to bypass with User-Agent fuzzing...{RESET}")

    headers = {}
    if custom_headers is not None:
        headers |= custom_headers

    data = custom_data if custom_data is not None else {}

    with open('./wordlists/UserAgents.fuzz.txt', 'r') as file:
        user_agents = file.read().splitlines()

    for user_agent in user_agents:
        headers["User-Agent"] = user_agent
        r = requests.get(url, headers=headers, verify=False, allow_redirects=False)

        if user_method == "POST":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.post(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.post(url, verify=False, data=data, headers=headers, allow_redirects=False)
            else:
                r = requests.post(url, verify=False, headers=headers, allow_redirects=False)
        elif user_method == "PUT":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)
            else:
                r = requests.put(url, verify=False, headers=headers, allow_redirects=False)
        elif user_method == "PATCH":
            if data:
                if is_json(data):
                    headers['Content-Type'] = 'application/json'
                    r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)

        elif user_method == "DELETE":
            r = requests.delete(url, verify=False, headers=headers, data=data, allow_redirects=False)
        else:
            r = requests.get(url, verify=False, headers=headers, data=data, allow_redirects=False)

        if args.proxy:
            r = requests.request(user_method, url, headers=headers, data=data,
                                 proxies={"http": args.proxy, "https": args.proxy}, verify=False, allow_redirects=False)

        status_code = r.status_code
        if status_code == 200:
            status_color = GREEN
        elif status_code in {401, 403}:
            status_color = RED
        else:
            status_color = RESET
        print(f"{status_color}{user_method} User-Agent: {user_agent} - Status Code: {r.status_code}{RESET}")


def modify_api_data(json_data):
    modified_data_first = {}
    modified_data_second = {}

    for key, value in json_data.items():
        # {“id”:111} ---> {“id”:{“id”:111}}
        modified_data_first[key] = {key: value}

        # {“id”:111} ---> {“id”:[111]}
        modified_data_second[key] = [value]

    return modified_data_first, modified_data_second


def perform_api_bypass(url, path, user_method, args, custom_headers=None, custom_data=None):
    print(f"\n{YELLOW}[INFO] Trying to bypass with API fuzzing...{RESET}")

    headers = {}
    if custom_headers is not None:
        headers |= custom_headers

    data = custom_data if custom_data is not None else {}

    if "api/v" in path:
        if version_number := re.search(r'/v(\d+(\.\d+)*)/?', path):
            current_version = version_number[1]
            all_versions = ["1", "2", "3", "4"]

            if current_version.endswith(".0"):
                all_versions = [f"{v}.0" for v in all_versions]

            other_versions = [v for v in all_versions if v != current_version]

            parsed_url = urlparse(url)

            for new_version in other_versions:
                path, query = parsed_url.path, parsed_url.query

                if current_version not in path:
                    new_path = f"{path}v{new_version}/"
                else:
                    new_path = path.replace(f"/v{current_version}/", f"/v{new_version}/")

                request_url = urljoin(url, new_path)

                if query:
                    request_url += f"?{query}"

                if user_method == "POST":
                    if data:
                        if is_json(data):
                            headers['Content-Type'] = 'application/json'
                            r = requests.post(url, verify=False, json=data, headers=headers, allow_redirects=False)
                        else:
                            headers['Content-Type'] = 'application/x-www-form-urlencoded'
                            r = requests.post(url, verify=False, data=data, headers=headers, allow_redirects=False)
                    else:
                        r = requests.post(url, verify=False, headers=headers, allow_redirects=False)

                elif user_method == "PUT":
                    if data:
                        if is_json(data):
                            headers['Content-Type'] = 'application/json'
                            r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                        else:
                            headers['Content-Type'] = 'application/x-www-form-urlencoded'
                            r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)
                    else:
                        r = requests.put(url, verify=False, headers=headers, allow_redirects=False)
                elif user_method == "PATCH":
                    if data:
                        if is_json(data):
                            headers['Content-Type'] = 'application/json'
                            r = requests.put(url, verify=False, json=data, headers=headers, allow_redirects=False)
                        else:
                            headers['Content-Type'] = 'application/x-www-form-urlencoded'
                            r = requests.put(url, verify=False, data=data, headers=headers, allow_redirects=False)
                elif user_method == "DELETE":
                    r = requests.delete(request_url, verify=False, headers=headers, data=data, allow_redirects=False)
                else:
                    r = requests.get(request_url, verify=False, headers=headers, data=data, allow_redirects=False)

                if args.proxy:
                    r = requests.request(user_method, request_url, headers=headers, data=data,
                                         proxies={"http": args.proxy, "https": args.proxy}, verify=False,
                                         allow_redirects=False)

                status_code = r.status_code
                if status_code == 200:
                    status_color = GREEN
                elif status_code in (401, 403):
                    status_color = RED
                else:
                    status_color = RESET
                print(f"{status_color}{user_method} {request_url}: {status_code}{RESET}")

    if custom_data and is_json(custom_data):
        try:
            json_data = json.loads(custom_data)
            modified_data = modify_api_data(json_data)
            print(f"{YELLOW}[INFO] Trying to modify data: {modified_data[0]}{RESET}")

            if user_method == "POST":
                headers['Content-Type'] = 'application/json'
                r = requests.post(url, verify=False, json=modified_data[0], headers=headers, allow_redirects=False)
            elif user_method == "PUT":
                headers['Content-Type'] = 'application/json'
                r = requests.put(url, verify=False, json=modified_data[0], headers=headers, allow_redirects=False)
            elif user_method == "PATCH":
                headers['Content-Type'] = 'application/json'
                r = requests.patch(url, verify=False, json=modified_data[0], headers=headers, allow_redirects=False)
            elif user_method == "DELETE":
                r = requests.delete(url, verify=False, headers=headers, json=modified_data[0], allow_redirects=False)

            if args.proxy:
                r = requests.request(user_method, url, headers=headers, json=modified_data[0],
                                     proxies={"http": args.proxy, "https": args.proxy}, verify=False,
                                     allow_redirects=False)

            status_code = r.status_code
            if status_code == 200:
                status_color = GREEN
            elif status_code in (401, 403):
                status_color = RED
            else:
                status_color = RESET
            print(f"{status_color}{user_method} {url}: {status_code}{RESET}")

            print(f"{YELLOW}[INFO] Trying to modify data: {modified_data[1]}{RESET}")

            if user_method == "POST":
                headers['Content-Type'] = 'application/json'
                r = requests.post(url, verify=False, json=modified_data[1], headers=headers, allow_redirects=False)
            elif user_method == "PUT":
                headers['Content-Type'] = 'application/json'
                r = requests.put(url, verify=False, json=modified_data[1], headers=headers, allow_redirects=False)
            elif user_method == "PATCH":
                headers['Content-Type'] = 'application/json'
                r = requests.patch(url, verify=False, json=modified_data[1], headers=headers, allow_redirects=False)
            elif user_method == "DELETE":
                r = requests.delete(url, verify=False, headers=headers, json=modified_data[1], allow_redirects=False)

            if args.proxy:
                r = requests.request(user_method, url, headers=headers, json=modified_data[1],
                                     proxies={"http": args.proxy, "https": args.proxy}, verify=False,
                                     allow_redirects=False)

            status_code = r.status_code
            if status_code == 200:
                status_color = GREEN
            elif status_code in (401, 403):
                status_color = RED
            else:
                status_color = RESET
            print(f"{status_color}{user_method} {url}: {status_code}{RESET}")

        except json.JSONDecodeError:
            print(f"\n{ORANGE}[WARNING] Unable to parse data as JSON. Skipping modification...{RESET}")


def perform_protocol_bypass(url, user_method, args, custom_headers=None, custom_data=None):
    print(f"\n{YELLOW}[INFO] Trying to bypass with HTTP protocols...{RESET}")

    base_url = url

    data = custom_data if custom_data is not None else {}

    http_versions = ["HTTP/1.0", "HTTP/1.1", "HTTP/2"]

    for version in http_versions:
        if args.method:
            user_method = args.method.upper()

        if not url.startswith("http"):
            url = f"http://{url}"

        parsed_url = urlparse(url)
        host = parsed_url.netloc
        path = parsed_url.path

        headers = {"Host": host}

        if custom_headers:
            headers |= custom_headers

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

            if user_method in ["POST", "PATCH", "PUT"] and data:
                if isinstance(data, dict):
                    headers['Content-Type'] = 'application/json'
                    data_bytes = json.dumps(data).encode('utf-8')
                else:
                    try:
                        json.loads(data)
                        headers['Content-Type'] = 'application/json'
                        data_bytes = data.encode('utf-8')
                    except ValueError:
                        headers['Content-Type'] = 'application/x-www-form-urlencoded'
                        data_bytes = data.encode('utf-8')

                conn.request(user_method, path, body=data_bytes, headers=headers)
            else:
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
        url = f"http://{url}"

    try:
        return urlparse(url)
    except ValueError as e:
        raise ValueError(
            "Invalid URL format. URL must be of the form 'http://example.com' or 'https://example.com'."
        ) from e


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Full path to be used", required=True, nargs=1)
    parser.add_argument("-m", "--method", help="Method to be used. Default is GET")
    parser.add_argument("-H", "--header", action="append", help="Add a custom header")
    parser.add_argument("-d", "--data", help="Add data to requset body. JSON is supported with escaping")
    parser.add_argument("-p", "--proxy", help="Use Proxy")
    parser.add_argument("--include-unicode", action="store_true", help="Include Unicode fuzzing (stressful)")
    parser.add_argument("--include-user-agent", action="store_true", help="Include User-Agent fuzzing (stressful)")
    parser.add_argument("--include-api", action="store_true", help="Include API fuzzing")

    args = parser.parse_args()

    custom_headers = None
    if args.header is not None:
        custom_headers = {}
        for header in args.header:
            key_value = header.split(':')
            if len(key_value) == 2:
                key, value = key_value
                custom_headers[key.strip()] = value.strip()
            else:
                print(f"\n{ORANGE}[WARNING] Invalid header format: {header}. Skipping...{RESET}\n")

    custom_data = args.data if args.data is not None else None
    try:
        initialize_bypass_procedures(args, custom_headers, custom_data)
    except KeyboardInterrupt:
        print(f"\n{ORANGE}[WARNING] Stopping...{RESET}")

    except ConnectionRefusedError:
        print(f"\n{RED}[ERROR] Connection refused{RESET}")

    except ConnectionError:
        print(f"\n{RED}[ERROR] Connection Error detected{RESET}")

    except requests.exceptions.SSLError as ssl_error:
        print(f"\n{RED}[ERROR] SSL Error: \n{ssl_error}{RESET}")

    except ValueError:
        print(f"\n{ORANGE}[WARNING] Please include a scheme (http:// or https://) inside the provided URL{RESET}")

    except requests.exceptions.ConnectionError as e:
        print(f"\n{RED}[ERROR] Connection Error: \n{e}{RESET}")

    except requests.exceptions.RequestException as e:
        print(f"\n{RED}[ERROR] Request Error: \n{e}{RESET}")


def execute_bypass_tests(args, headers_bypass, custom_headers, custom_data):
    url = args.url[0]
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'http://{url}'

    validate_result = validate_url(url)
    user_method = args.method or "GET"
    path = urlparse(url).path

    perform_headers_bypass(url, args, headers_bypass, custom_headers, custom_data)
    method_bypass = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "CONNECT", "TRACE", "OPTIONS", "INVENTED",
                     "HACK"]

    perform_method_bypass(url, args, headers_bypass, method_bypass, custom_headers, custom_data)
    perform_path_bypass(url, path, args, user_method, custom_headers, custom_data)
    perform_protocol_bypass(url, user_method, args, custom_headers, custom_data)

    if args.include_unicode:
        perform_unicode_bypass(url, path, user_method, args, custom_headers, custom_data)

    if args.include_user_agent:
        perform_user_agent_bypass(url, args, user_method, custom_headers, custom_data)

    if args.include_api:
        perform_api_bypass(url, path, user_method, args, custom_headers, custom_data)

    print(f"{GREEN}\n[+] Done.{RESET}")


def initialize_bypass_procedures(args, custom_headers, custom_data):
    with open('./wordlists/headers_bypass.txt') as f:
        headers_bypass = f.readlines()

    parsed_url = urlparse(args.url[0])
    path = parsed_url.path

    headers_bypass.append(f"X-Original-URL: {path}")
    headers_bypass.append(f"X-Rewrite-URL: {path}")

    if args.url:
        execute_bypass_tests(args, headers_bypass, custom_headers, custom_data)


if __name__ == '__main__':
    print_banner()
    main()
