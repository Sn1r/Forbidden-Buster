![image](https://github.com/Sn1r/Forbidden-Buster/assets/71400526/2ea8ba03-965c-4288-a3b8-ef6a6202f4a5)

Forbidden Buster is a tool designed to automate various techniques in order to bypass HTTP 401 and 403 response codes and gain access to unauthorized areas in the system. **This code is made for security enthusiasts and professionals only. Use it at your own risk.**

## Features

- Probes HTTP 401 and 403 response codes to discover potential bypass techniques.
- Utilizes various methods and headers to test and bypass access controls.
- Customizable through command-line arguments.

### Updates
- Added API fuzzing methods, which probe for different API versions and also tamper with the data.
- Removed rate limiting feature for now. Better implementation in the future.
  
## Installation & Usage
Install requirements

```bash
pip3 install -r requirements.txt
```

Run the script

```bash
python3 forbidden_buster.py -u http://example.com
```

## Arguments
Forbidden Buster accepts the following arguments:

```bash
  -h, --help            show this help message and exit
  -u URL, --url URL     Full path to be used
  -m METHOD, --method METHOD
                        Method to be used. Default is GET
  -H HEADER, --header HEADER
                        Add a custom header
  -d DATA, --data DATA  Add data to requset body. JSON is supported with escaping
  -p PROXY, --proxy PROXY
                        Use Proxy
  --include-unicode     Include Unicode fuzzing (stressful)
  --include-user-agent  Include User-Agent fuzzing (stressful)
  --include-api         Include API fuzzing
```

Example Usage:
```bash
python3 forbidden_buster.py --url "https://example.com/api/v1/secret" --method POST --header "Authorization: Bearer XXX" --data '{\"key\":\"value\"}' --proxy "http://proxy.example.com" --include-api --include-unicode
```

## Credits
- **Hacktricks** - Special thanks for providing valuable techniques and insights used in this tool.
- **SecLists** - Credit to danielmiessler's SecLists for providing the wordlists.
- **kaimi** - Credit to kaimi's "Possible IP Bypass HTTP Headers" wordlist.

