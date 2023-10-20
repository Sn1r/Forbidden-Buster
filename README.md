# Forbidden Buster

Forbidden Buster is a tool designed to automate various techniques in order to bypass HTTP 401 and 403 response codes and gain access to unauthorized areas in the system. **This code is made for security enthusiasts and professionals only. Use it at your own risk.**

## Features

- Probes HTTP 401 and 403 response codes to discover potential bypass techniques.
- Utilizes various methods and headers to test and bypass access controls.
- Customizable through command-line arguments.
  
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
-u, --url: Full path to be used. This argument is required.
-m, --method: Method to be used. The default is GET.
-p, --proxy: Use a proxy.
--rate-limit: Set the rate limit (calls per second). The default rate limit is 10.
--include-unicode: Include Unicode bypass (stressful).
--include-user-agent: Include User-Agent bypass (stressful).
```

Example Usage:
```bash
python3 forbidden_buster.py -u http://example.com/secret --method POST --proxy http://proxy.example.com --rate-limit 5 --include-unicode --include-user-agent
```

## Credits
- **Hacktricks** - Special thanks for providing valuable techniques and insights used in this tool.
- **SecLists** - Credit to danielmiessler's SecLists for providing the wordlists.


