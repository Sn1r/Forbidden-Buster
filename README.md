![image](https://github.com/Sn1r/Forbidden-Buster/assets/71400526/d2f8ea28-f650-442f-9a89-115fee0e97ac)

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/) ![image](https://github.com/Sn1r/Forbidden-Buster/assets/71400526/b1f3cdd6-3d00-4bbb-94c1-38a9204add71)


Forbidden Buster is a tool designed to automate various techniques in order to bypass HTTP 401 and 403 response codes and gain access to unauthorized areas in the system. **This code is made for security enthusiasts and professionals only. Use it at your own risk.**

## Features

- Probes HTTP 401 and 403 response codes to discover potential bypass techniques.
- Utilizes various methods and headers to test and bypass access controls.
- Customizable through command-line arguments.

### 🚀 Updates
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

### Using Docker
You can also use Docker to run Forbidden-Buster. This approach ensures that you have a consistent environment without needing to install Python on your host machine.

#### Building the Docker Image
First, build the Docker image:

```bash
docker build -t Forbidden-Buster-image .
```

#### Running the Docker Container
Next, run the Docker container. You need to pass a folder containing the files to analyze as a volume:

```bash
docker run --rm -it -v /path/to/your/folder:/app Forbidden-Buster-image /bin/bash
```

Inside the container, navigate to the /app directory and run your analysis using Forbidden-Buster command as normal.

> [!NOTE]  
> Make sure to replace /path/to/your/folder with the actual path to the folder containing the files you want to analyze. This command mounts your local folder into the /app directory inside the container, allowing you to run the Forbidden-Buster command on your files.

## Arguments
Forbidden Buster accepts the following arguments:

```bash
  -h, --help            show this help message and exit
  -u URL, --url URL     Full path to be used
  -f FILE, --file FILE  Include a file with multiple URLs to be tested.
  -o OUTPUT, --output OUTPUT
                        Print the results to an output file, Usage i.e: output.txt.
  -m METHOD, --method METHOD
                        Method to be used. Default is GET.
  -H HEADER, --header HEADER
                        Add a custom header.
  -d DATA, --data DATA  Add data to requset body. JSON is supported with escaping.
  -p PROXY, --proxy PROXY
                        Use Proxy, Usage i.e: 127.0.0.1:8080.
  --include-unicode     Include Unicode fuzzing (stressful).
  --include-user-agent  Include User-Agent fuzzing (stressful).
  --include-api         Include API fuzzing.
```

Example Usage:
```bash
python3 forbidden_buster.py --url "https://example.com/api/v1/secret" --method POST --header "Authorization: Bearer XXX" --data '{\"key\":\"value\"}' --proxy "http://proxy.example.com" --include-api --include-unicode
```

## Credits
- **Hacktricks** - Special thanks for providing valuable techniques and insights used in this tool.
- **SecLists** - Credit to danielmiessler's SecLists for providing the wordlists.
- **kaimi** - Credit to kaimi's "Possible IP Bypass HTTP Headers" wordlist.

