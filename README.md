
# RMDV - Honeypot Creator and IP Banning Tool

RMDV is a Python-based tool designed to create honeypots and automatically ban suspicious connections using IP-Tables. This tool is ideal for enhancing your server’s security by trapping malicious actors and preventing further attacks.

## Features
- Honeypot Creation: Set up fake services to lure attackers.
- IP Banning: Automatically add IP addresses to the IP-Tables blacklist.
- Logging: Log all things trough discord webhooks.

## Requirements
#### These things are needed to run RMDV smoothly:
- Linux server
- Python3


## Installation
#### Follow these steps to install and run RMDV:

```bash
git clone https://github.com/jonasdallmann/honeypot-linux.git
```

```bash
cd rmdv
```

```bash
pip install -r requirements.txt
```

- Configuration: Edit the config.json file to suit your needs.

```bash
python3 rmdv.py
```

## Contributing
Feel free to submit issues or pull requests if you find bugs or have improvements to suggest.



