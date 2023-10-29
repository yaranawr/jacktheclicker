# Jack the Clicker

### About

Jack the Clicker is a Python3 script designed to scan a website to determine if it's vulnerable to clickjacking.

It performs the following checks

1. Checks for the presence of the X-Frame-Options header and analyzes its content.
2. Verifies the existence of the Content Security Policy header and analyzes its content.
3. Identifies the presence of a Frame-Buster script in the page's source code.

### Requiriments

The only Python library that doesn't come by default is Requests, so you can either install it using `python -m pip install requests` (you might need to use 'python3' instead), or through this script's requirements.txt using `pip install -r requirements.txt`.

### Installation

Download this repository:

```
git clone https://github.com/yannawr/jacktheclicker && cd jacktheclicker
```

### Usage

To use Jack the Clicker, simply run the script with a URL as an argument:

```bash
python3 jacktheclicker.py <URL>
```