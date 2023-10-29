# 
# ░░█ ▄▀█ █▀▀ █▄▀   ▀█▀ █░█ █▀▀   █▀▀ █░░ █ █▀▀ █▄▀ █▀▀ █▀█
# █▄█ █▀█ █▄▄ █░█   ░█░ █▀█ ██▄   █▄▄ █▄▄ █ █▄▄ █░█ ██▄ █▀▄
#                                                                                                                                                 
# Jack the Clicker 
# Version: 1.0.0
# Creation: 2023-10-28
# Author: yannawr
# Repository: github.com/yannawr/jacktheclicker
#
# Jack the Clicker is a Python3 script designed to scan a website to determine 
# if it's vulnerable to clickjacking.
# 
# It performs the following checks
#
#   1. Checks for the presence of the X-Frame-Options header and analyzes its content.
#   2. Verifies the existence of the Content Security Policy header and 
#      analyzes its content.
#   3. Identifies the presence of a Frame-Buster script in the page's source code.
# 
# For details on the requirements necessary to run the tool, please refer to the 
# requirements.txt file.

import sys
import re
import requests
import time

url = sys.argv[1]

def colour(color, text):
    colors = {
        'green_msg': '\033[92m',
        'red_msg': '\033[91m',
        'orange_msg': '\033[93m',
        'blue_msg': '\033[94m',
        'pink_msg': '\033[95m'
    }

    reset = '\033[0m'

    if color in colors:
        return f'{colors[color]}{text}{reset}'


def check_x_frame_options(url):
    try:
        response = requests.get(url)
        x_frame_options = response.headers.get('X-Frame-Options', '')

        if x_frame_options:
            if x_frame_options.lower() == 'deny' or x_frame_options.lower() == 'sameorigin':
                print(colour('green_msg', f'The site is likely protected against clickjacking. X-Frame-Options content: {x_frame_options}'))
                time.sleep(2)
            elif x_frame_options.lower() == 'allow-from *':
                print(colour('red_msg', f'[!] The site may be vulnerable to clickjacking. X-Frame-Options content: {x_frame_options}'))
                time.sleep(2)
            else:
                print(colour('orange_msg', f'[!] The site may be vulnerable to clickjacking. X-Frame-Options content: {x_frame_options}'))
                time.sleep(2)
        else:
            print(colour('red_msg', "[!] The site does not set the X-Frame-Options header."))
            time.sleep(2)

    except requests.exceptions.RequestException as e:
        print(f'Error accessing the site: {e}')

def check_csp(url):
    try:
        response = requests.get(url)
        content_security_policy = response.headers.get('Content-Security-Policy', '')

        if content_security_policy:
            print(colour('green_msg', 'CSP policies found: '))
            time.sleep(2)

            csp_policies = content_security_policy.split(';')

            for policy in csp_policies:
                print(policy.strip())
            
            frame_ancestors = re.search(r'frame-ancestors\s(.*?);', content_security_policy)
            if 'frame-ancestors' in content_security_policy:

                frame_ancestors_content = frame_ancestors.group(1)
                print(frame_ancestors_content)

                if frame_ancestors_content.lower() == '\'none\'':
                    print(colour('green_msg', f'The site is likely protected against clickjacking. Frame-ancestors content: {frame_ancestors_content}'))
                    time.sleep(2)
                elif frame_ancestors_content.lower() == '\'self\' *':
                    print(colour('red_msg', f'[!] The site may be vulnerable to clickjacking. Frame-ancestors content: {frame_ancestors_content}'))
                    time.sleep(2)
                else:
                    print(colour('orange_msg', f'[!] The site may be vulnerable to clickjacking. Frame-ancestors content: {frame_ancestors_content}'))
                    time.sleep(2)
            else:
                print(colour('red_msg', f'[!] Frame-ancestors is not present in the CSP policy.'))
                time.sleep(2)
        else:
            print(colour('red_msg', f'[!] No CSP policy found.'))
            time.sleep(2)

    except requests.exceptions.RequestException as e:
        print(f'Error accessing the site: {e}')


def check_frame_buster(url):

    try:
        response = requests.get(url)

        frame_buster = re.search(r'<script>(.*)if\(top \!= self\)\s*{', response.text, re.DOTALL | re.IGNORECASE)

        if frame_buster:
            print(colour('orange_msg', f'[!] Frame-buster found on the page, but can be bypassed using the \'sandbox=\"allow-forms\"\' attribute.'))
            time.sleep(2)
        else:
            print('Frame-buster not found on the page.')
            time.sleep(2)
    
    except requests.exceptions.RequestException as e:
        print(f'Error accessing the site: {e}')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 jacktheclicker.py <URL>')
    else:
        time.sleep(1)
        print(colour('blue_msg', 'Jack is clickjacking...\n'))
        time.sleep(2)
        check_x_frame_options(url)
        check_csp(url)
        check_frame_buster(url)