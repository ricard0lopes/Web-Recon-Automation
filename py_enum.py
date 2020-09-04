#!/usr/bin/env python3

import subprocess
import os
import errno
import argparse
import datetime

# get url argument
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="Specify target URL")
    options = parser.parse_args()
    url = options.url
    if url is None:
        parser.print_usage()
        exit(0)

    check_dirs(url)
    subdomains(url)
    #thrd_lvl_domains(url)
    alive(url)
    subtkover(url)
    whatweb(url)
    wayback(url)
    nmap(url)
    eyewitness(url)

# check if directories and files exist
def check_dirs(url):

    if not os.path.exists(os.path.dirname(url)):
        try:
            os.makedirs(url)
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon")):
        try:
            os.makedirs(f"{url}/recon")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
#    if not os.path.exists(os.path.dirname(f"/{url}/recon/3rd-lvls")):
#        try:
#            os.makedirs(f"{url}/recon/3rd-lvls")
#        except OSError as exc: 
#            if exc.errno != errno.EEXIST:
#                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon/scans")):
        try:
            os.makedirs(f"{url}/recon/scans")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon/httprobe")):
        try:
            os.makedirs(f"{url}/recon/httprobe")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon/potential_takeovers")):
        try:
            os.makedirs(f"{url}/recon/potential_takeovers")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon/wayback")):
        try:
            os.makedirs(f"{url}/recon/wayback")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon/wayback/params")):
        try:
            os.makedirs(f"{url}/recon/wayback/params")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon/wayback/extensions")):
        try:
            os.makedirs(f"{url}/recon/wayback/extensions")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon/whatweb")):
        try:
            os.makedirs(f"{url}/recon/whatweb")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon/httprobe/alive.txt")):
        try:
            f = open(f"{url}/recon/httprobe/alive.txt", "w+")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon/final.txt")):
        try:
            f = open(f"{url}/recon/final.txt", "w+")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
#    if not os.path.exists(os.path.dirname(f"/{url}/recon/3rd-lvls/3rd-lvl-domains.txt")):
#        try:
#            f = open(f"{url}/recon/3rd-lvls/3rd-lvl-domains.txt", "w+")
#        except OSError as exc: 
#            if exc.errno != errno.EEXIST:
#                raise

# Enumerating subdomains
def subdomains(url):

    print("\n[+] Enumerating subdomains with assetfinder...\n")
    command = f"assetfinder {url} | grep '.{url}' | sort -u | tee -a {url}/recon/final1.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")

    print("\n[+] Double checking for subdomains with amass...\n")
    command = f"amass enum -d {url} | tee -a {url}/recon/final1.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")

    print("\n[+] Saving sorted results on final.txt...")
    command = f"sort -u {url}/recon/final1.txt >> {url}/recon/final.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")
    command = f"rm {url}/recon/final1.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")

# Enumerating 3rd lvl domains
#def thrd_lvl_domains(url):
#
#    print("\n[+] Compiling 3rd lvl domains...")
#    command = f"cat {url}/recon/final.txt | grep -Po '(\w+\.\w+\.\w+)$' | sort -u | tee -a {url}/recon/3rd-lvls/3rd-lvl-domains.txt"
#    result = subprocess.run(command, shell=True, executable="/bin/bash")
#    # write in line to recursively run through final.txt
#    command = f"for line in $(cat {url}/recon/3rd-lvls/3rd-lvl-domains.txt);do echo $line | sort -u | tee -a {url}/recon/final.txt;done"
#    result = subprocess.run(command, shell=True, executable="/bin/bash")
#
#    print("\n[+] Enumerating full 3rd lvl domains with sublist3r...")
#    command = f"for domain in $(cat {url}/recon/3rd-lvls/3rd-lvl-domains.txt);do sublist3r -d $domain -o {url}/recon/3rd-lvls/3rd-lvls/$domain.txt;done"
#    result = subprocess.run(command, shell=True, executable="/bin/bash")

# Probe for alive domains 
def alive(url):

    print("\n[+] Probing for alive domains...")
    command = f"cat {url}/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' | sort -u >> {url}/recon/httprobe/alive.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")

# Checking for possible subdomain takeover
def subtkover(url):

    print("\n[+] Checking for possible subdomain takeover...")

    if not os.path.exists(os.path.dirname(f"/{url}/recon/potential_takeovers/domains.txt")):
        try:
            f = open(f"{url}/recon/potential_takeovers/domains.txt", "w+")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    if not os.path.exists(os.path.dirname(f"/{url}/recon/potential_takeovers/potential_takeovers1.txt")):
        try:
            f = open(f"{url}/recon/potential_takeovers/potential_takeovers1.txt", "w+")
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    
    command = f"for line in $(cat {url}/recon/final.txt);do echo $line |sort -u >> {url}/recon/potential_takeovers/domains.txt;done"
    result = subprocess.run(command, shell=True, executable="/bin/bash")
    command = f"subjack -w {url}/recon/httprobe/alive.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> {url}/recon/potential_takeovers/potential_takeovers1.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")
    command = f"sort -u {url}/recon/potential_takeovers/potential_takeovers1.txt >> {url}/recon/potential_takeovers/potential_takeovers.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")
    command = f"rm {url}/recon/potential_takeovers/potential_takeovers1.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")

def whatweb(url):

    print("\n[+] Running whatweb on compiled domains...")
    now = datetime.datetime.now()
    f = open(f"{url}/recon/httprobe/alive.txt", "r")
    for domain in f:
        if not os.path.exists(os.path.dirname(f"/{url}/recon/whatweb/{domain}")):
            try:
                os.makedirs(f"{url}/recon/whatweb/{domain}")
            except OSError as exc: 
                if exc.errno != errno.EEXIST:
                    raise
        if not os.path.exists(os.path.dirname(f"/{url}/recon/whatweb/{domain}/output.txt")):
            try:
                f = open(f"{url}/recon/whatweb/{domain}/output.txt", "w+")
            except OSError as exc: 
                if exc.errno != errno.EEXIST:
                    raise
        if not os.path.exists(os.path.dirname(f"/{url}/recon/whatweb/{domain}/plugins.txt")):
            try:
                f = open(f"{url}/recon/whatweb/{domain}/plugins.txt", "w+")
            except OSError as exc: 
                if exc.errno != errno.EEXIST:
                    raise
        print(f"\n[*] Pulling plugins data on {domain} {now}\n")
        command = f"whatweb --info-plugins -t 50 -v {domain} | sort -u | tee -a {url}/recon/whatweb/{domain}/plugins.txt; sleep 3"
        result = subprocess.run(command, shell=True, executable="/bin/bash")
        print(f"\n[*] Running whatweb on {domain} {now}\n")
        command = f"whatweb -t 50 -v {domain} | sort -u | tee -a {url}/recon/whatweb/{domain}/output.txt; sleep 3"
        result = subprocess.run(command, shell=True, executable="/bin/bash")

def wayback(url):

    print("\n[+] Scraping wayback data...")
    command = f"cat {url}/recon/final.txt | waybackurls | tee -a  {url}/recon/wayback/wayback_output1.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")
    command = f"sort -u {url}/recon/wayback/wayback_output1.txt >> {url}/recon/wayback/wayback_output.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")
    command = f"rm {url}/recon/wayback/wayback_output1.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")

    print("\n[+] Pulling and compiling all possible params found in wayback data...")
    command = f"cat {url}/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> {url}/recon/wayback/params/wayback_params.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")
    command = f"for line in $(cat {url}/recon/wayback/params/wayback_params.txt);do echo $line'=';done"
    result = subprocess.run(command, shell=True, executable="/bin/bash")

    print("\n[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output...")
    f = open(f"{url}/recon/wayback/wayback_output.txt", "r")
    for line in f:
        if line.endswith(".js"):
            command = f"echo {line} | sort -u | tee -a  {url}/recon/wayback/extensions/js.txt"
            result = subprocess.run(command, shell=True, executable="/bin/bash")
        if line.endswith(".html"):
            command = f"echo {line} | sort -u | tee -a {url}/recon/wayback/extensions/jsp.txt"
            result = subprocess.run(command, shell=True, executable="/bin/bash")
        if line.endswith(".json"):
            command = f"echo {line} | sort -u | tee -a {url}/recon/wayback/extensions/json.txt"
            result = subprocess.run(command, shell=True, executable="/bin/bash")
        if line.endswith(".php"):
            command = f"echo {line} | sort -u | tee -a {url}/recon/wayback/extensions/php.txt"
            result = subprocess.run(command, shell=True, executable="/bin/bash")
        if line.endswith(".aspx"):
            command = f"echo {line} | sort -u | tee -a {url}/recon/wayback/extensions/aspx.txt"
            result = subprocess.run(command, shell=True, executable="/bin/bash")

def nmap(url):

    print("\n[+] Scanning for open ports...")
    command = f"nmap -iL {url}/recon/httprobe/alive.txt -sV -T4 -oA {url}/recon/scans/scanned.txt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")

def eyewitness(url):
    command = f"python3 /opt/EyeWitness/Python/EyeWitness.py --web -f {url}/recon/httprobe/alive.txt -d {url}/recon/eyewitness --resolve --no-prompt"
    result = subprocess.run(command, shell=True, executable="/bin/bash")

if __name__ == '__main__':
    main()
