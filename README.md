# Web-Recon-Automation

A simple script that automates recon and enumeration of domains and subdomains.

The script was written in python and its main purpose is to automate reconaissance, interacting with the Linux command line. It starts by creating the necessary directories and files to store the information, then it goes through subdomain enumeration, sorting out the results in a final text file. Then, it checks the text file for alive subdomains, storing the alive subdomains in another text file, that later will be used to check for possible subdomain takeovers. The script also goes through the process of identifying the alive websites and enumerate their current technologies, alongside other information, as well as searching for past changes on them using WayBackUrls and checking for open ports. To finalize it takes screenshots of every website categorized as "alive".

Tools that this script automates:

  * Assetfinder
  * Amass
  * HTTPROBE
  * Subjack
  * Whatweb
  * Waybackurls
  * Nmap
  * EyeWitness
  
  
There is also a commented section that was written to look for 3rd level subdomains. This section was commented monstly due to the fact that through the enumeration with sublist3r, my IP was constantly being blocked.
Fell free to uncomment that section and use this script to also automate 3rd level subdomains.

Usage: python3 py_enum.py -u <url>
  
Feel free to make any changes or improve the coding style of this script. That would be highly appreciated.

