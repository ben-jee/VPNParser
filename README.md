# VPNParser
Python script to parse and detect VPN IPs within a network log
--------------------------------------------------------------

!Usage!
python vpnparser.py "your_network_log.csv"

Credit to X4B.Net for their VPN and Datacenter known IP list -> https://github.com/X4BNet
IPs not present in these are checked and scraped from https://whatismyipaddress.com/

VPN and Datacenter connections commonly appear as raw IP addresses in network logs. By parsing through with this script, IPs are checked against the sources above.
Some addresses return as "OTHER" - these are typically safe addresses and not assosciated with any datacenters or VPNs.
The script generates a local list of already processed IPs for easy CSV export.
Depending on the structure of your network logs, you may need to change the selected header for IP retrieval in the source code. (See Below)

![image](https://github.com/ben-jee/VPNParser/assets/75759861/2d39e329-3267-44cf-8d5e-386d1fd56751)

