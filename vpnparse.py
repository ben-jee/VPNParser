import argparse
import re
import requests
from bs4 import BeautifulSoup
import pandas as pd
import random
import time
import ipaddress
import csv
import os
import rich.progress
from rich.progress import Progress

#command line arguments parsing
parser = argparse.ArgumentParser(description="Process IP addresses from CSV.")
parser.add_argument("csv_file", help="Path to Network Log CSV.")
args = parser.parse_args()


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


#collect addresses from csv
def extract_ips(csv_file):
    ips = []
    visited_ips = set()
    with rich.progress.open(csv_file, 'r', newline='') as file:
        reader = csv.DictReader(file)
        if 'Url' in reader.fieldnames:      # REPLACE WITH IP COLUMN HEADER
            url_index = reader.fieldnames.index('Url')
            for row in reader:
                url = row[reader.fieldnames[url_index]]
                for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url):
                    if ip not in visited_ips and is_valid_ip:
                        ips.append(ip)
                        visited_ips.add(ip) 
    #print("Extracted IPs:", ips)
    return ips

#load known vpn addresses into pandas df from text files
def create_df(dc_file, vpn_file):
    dc_df = pd.read_csv(dc_file, header=None, names=['IP'])
    vpn_df = pd.read_csv(vpn_file, header=None, names=['IP'])
    return dc_df, vpn_df

#check if address is within subnet range
def ip_in_subnet(ip, df):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"\rSkipping invalid IP address: {ip}")
        return False
    for subnet in df['IP']:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
            return True
        return False

#check if in local data
def ip_in_local_data(ip):
    if not os.path.isfile('local_data.csv'):
        return False
    with open('local_data.csv', 'r', newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == ip:
                return True
    return False

#process ip addresses
def process_ips(ips, dc_df, vpn_df):
    processed_ips = {}
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing IPs...", total=len(ips))
    
        for ip in ips:
            if not is_valid_ip(ip):
                print(f"Invalid IP, skipping: {ip}")
                continue

        if ip_in_local_data(ip):
            service = fetch_local_service(ip)
            print(f"\r{ip} - Found in local data. Service: {service}")
            processed_ips[ip] = service
        
        with requests.Session() as session:
                for ip in ips:
                    if ip not in processed_ips and is_valid_ip(ip):
                        if ip_in_subnet(ip, vpn_df):
                            print(f"\r{ip} - VPN")
                            processed_ips[ip] = "VPN"
                        elif ip_in_subnet(ip, dc_df):
                            print(f"\r{ip} - Datacenter")
                            processed_ips[ip] = "DC"
                        else:
                            print(f"\r{ip} - Not found in text files, querying web...")
                            url = f"https://whatismyipaddress.com/ip/{ip}"
                            service = "IP could not be resolved... Is the address private?"
                            try:
                                headers = {
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0'
                                }
                                response = session.get(url, headers=headers)
                                response.encoding = 'utf-8'
                                soup = BeautifulSoup(response.content, 'html.parser')

                                """size = int(response.headers["Content-Length"]) 
                                with wrap_file(response, size) as file:
                                    for line in file:
                                        print(line.decode("utf-8"), end="") """

                                #soup debugging file
                                with open("soup.txt", "w", errors="ignore") as f:
                                    f.write(str(soup))

                                ip_detail_div = soup.find('div', class_='ip-detail expanded')
                                if ip_detail_div:
                                    service_tag = ip_detail_div.find('span', string='Services:')
                                    if service_tag:
                                        service_info = service_tag.find_next_sibling('span').text
                                        if 'VPN Server' in service_info:
                                            print(f"\rMatch for {ip} found online. Provided service(s): {service_info.strip()}")
                                            processed_ips[ip] = "VPN"
                                        elif 'Datacenter' in service_info:
                                            print(f"\rMatch for {ip} found online. Provided service(s): {service_info.strip()}")
                                            processed_ips[ip] = "DC"
                                        else:
                                            print(f"\rMatch for {ip} found online. Provided service(s): {service_info.strip()}")
                                            processed_ips[ip] = "OTHER"
                                    else:
                                        print(service)
                                else:
                                    print(service)
                            except Exception as e:
                                print(f"\rAn error occurred checking {ip}: {e}")
                            
                            # introduce random delay only after web query to keep rest of code fast
                            delay = random.uniform(3, 6)
                            time.sleep(delay)
                            progress.advance(task)
       
    return processed_ips


# for reading local data file 
def fetch_local_service(ip):
    with open('local_data.csv', 'r', newline='') as file:
        reader = csv.reader(file)
        next(reader) # skip header
        for row in reader:
            if row[0] == ip:
                return row[1] # return service column

#write ip addresses to CSV file
def write_to_csv(processed_ips):
    with open('local_data.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        if os.path.getsize('local_data.csv') == 0: #only write header if file is empty
            writer.writerow(['IP', 'Service'])
        for ip, service in processed_ips.items():
            if not ip_in_local_data(ip):
                writer.writerow([ip, service])

#main
def main(csv_file, dc_file, vpn_file):
    ips = extract_ips(csv_file)
    print("Number of IPs:", len(ips))
    dc_df, vpn_df = create_df(dc_file, vpn_file)   
    processed_ips = process_ips(ips, dc_df, vpn_df)
    write_to_csv(processed_ips)

#entry
if __name__ == "__main__":
    main(args.csv_file, 'ipv4 (DC).txt', 'ipv4 (VPN).txt')
