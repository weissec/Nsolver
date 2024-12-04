#!/usr/bin/env python3

# NSolver, 2024, W3155

import csv
import argparse
import whois
import dns.resolver
from ipwhois import IPWhois
import ssl
import socket
from tqdm import tqdm

def get_a_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers], None
    except Exception as e:
        return [], str(e)

def get_aaaa_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        return [str(rdata) for rdata in answers], None
    except Exception as e:
        return [], str(e)

def get_cname_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        return [str(rdata) for rdata in answers], None
    except Exception as e:
        return [], str(e)

def get_ip_owner(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        return results.get('network', {}).get('name', 'N/A'), None
    except Exception as e:
        return None, str(e)

def get_ssl_cn(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                return subject.get('commonName', 'N/A'), None
    except Exception as e:
        return None, str(e)

def process_domain(domain):
   
    a_record, a_error = get_a_record(domain)
    aaaa_record, aaaa_error = get_aaaa_record(domain)
    cname_record, cname_error = get_cname_record(domain)

    ip_owners = []
    for ip in a_record:
        owner, ip_error = get_ip_owner(ip)
        if ip_error:
            ip_owners.append('N/A')  # If there's an IP ownership lookup error, add 'N/A'
        else:
            ip_owners.append(owner)

    ssl_cn, ssl_error = get_ssl_cn(domain)
    if ssl_error:
        ssl_cn = 'N/A'  # If there's an SSL error, set CN to 'N/A'
    
    return {
        'Domain': domain,
        'A Record': ','.join(a_record) if a_record else 'N/A',
        'AAAA Record': ','.join(aaaa_record) if aaaa_record else 'N/A',
        'CNAME Record': ','.join(cname_record) if cname_record else 'N/A',
        'IP Owner': ','.join(ip_owners) if ip_owners else 'N/A',
        'SSL CN': ssl_cn
    }
    
def banner():
    font = """                 _                
 _ __  ___  ___ | |_   _____ _ __ 
| '_ \/ __|/ _ \| \ \ / / _ \ '__|
| | | \__ \ (_) | |\ V /  __/ |   
|_| |_|___/\___/|_| \_/ \___|_| W315
 
 """
    print(font)    

def main(input_file, output_file):
    with open(input_file, 'r') as infile:
        domains = [line.strip() for line in infile]
        
        print('# Found: ' + str(len(domains)) + ' domain(s)/subdomain(s).\n')

    results = []
    for domain in tqdm(domains, desc="Progress"):
        result = process_domain(domain)
        if result:
            results.append(result)

    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Domain', 'A Record', 'AAAA Record', 'CNAME Record', 'IP Owner', 'SSL CN']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            writer.writerow(result)
            
        print('\n# Finished processing domains. Results saved in CSV file: ' + str(output_file))

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(
        description="This script processes domains/subdomains to find DNS A records, AAAA records, CNAME records, IP ownership, and SSL certificate Common Names (CN).",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-i', '--input_file', type=str, required=True, help='Input file containing list of domains')
    parser.add_argument('-o', '--output_file', type=str, required=True, help='Output CSV file')
    
    args = parser.parse_args()
    
    main(args.input_file, args.output_file)
