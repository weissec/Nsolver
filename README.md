# Nsolver
OSINT tool that can be used to retrieve information from a list of domains/subdomains. Useful to determine the ownership of public assets. 

Given a list of domains and subdomanis, the tool extracts and presents the following information in a CSV file:
- DNS A Records
- DNS AAAA Records
- DNS CNAME Records
- SSL Certificate CN

### Upcoming Changes:
- The tool will be expanded to include an initial subdomain enumeration.
- Better layout and more information printed on screen.

### Usage:
```
pip install -r requirements.txt
python3 nsolver.py [-h] -i INPUT_FILE -o OUTPUT_FILE.csv
```

### Example Output:

| Domain | A Record | AAAA Record | CNAME Record | IP Owners | SSL CN |
| -------- | ------- | ------- | ------- | ------- | ------- |
| www.google.com | 172.217.16.228 | 2a00:1450:4009:821::2004 | N/A | GOOGLE | www.google.com |

