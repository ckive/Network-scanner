import sys, json, os, time, subprocess
from pathlib import Path


def usage():
    print("python scan.py [input_file.txt] [output_file.json]")
    return

#validates extension and existence of paths, if outpath not exist, create it. if exists, overwrite it.
def validate(inpath, outpath) -> bool:
    if not inpath.endswith('.txt') or not outpath.endswith('.json'):
        print("wrong path extensions")
        return False
    if os.path.exists(inpath):
        if not os.path.exists(outpath):
            #outpath DNE, create it, if exists, write over it
            Path(outpath).touch()
        return True
    else:
        #inpath DNE, error
        print("input_file does not exist. Please check again.")
        return False

#Part B scanners to implement

"""
#pass in output from cli and target header, returns dict of headers and values as key value pair
def output_parser(output: str) -> dict:
    parsed = {}
    for row in result.split('\n'):
        if ':' in row:
            key, value = row.split(':')
            print(key)
            print(value)
            parsed[key] = value
    return parsed
"""

#given list of dns, scans for ipv4 addrs, returns list of unique ipv4 addrs
def ipv4_scanner(target: str, dnss: list) -> list:
    addrs = []
    for dns in dnss:
        result = subprocess.run(["nslookup", target, dns], capture_output=True, text=True)
        a = result.stdout.split('\n\n')[1]
        for row in a.split('\n'):
            if row.startswith("Address"):           #works with multiple ipv4s, each ipv4 will have a "Address: XXX.XXX.XXX.XXX"
                _, addr = row.split(' ')
                if addr not in addrs:
                    addrs.append(addr)
            elif row.startswith("***"):
                #No answer, try next DNS
                break
    #TODO: HANDLE EXCEPTIONS!
    return addrs
"""
#given list of dns, scans for ipv4 addrs, returns list of unique ipv4 addrs
def ipv6_scanner(target: str, dnss: list) -> list[str]:
    addrs = []
    for dns in dnss:
        result = subprocess.run(["nslookup", "-query=AAAA" target, dns], capture_output=True, text=True)
        a = result.stdout.split('\n\n')[1]
        for row in a.split('\n'):
            if row.startswith("Address"):           #works with multiple ipv6s
                _, addr = row.split(' ')
                if addr not in addrs:
                    addrs.append(addr)
            elif row.startswith("***"):
                #No answer, try next DNS
                break
    return addrs
"""

def main():
    if len(sys.argv) != 3:
        usage()
    infile = sys.argv[1]
    outfile = sys.argv[2]
    if not validate(infile, outfile):
        sys.exit(1)
    
    with open("public_dns_resolvers.txt") as f:
        DNS_SERVERS = [DNS_SERVERS.rstrip() for DNS_SERVERS in f]
    print(DNS_SERVERS)

    with open(infile) as f:
        scan_domains = [scan_domains.rstrip() for scan_domains in f]
        print(scan_domains)
    scan_result = {}
    for domain in scan_domains:
        scan_time = time.time()
        ### Scanning Helpers 
        ipv4addrs = ipv4_scanner(domain, DNS_SERVERS)
        #ipv6addrs = ipv6_scanner(domain, DNS_SERVERS)
        ###
        scan_result[domain] = {
            "scan_time": scan_time,
            "ipv4_addresses": 0,
            "ipv6_addresses": [],
            "http_server": "",
        }
    with open(outfile, "w") as f:
        json.dump(scan_result, f, sort_keys=True, indent=4)

if __name__ == '__main__':
    main()