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

#given list of dns, scans for ipvX addrs, returns list of unique ipvX addrs
def ipvX_scanner(target: str, dnss: list, version: int) -> list:
    if version == 4:
        query_type = "-query=A"
    elif version == 6:
        query_type = "-query=AAAA"
    else:
        #bad bad error
        sys.exit(2)
    addrs = []
    for dns in dnss:
        try:
            result = subprocess.run(["nslookup", query_type, target, dns], timeout=2, capture_output=True, text=True)
        except ValueError as error:
            print(error)
            sys.exit(1)
        except subprocess.TimeoutExpired as error:
            print("timeout happened, moving on to next dns or next domain")
            print(error)
            break #Design choice: don't stop, pull through
            #sys.exit(1)

        a = result.stdout.split('\n\n')[1]
        for row in a.split('\n'):
            if row.startswith("Address"):
                _, addr = row.split(' ')
                if addr not in addrs:
                    addrs.append(addr)
            elif row.startswith("***"):
                #No answer, try next DNS
                break
        #print(addrs)
    return addrs



def main():
    if len(sys.argv) != 3:
        usage()
        sys.exit(1)
    
    infile = sys.argv[1]
    outfile = sys.argv[2]
    if not validate(infile, outfile):
        sys.exit(1)
    
    with open("public_dns_resolvers.txt") as f:
        DNS_SERVERS = [DNS_SERVERS.rstrip() for DNS_SERVERS in f]
    #print(DNS_SERVERS)

    with open(infile) as f:
        scan_domains = [scan_domains.rstrip() for scan_domains in f]
        #print(scan_domains)
    scan_result = {}
    for domain in scan_domains:
        scan_time = time.time()
        ### Scanning Helpers 
        ipv4addrs = ipvX_scanner(domain, DNS_SERVERS, 4)
        ipv6addrs = ipvX_scanner(domain, DNS_SERVERS, 6)
        ###
        scan_result[domain] = {
            "scan_time": scan_time,
            "ipv4_addresses": ipv4addrs,
            "ipv6_addresses": ipv6addrs,
            "http_server": "",
        }
    with open(outfile, "w") as f:
        json.dump(scan_result, f, sort_keys=True, indent=4)

if __name__ == '__main__':
    main()