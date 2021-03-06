import sys, json, os, time, subprocess, socket, requests, maxminddb
import dns.resolver
import dns.reversename
from pathlib import Path
import time
import socket
import ssl


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

#Part 2 scanners to implement

#Part b,c
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
            result = subprocess.run(["nslookup", query_type, target, dns], \
                timeout=2, stdout=subprocess.PIPE, universal_newlines=True)
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

#Part d,e,f,g
def httpinfo_scanner(target: str) -> dict:
    response = {}
    #response = {
    #    "http_server": 0,
    #    "insecure_http": 0, 
    #    "redirect_to_https": 0,
    #    "hsts": 0,
    #}
    session = requests.Session()
    session.max_redirects = 10

    #insecure_http
    try:
        serverip = socket.gethostbyname(target)
        port = 80
    except socket.gaierror:
        print('Hostname could not be resolved. Exiting')
        sys.exit(2)
    except Exception as e:
        print("some other error occured")
        print(e.message)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((serverip, port))
        if result == 0:
            print("{} listens to response on port 80".format(target))
            response["insecure_http"] = True
        else:
            print("port not opened")
            print(result)
            response["insecure_http"] = False
        sock.close()
    except Exception as e:
        print("Port {}: Closed" .format(port))
        response["insecure_http"] = False
        print(e.message)
        print('lol')

    #redirect_to_https
    try:
        r = session.get("http://" + target, timeout=5)
        if r.url.startswith('https'):
            #redirects from http --> https
            response["redirect_to_https"] = True
        else:
            #didnt change our initial request on http
            response["redirect_to_https"] = False

        #http_server
        if 'server' in r.headers:
            response["http_server"] = r.headers['server'].split('/')[0] #to get rid of Apache/blahblahblah
        else:
            response["http_server"] = None

        #hsts
        if 'strict-transport-security' in r.headers:
            print("{} has hsts".format(target))
            response["hsts"] = True
        else:
            print("response for {url} doesn't have hsts".format(url=target))
            response["hsts"] = False

    except requests.TooManyRedirects as e:
        print("more 10 10 redirects, set redirect_to_https as FALSE since no page was reached")
        response["redirect_to_https"] = False
    except Exception as e:
        print("DERP! set stuff to = False for now")
        print(e)
        response["redirect_to_https"] = False
        response["http_server"] = None
        response["hsts"] = False
        #sys.exit(3)

    #return dict
    return response

#Part h
def tls_scanner(target: str) -> list:
    tls_v = []

    url = target + ":443"
    pro = {
        '-tls1': "TLSv1.0",
        '-tls1_1': "TLSv1.1",
        '-tls1_2': "TLSv1.2",
        '-tls1_3': "TLSv1.3",
    }
    try:
        for proto in pro.keys():
            pipein = subprocess.run(["echo"], check=True, stdout=subprocess.PIPE)
            outcome = subprocess.run(['openssl', 's_client', proto, '-connect', str(url)],
                                        input=pipein.stdout, stdout=subprocess.PIPE, timeout=2)

            for row in outcome.stdout.decode().split('\n'):
                row = row.lstrip()
                if row.startswith("Server certificate"): # row we want
                    #supports
                    tls_v.append(pro[proto])
    except Exception as e:
        print("Exception")
    
    context = ssl.create_default_context()

    try:
        with socket.create_connection((target, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                for cipher in context.get_ciphers():
                    protocol = cipher['protocol']
                    if protocol not in tls_v:
                        tls_v.append(protocol)
    except Exception:
        print(tls_v)
        return tls_v
    print(tls_v)
    return tls_v

#Part i
def root_ca_scanner(target: str) -> str:
    root_ca = None
    url = target + ":443"
    try:
        pipein = subprocess.run(["echo"], check=True, stdout=subprocess.PIPE)
        outcome = subprocess.run(['openssl', 's_client', '-connect', str(url)],
                                    input=pipein.stdout, stdout=subprocess.PIPE, timeout=2)
    
        chunks = outcome.stdout.decode("utf-8").split("---")
        cert_chain = chunks[1]
        for row in cert_chain.split('\n'):
            row = row.lstrip()
            if row.startswith("i:O"): # row we want
                split1 = row.split(',')
                intermediary = split1[0]
                split2 = intermediary.split('=')
                root_ca = split2[1].lstrip()
                print("##################")
                print(root_ca)
                print("##################")
    except Exception as e:
        print("Exception: prob timed out")
    
    return root_ca

#Part j

def rdns_scanner(ipaddrs: list) -> list:
    rdns = []
    for ipaddr in ipaddrs:
        try:
            n = dns.reversename.from_address(ipaddr)
            found = dns.resolver.query(n, "PTR")[0]
            rdns.append(str(found))
        except Exception as e:
            print("failed to reverse, try next ip")
    return rdns

#Part L
def geo_location_scanner(ipaddrs: list) -> list:
    locations = []
    reader = maxminddb.open_database('GeoLite2-City.mmdb')
    #Want "city, province, country", "city, province, country" ...list
    for ipaddr in ipaddrs:
        info = reader.get(ipaddr)
        if 'city' not in info:
            if 'province' not in info:
                if 'country' not in info:
                    #no data option
                    location = ''
                else:
                    #only country info
                    location = info['country']['names']['en']
            else:
                #only province & country
                location = info['subdivisions'][0]['names']['en'] \
                    +', '+info['country']['names']['en']
        else:
            #city,province,country all known
            location = info['city']['names']['en'] +', '+ \
                info['subdivisions'][0]['names']['en'] \
                +', '+info['country']['names']['en']
        #Check for duplicates
        if location in locations:
            pass
        else:
            locations.append(location)
    
    return locations

def rtt_scanner(ipaddrs: list) -> list:
    rt_times = []
    for addr in ipaddrs:
        for _ in range(5):
            s = socket.socket()
            s.settimeout(2)
            t1 = time.time()
            try:
                s.connect((str(addr), 443))
            except Exception:
                continue
            t2 = time.time()
            s.close()
            rt_times.append(t2 - t1)
    if len(rt_times) == 0:
        return None

    return [min(rt_times), max(rt_times)]


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
        #Part a
        scan_time = time.time()
        ### Scanning Helpers 
        ipv4addrs = ipvX_scanner(domain, DNS_SERVERS, 4)
        ipv6addrs = ipvX_scanner(domain, DNS_SERVERS, 6)
        http_info = httpinfo_scanner(domain)
        
        #print(http_info)
        tls_vs = tls_scanner(domain)
        root_ca = root_ca_scanner(domain)
        rdns_names = rdns_scanner(ipv4addrs)
        rtt_range = rtt_scanner(ipv4addrs)
        print(rdns_names)
        print(type(rdns_names))
        geolocations = geo_location_scanner(ipv4addrs)
        ###
        scan_result[domain] = {
            "scan_time": scan_time,
            "ipv4_addresses": ipv4addrs,
            "ipv6_addresses": ipv6addrs,
            "http_server": http_info["http_server"],
            "insecure_http": http_info["insecure_http"], 
            "redirect_to_https": http_info["redirect_to_https"],
            "hsts": http_info["hsts"],
            "tls_versions": tls_vs,
            "root_ca": root_ca,
            "rdns_names": rdns_names,
            "rtt_range": rtt_range,            
            "geo_locations": geolocations,
        }

    with open(outfile, "w") as f:
        json.dump(scan_result, f, sort_keys=True, indent=4)

if __name__ == '__main__':
    main()