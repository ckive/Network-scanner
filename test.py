import subprocess

#try:
#    result = subprocess.run(["echo", "|", "openssl", "s_client", "-connect", "stevetarzia.com:443"], timeout=2, capture_output=True, text=True)

#except Exception as e:
#    print(e)

#subprocess.run(["echo", "|", "openssl"])
def root_ca(target: str) -> str:
    url = target + ":443"
    
    print(url)
    
    versions = ["-tls1", "-tls1_", "-tls1", ]

    pipein = subprocess.run(["echo"], check=True, capture_output=True)
    
    outcome = subprocess.run(['openssl', 's_client', '-connect', str(url)],
                                input=pipein.stdout, capture_output=True)
    
    chunks = outcome.stdout.decode("utf-8").split("---")
    cert_chain = chunks[1]
    for row in cert_chain.split('\n'):
        row = row.lstrip()
        if row.startswith("i:O"): # row we want
            split1 = row.split(',')
            intermediary = split1[0]
            split2 = intermediary.split('=')
            root_ca = split2[1].lstrip()

            print(root_ca)
    return root_ca

def tls_versions_scanner(target: str) -> list:
    url = target + ":443"

    pipein = subprocess.run(["echo"], check=True, capture_output=True)
    
    outcome = subprocess.run(['openssl', 's_client', '-connect', str(url)],
                                input=pipein.stdout, capture_output=True)

import dns.resolver
import dns.reversename
def rdns(ipaddr: str) -> list:
    #https://stackoverflow.com/questions/2575760/python-lookup-hostname-from-ip-with-1-second-timeout
    #https://stackoverflow.com/questions/49121746/reverse-dns-lookup-using-dnspython-module
    #https://www.dnspython.org/examples/
    try:
        n = dns.reversename.from_address(ipaddr)
        #ans = dns.resolver.resolve(n, 'PTR')
        print(n)
        print(type(n))
        print(dir(n))
        print("#############")
        print(ans)
    except Exception as e:
        print(e)

target = "165.124.180.20"
google = "59.24.3.174"
#rdns(google)
#print(dns.reversename.to_address(n))

################################################
import time
import socket
def RTT(host="127.0.0.1", port=80, timeout=10):
    #https://stackoverflow.com/questions/62877690/calculating-rtt-using-an-ip-address
    # Format our parameters into a tuple to be passed to the socket
    sock_params = (host, port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Set the timeout in the event that the host/port we are pinging doesn't send information back
        sock.settimeout(timeout)
        # Open a TCP Connection
        sock.connect(sock_params)
        # Time prior to sending 1 byte
        t1 = time.time()
        sock.sendall(b'1')
        data = sock.recv(1)
        # Time after receiving 1 byte
        t2 = time.time()
        # RTT
        return t2-t1
# url address 
#url = "http://205.251.242.103:433"
#RTT("205.251.242.103", 433) 


#socket.gethostbyaddr("165.124.147.150")

import maxminddb
def geo_location_scanner(ipaddrs: list) -> list:
    locations = []
    reader = maxminddb.open_database('GeoLite2-City.mmdb')
    #Want "city, province, country", "city, province, country" ...list
    for ipaddr in ipaddrs:
        info = reader.get(ipaddr)
        print(info.keys())
        print("#########")
        b = info['country']['names']['en']
        print(b)
        #city = info['city']['names']['en']
        #province = info['subdivisions'][0]['names']['en']
        #country = info['country']['names']['en']
        #location = city + province + country
        #locations.append(location)
    return locations

a = geo_location_scanner([
            "172.67.220.24",
            "104.21.35.119"
        ])
print(a)