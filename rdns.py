import dns.resolver
import dns.reversename
def rdns(ipaddrs: list) -> list:
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

ips = ["165.124.180.20", "59.24.3.174"]
for ip in ips:
    n = dns.reversename.from_address(ip)
    rdns = dns.resolver.query(n, "PTR")[0]
    pritn(rdns)