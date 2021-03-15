import subprocess
import time
import socket

#given ipv4addrs, return [min, max]
def rtt_scanner(ipaddrs: list) -> list:
    rt_times = []
    for addr in ipaddrs:
        for _ in range (5):
            s = socket.socket()
            s.settimeout(2)
            t1 = time.time()
            s.connect((addr, 443))
            t2 = time.time()
            s.close()
            rt_times.append(t2 - t1)

        # try:
        #     result = subprocess.run(["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet {ip} 443".format(ip=addr)], \
        #         check=True, stdout=subprocess.PIPE, timeout=2)

            
        #     #pipein = subprocess.run(["time", "echo", "-e", "\x1dclose\x0d"], check=True, stdout=subprocess.PIPE)
        #     #result = subprocess.run(['telnet', addr], input=pipein.stdout, stdout=subprocess.PIPE, timeout=2)
        
        # except Exception as e:
        #     print("rtt_failed")
        #     print(e)
        #     continue #try next addr

        # a = result.stdout.decode()
        # print(a)
        # print(result)
        # print("!!!!!!!!!!!!!!!!!!!!!")
        # for row in a.split('\n'):
        #     if row.startswith("real"):
        #         _, ret_time = row.split('m')
        #         mins = ret_time[0].lstrip()
        #         secs = ret_time[1].rstrip()[:-1]
        #         total_rtt = int(mins)*60 + int(secs)
        #         rt_times.append(total_rtt)

    return [min(rt_times), max(rt_times)]

testaddrs = ["172.67.220.24", "104.21.35.119"]
res = rtt_scanner(testaddrs)
print("###")
print(res)
