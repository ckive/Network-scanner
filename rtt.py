import subprocess

#given ipv4addrs, return [min, max]
def rtt_scanner(ipaddrs: list) -> list:
    rt_times = []
    for addr in ipaddrs:
        try:
            result = subprocess.run(["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet {ip}".format(ip=addr)], \
                check=True, stdout=subprocess.PIPE, timeout=2)

            
            #pipein = subprocess.run(["time", "echo", "-e", "\x1dclose\x0d"], check=True, stdout=subprocess.PIPE)
            #result = subprocess.run(['telnet', addr], input=pipein.stdout, stdout=subprocess.PIPE, timeout=2)
        
        except Exception as e:
            print("rtt_failed")
            print(e)
            continue #try next addr

        a = result.stdout.decode()
        print("!!!!!!!!!!!!!!!!!!!!!")
        for row in a.split('\n'):
            if row.startswith("real"):
                print("here:")
                print(row)
                _, ret_time = row.split('m')
                mins = ret_time[0].lstrip()
                secs = ret_time[1].rstrip()[:-1]
                print(mins, secs)
                total_rtt = int(mins)*60 + int(secs)
                rt_times.append(total_rtt)

    return rt_times

testaddrs = ["172.67.220.24", "104.21.35.119"]
res = rtt_scanner(testaddrs)
print("###")
print(res)