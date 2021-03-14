import subprocess


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
    
    print(tls_v)
    return tls_v

tls_scanner("stevetarzia.com")