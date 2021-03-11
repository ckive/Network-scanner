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

def tls_versions_scanner(target: str) -> str:
    url = target + ":443"

    pipein = subprocess.run(["echo"], check=True, capture_output=True)
    
    outcome = subprocess.run(['openssl', 's_client', '-connect', str(url)],
                                input=pipein.stdout, capture_output=True)