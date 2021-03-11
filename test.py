import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
location = ("insecure.stevetarzia.com/basic.html", 80)
result = sock.connect_ex(location)

print(result)