import socket
target = "127.0.0.1"
ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
port_names = {
21: "FTP",
22: "SSH"
23: "Telnet"
25: "SMTP"
53: "DNS"
80: "HTTP"
443: "HTTPS"
3306: "MySQL"
3389: "RDP"
8080: "HTTP-Alt"
}
print("Scanning" + target)
print("_" * 30)
for port in ports:
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)
result = sock.connect-ex ((target, port))
if result == 0:
print("Port} + str(port) + " " + poirt_names[port] + " -- OPEN")
else:
print("Port" + str(port) + " " + port_names[port] + " -- closed")
sock.close()
print("_" * 30)
print("Done.")

