import socket

def port_scan(target, ports=None):
    if ports is None:
        ports = [21, 22, 23, 80, 443, 3306]
    print(f"\n[+] Scanning {target}...\n")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"[OPEN] Port {port}")
            open_ports.append(port)
        else:
            print(f"[CLOSED] Port {port}")
        sock.close()
    return open_ports