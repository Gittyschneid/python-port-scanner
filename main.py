import socket
import ssl

COMMON_PORTS = {21: "FTP", 22: "SSH",23: "Telnet",25: "SMTP",53: "DNS", 80: "HTTP", 110: "POP3",143: "IMAP",443: "HTTPS",3306: "MySQL",3389: "RDP", 5900: "VNC",8080: "HTTP-Alt"}

def check_ssh(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=5) as connect: #create a socket connection
            banner = connect.recv(1024).decode().strip() #receive the banner from the server
            if banner:
                print(f"    SSH Banner: {banner}") #print the banner if it exists
            else:
                print("    No SSH banner received.")
    except Exception as e: #catch any errors
        print(f"    SSH check failed: {e}")


def check_tls_version(ip, port):
    try:
        context = ssl.create_default_context() #create ssl settings with secure defaults
        with socket.create_connection((ip, port), timeout=5) as connect: #create a socket connection
            with context.wrap_socket(connect, server_hostname=ip) as c_connect: #Takes the basic connection and adds SSL encryption to it
                tls_version = c_connect.version() #get the TLS version
                cipher = c_connect.cipher() #get the encryption method 
                print(f"    TLS Version: {tls_version}")
                if cipher:
                    print(f"    Cipher: {cipher[0]} ({cipher[1]} bits)") #print of exists the encryption method and strength
    except ssl.SSLError as e: #catch any SSL errors
        print(f"    SSL Error: {e}")
    except Exception as e: #catch any other errors
        print(f"    TLS check failed: {e}")

    
def scan_ports(ip, ports, timeout=1):
    open_ports = [] #a list to store any ports that are found to be open
    for port in ports: #loop through the list of ports
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connect: #create a socket connection
            connect.settimeout(timeout) #add the timeout (1) for the connection attempt
            result = connect.connect_ex((ip, port))
            if result == 0: #if the connection was successful
                open_ports.append(port) #add the port to the list of open ports
    return open_ports

def main():
    target_ip = input("Enter IP address to scan: ").strip()
    print(f"Scanning {target_ip} for common ports...")
    open_ports = scan_ports(target_ip, COMMON_PORTS.keys())
    if open_ports:
        print("Open ports:")
        for port in open_ports:
            print(f"  {port} ({COMMON_PORTS[port]})")
            if port == 443 or COMMON_PORTS[port] == "HTTPS": # If it's HTTPS, check TLS version
                check_tls_version(target_ip, port)
            if port == 22 or COMMON_PORTS[port] == "SSH": # If it's SSH, detect SSH version
                check_ssh(target_ip, port)
    else:
        print("No common ports open.")

if __name__ == "__main__":
    main()
    