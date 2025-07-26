import socket
import itertools
import time

def port_scanner(target, ports):
    print(f"\n[+] Scanning {target} for open ports...\n")
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) 
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[OPEN] Port {port} is open")
                open_ports.append(port)
            s.close()
        except KeyboardInterrupt:
            print("\n[-] Scan aborted by user.")
            break
        except Exception as e:
            print(f"[-] Error on port {port}: {e}")
    if not open_ports:
        print("[-] No open ports found.")
    return open_ports

def brute_force(username, password_list, real_password):
    print(f"\n[+] Starting brute force on username: {username}\n")
    for password in password_list:
        print(f"Trying password: {password}")
        time.sleep(0.2)  
        if password == real_password:
            print(f"\n[SUCCESS] Password found for {username}: {password}")
            return password
    print("\n[-] Password not found in list.")
    return None

if __name__ == "__main__":
    print("""
    ===============================
       PENETRATION TESTING TOOLKIT
    ===============================
    1. Port Scanner
    2. Brute Force (Demo)
    """)

    choice = input("Choose an option (1/2): ")

    if choice == "1":
        target = input("Enter target IP (e.g., 127.0.0.1): ")
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 8080]
        port_scanner(target, ports)

    elif choice == "2":
        username = input("Enter username: ")
        real_password = "admin123"  
        password_list = ["1234", "password", "admin", "letmein", "admin123"]
        brute_force(username, password_list, real_password)

    else:
        print("[-] Invalid choice.")