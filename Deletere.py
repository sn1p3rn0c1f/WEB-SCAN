import os
import requests
import ssl
import socket
import nmap
import subprocess

title = "//DELETERE TOOL//"
os.system(f"title {title}")

subprocess.run ('color C', shell=True)
subprocess.run ('cls', shell=True)

menu = """
______ _____ _      _____ _____ ___________ _____ 
|  _  \  ___| |    |  ___|_   _|  ___| ___ \  ___|
| | | | |__ | |    | |__   | | | |__ | |_/ / |__  
| | | |  __|| |    |  __|  | | |  __||    /|  __| 
| |/ /| |___| |____| |___  | | | |___| |\ \| |___ 
|___/ \____/\_____/\____/  \_/ \____/\_| \_\____/ 
                                                  
"""
print(menu)

def check_https(url):
    if not url.startswith("http"):
        url = "https://" + url  
    try:
        response = requests.get(url, timeout=5)
        if response.url.startswith("https"):
            print(f"[✓] HTTPS activé sur {url}")
        else:
            print(f"[!] HTTPS non activé sur {url}")
    except requests.exceptions.RequestException:
        print(f"[X] Impossible d'accéder à {url}")

def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        print(f"[✓] Certificat SSL valide pour {domain}")
    except Exception as e:
        print(f"[!] Problème avec le certificat SSL de {domain} : {e}")

def check_http_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = [
            "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
            "X-XSS-Protection", "X-Content-Type-Options"
        ]
        print("\n[🔍] Vérification des en-têtes de sécurité :")
        for header in security_headers:
            if header in headers:
                print(f"[✓] {header} : {headers[header]}")
            else:
                print(f"[!] {header} manquant !")
    except requests.exceptions.RequestException:
        print(f"[X] Impossible d'accéder à {url}")

def scan_ports(domain):
    nm = nmap.PortScanner()
    print("\n[🔍] Scan des ports ouverts...")
    try:
        nm.scan(domain, arguments="-Pn -p 80,443,21,22,25,3306,8080")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    print(f"[{state.upper()}] Port {port} ouvert sur {host}")
    except Exception as e:
        print(f"[X] Erreur lors du scan des ports : {e}")

if __name__ == "__main__":
    site = input("Entrez le site web (sans https://) : ")
    url = f"https://{site}"
    
    check_https(url)
    check_ssl_certificate(site)
    check_http_headers(url)
    scan_ports(site)



  
    
    
