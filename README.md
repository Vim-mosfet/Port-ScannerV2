# Port-ScannerV2
Advanced Python port scanner built for Hack The Box labs, featuring service enumeration, OS detection, and structured output export.
AI was used to assist with the initial structure of the project. All features and improvements were reviewed and adapted manually. More information and usage instructions can be found in the README.md file.


⚠️ Disclaimer

This tool is intended for educational use only.
Do not scan systems without proper authorization.

## README.md - English
# TCP Port Scanner in Python

This project presents a TCP port scanner written in Python, designed to illustrate fundamental networking and socket concepts. It enables you to:

It allows you to:
- Scan all ports or a specified range on a target IP address
- Identify open ports and associated services
- Perform service and version detection
- Detect the target operating system (OS fingerprinting)
- Export scan results to multiple formats (TXT, JSON, CSV)

**Technologies Used:**

* Python 3.x
* Nmap
* python-nmap

**Prerequisites:**

*   Python 3.x installed on your system.

**Usage:**

```bash
python Auto_scan.py 
```

**Exemple**

![Image](https://github.com/user-attachments/assets/080fdbba-0614-45fb-8f93-22edc7cd0c2e)



**Script**

```
import argparse
import json
import csv
import os
import time
import itertools
import threading
from datetime import datetime
import nmap

# ------------------------------------------------------------------
# 1. Fonctions utilitaires
# ------------------------------------------------------------------

def styled_print(text):
    print(f"\033[92m{text}\033[0m")

def banner():
    art = r"""
    +======================================================================+
    |                                                                      |
    |   _____ ______   ________  ________  ________ _______  _________     |
    |  |\   _ \  _   \|\   __  \|\   ____\|\  _____\\  ___ \|\___   ___\   |
    |  \ \  \\\__\ \  \ \  \|\  \ \  \___|\ \  \__/\ \   __/\|___ \  \_|   |
    |   \ \  \\|__| \  \ \  \\\  \ \_____  \ \   __\\ \  \_|/__  \ \  \    |
    |    \ \  \    \ \  \ \  \\\  \|____|\  \ \  \_| \ \  \_|\ \  \ \  \   |
    |     \ \__\    \ \__\ \_______\____\_\  \ \__\   \ \_______\  \ \__\  |
    |      \|__|     \|__|\|_______|\_________\|__|    \|_______|   \|__|  |
    |                              \|_________|                            |
    |                                                                      |
    +======================================================================+
    """
    styled_print(art)

def spinner(stop_event):
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if stop_event.is_set():
            break
        print(f'\r[+] En cours… {c}', end='', flush=True)
        time.sleep(0.1)
    print('\r' + ' ' * 20, end='\r')

# ------------------------------------------------------------------
# 2. Scan principal
# ------------------------------------------------------------------

def scan(target, mode, output_prefix):
    nm = nmap.PortScanner()

    if mode == "rapide":
        args = "-T4 -F -sS -sV "
    elif mode == "complet":
        args = "-A -T4 -sS -sV "
    else:
        args = "-T4 -sS -sV "

    styled_print(f"\n[+] Scan {mode} en cours sur {target}...")

    stop_spinner = threading.Event()
    t_spin = threading.Thread(target=spinner, args=(stop_spinner,))
    t_spin.start()

    try:
        nm.scan(hosts=target, arguments=args)
    finally:
        stop_spinner.set()
        t_spin.join()

    results = []
    for host in nm.all_hosts():
        styled_print(f"\nHost: {host}")

        if 'osmatch' in nm[host]:
            for os in nm[host]['osmatch']:
                print(f"OS: {os['name']} ({os['accuracy']}%)")

        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]
                if service['state'] == 'open':
                    line = {
                        "host": host,
                        "port": port,
                        "service": service.get('name', ''),
                        "product": service.get('product', ''),
                        "version": service.get('version', '')
                    }
                    results.append(line)
                    styled_print(f"Port {port} -> {line['service']} {line['product']} {line['version']}")

    export_results(results, output_prefix)

# ------------------------------------------------------------------
# 3. Export
# ------------------------------------------------------------------

def export_results(results, prefix):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    with open(f"{prefix}_{timestamp}.txt", "w") as f:
        for r in results:
            f.write(str(r) + "\n")

    with open(f"{prefix}_{timestamp}.json", "w") as f:
        json.dump(results, f, indent=4)

    with open(f"{prefix}_{timestamp}.csv", "w", newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["host", "port", "service", "product", "version"]
        )
        writer.writeheader()
        writer.writerows(results)

    styled_print("\n[+] Résultats exportés !")

# ------------------------------------------------------------------
# 4. scan_ports (déplacé ici)
# ------------------------------------------------------------------

def scan_ports(target, ports='all', output_file=None):
    nm = nmap.PortScanner()
    try:
        print(f"Scan en cours sur {target}...")
        if ports == 'all':
            nm.scan(hosts=target, ports='1-65535', arguments='-T4')
        else:
            port_list = [int(p) for p in ports.split(',')]
            nm.scan(hosts=target, ports=','.join(map(str, port_list)), arguments='-T4')

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    if nm[host][proto][port]['state'] == 'open':
                        result = f"Port {port}: Ouvert - {nm[host][proto][port]['name']}\n"
                        print(result.strip())
                        if output_file:
                            with open(output_file, "a") as f:
                                f.write(result)

    except Exception as e:
        print(f"Erreur : {e}")

# ------------------------------------------------------------------
# 5. Menu
# ------------------------------------------------------------------

def menu():
    banner()

    print("""
===== NMAP SCANNER =====
1. Scan rapide
2. Scan complet
3. Quitter
""")
    choice = input("Choix : ")
    if choice == "1":
        mode = "rapide"
    elif choice == "2":
        mode = "complet"
    else:
        exit()

    target = input("IP ou hostname à scanner : ")

    scan_dir = "scans"
    os.makedirs(scan_dir, exist_ok=True)

    output_file_name = input("Nom du fichier de sortie (sans extension) : ")
    output_prefix = f"{scan_dir}/{output_file_name}"

    scan(target, mode, output_prefix)

# ------------------------------------------------------------------
# 6. Point d’entrée UNIQUE
# ------------------------------------------------------------------

if __name__ == "__main__":
    menu()

```



