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
python Automatisation_scanNmap.py <IP> --ports <ports>
```

**Exemple**

```bash
python Auto_scan.py 192.1.1.1

```

**Script**

```
import argparse # pour le support de la ligne de commande
import json # pour l'export JSON
import csv # pour l'export CSV
import os # pour la gestion des fichiers et dossiers
import time # pour le spinner
import itertools # pour le spinner
import threading # pour le spinner en multithread
from datetime import datetime # pour les timestamps dans les noms de fichiers
import nmap # Assurez-vous d'avoir installé python-nmap (pip install python-nmap)

# ------------------------------------------------------------------
# 1. Fonctions utilitaires (couleurs, bannière et spinner)
# ------------------------------------------------------------------

def styled_print(text):
    """Affichage en vert."""
    print(f"\033[92m{text}\033[0m")   # 92 = vert, 0 = reset

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
    """Spinner simple affiché pendant le scan."""
    for c in itertools.cycle(['|', '/', '-', '\\']): # boucle infinie pour le spinner
        if stop_event.is_set():
            break # si l'événement d'arrêt est déclenché, on sort de la boucle
        print(f'\r[+] En cours… {c}', end='', flush=True) # affichage du spinner sur la même ligne
        time.sleep(0.1)
    print('\r' + ' ' * 20, end='\r')   # efface la ligne

# ------------------------------------------------------------------
# 2. Scan et export des résultats (avec options de scan et export améliorées)
# ------------------------------------------------------------------

def scan(target, mode, output_prefix):
    nm = nmap.PortScanner()

    # Options de base + furtif + NSE vuln
    if mode == "rapide":
        args = "-T4 -F -sS -sV " # scan rapide : moins de ports, mais détection de version
    elif mode == "complet":
        args = "-A -T4 -sS -sV " # scan complet : détection OS, versions, scripts vulnérabilités
    else:
        args = "-T4 -sS -sV " # par défaut : scan standard

    styled_print(f"\n[+] Scan {mode} en cours sur {target}...") # message de début de scan

    # Spinner multithread
    stop_spinner = threading.Event()
    t_spin = threading.Thread(target=spinner, args=(stop_spinner,))
    t_spin.start()

    try:
        nm.scan(hosts=target, arguments=args) # lancement du scan avec les arguments définis
    finally:
        stop_spinner.set()
        t_spin.join()

    results = []
    for host in nm.all_hosts(): 
        styled_print(f"\nHost: {host}") 

        # OS detection
        if 'osmatch' in nm[host]:
            for os in nm[host]['osmatch']:
                print(f"OS: {os['name']} ({os['accuracy']}%)")

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                if service['state'] == 'open': # on ne garde que les ports ouverts
                    name = service.get('name', '') # nom du service (ex: http)
                    product = service.get('product', '') # nom du produit (ex: Apache httpd)
                    version = service.get('version', '') # version du produit (ex: 2.4.41)
                    line = {
                        "host": host,
                        "port": port,
                        "service": name,
                        "product": product,
                        "version": version
                    }
                    results.append(line)
                    styled_print(f"Port {port} -> {name} {product} {version}") # affichage stylé du résultat

    export_results(results, output_prefix) # export des résultats dans différents formats


def export_results(results, prefix):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # TXT
    with open(f"{prefix}_{timestamp}.txt", "w") as f:  # on ajoute le timestamp pour éviter d’écraser les fichiers précédents et on utilise le préfixe pour inclure le dossier et le nom de base
        for r in results:
            f.write(str(r) + "\n")

    # JSON
    with open(f"{prefix}_{timestamp}.json", "w") as f: # même logique pour le nom du fichier JSON
        json.dump(results, f, indent=4)

    # CSV
    with open(f"{prefix}_{timestamp}.csv", "w", newline='') as f: # même logique pour le nom du fichier CSV
        writer = csv.DictWriter(
            f,
            fieldnames=["host", "port", "service", "product", "version"] # les champs à inclure dans le CSV
        )
        writer.writeheader()
        writer.writerows(results)

    styled_print("\n[+] Résultats exportés !") # message de confirmation après l’export


# ------------------------------------------------------------------
# 3. Menu CLI (inchangé)
# ------------------------------------------------------------------

def menu():
    banner()          # affichage de la bannière

    print("""
===== NMAP SCANNER ===== # menu de sélection du mode de scan
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

    target = input("IP ou hostname à scanner : ") # demande de la cible à scanner

    # Le dossier de sauvegarde (créé si besoin)
    scan_dir = "scans"
    os.makedirs(scan_dir, exist_ok=True)

    output_file_name = input("Nom du fichier de sortie (sans extension) : ") # demande du nom de fichier de sortie
    output_prefix = f"{scan_dir}/{output_file_name}"   # préparation du préfixe pour inclure le dossier et le nom de base

    scan(target, mode, output_prefix)


if __name__ == "__main__":

    # ------------------------------------------------------------------
    # 4. Support optionnel : parser d’arguments depuis la ligne de commande
    # ------------------------------------------------------------------
    
    parser = argparse.ArgumentParser(
        description="Scanner les ports d'une IP ou hostname."
    )
    parser.add_argument("target", help="IP ou hostname")
    parser.add_argument("--ports", help="Ports ex: 80,443 (défaut : all)")
    parser.add_argument(
        "--output",
        help=(
            "Nom du fichier de sortie sans extension. "
            "Le script créera le dossier 'scans/' automatiquement."
        )
    )
    args = parser.parse_args()

    ports = args.ports if args.ports else 'all'
    output_file = args.output

    # Préparer la variable prefix : <dossier>/<nom_fichier>
    if output_file:
        with open(output_file, "w") as f:
            f.write("Scan en cours...\n")
        # ici on remplace simplement le préfixe pour qu’il inclue le dossier
        output_prefix = f"scans/{output_file}"
    else:
        output_prefix = None

    scan_ports(args.target, ports, output_prefix)


# ------------------------------------------------------------------
# 4. Fonction principale (inchangé)
# ------------------------------------------------------------------

def scan_ports(target, ports='all', output_file=None):
    # Cette fonction est appelée depuis le CLI ou directement.
    nm = nmap.PortScanner() # Initialise le PortScanner, l'objet principal pour interagir avec Nmap
    try:
        print(f"Scan en cours sur {target}...") # Message de début de scan
        if ports == 'all':
            nm.scan(hosts=target, ports='1-65535', arguments='-T4') # Scan de tous les ports avec une vitesse de scan rapide (-T4)
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto]:
                        if nm[host][proto][port]['state'] == 'open':
                            result = f"Port {port}: Ouvert - {nm[host][proto][port]['name']}\n"
                            print(result.strip())
                            if output_file:
                                with open(output_file, "a") as f:
                                    f.write(result)
        else:
            port_list = [int(p) for p in ports.split(',')]
            port_str = ','.join(str(p) for p in port_list)
            nm.scan(hosts=target, ports=port_str, arguments='-T4')
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


if __name__ == "__main__":
    menu()

```



