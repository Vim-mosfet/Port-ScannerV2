import argparse # pour le support de la ligne de commande
import os # pour la gestion des fichiers et dossiers
import time # pour le spinner
import itertools # pour le spinner
import threading # pour le spinner en multithread
import nmap # Assurez-vous d'avoir installé python-nmap (pip install python-nmap)
import json # export JSON

# ------------------------------------------------------------------
# 1. Fonctions utilitaires (couleurs, bannière et spinner)
# ------------------------------------------------------------------

def styled_print(text, color=92):
    """Affichage coloré. Vert par défaut."""
    print(f"\033[{color}m{text}\033[0m")   # 92 = vert, 0 = reset

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
    print('\r' + ' ' * 40, end='\r')   # efface la ligne

# ------------------------------------------------------------------
# 2. Scan amélioré (multi-cible, TCP/UDP, ports inhabituels, JSON)
# ------------------------------------------------------------------

def scan_target(target, mode, proto='tcp', output_prefix=None):
    nm = nmap.PortScanner()

    # Options de scan
    if mode == "rapide":
        args = f"-T4 -sS -sV --top-ports 200"  # scan rapide : top ports connus
    elif mode == "complet":
        args = f"-A -T4 -sS -sV -p-"          # scan complet : tous les ports, OS, scripts vuln
    else:
        args = "-T4 -sS -sV"                   # par défaut

    if proto.lower() == 'udp':
        args += " -sU"                         # ajout du scan UDP si choisi

    styled_print(f"\n[+] Scan {mode} ({proto.upper()}) en cours sur {target}...")

    # Spinner multithread
    stop_spinner = threading.Event()
    t_spin = threading.Thread(target=spinner, args=(stop_spinner,))
    t_spin.start()

    try:
        nm.scan(hosts=target, arguments=args)
    finally:
        stop_spinner.set()
        t_spin.join()

    results = []
    unusual_ports = []  #liste pour ports inhabituels

    for host in nm.all_hosts():
        styled_print(f"\nHost: {host}")

        # OS detection
        if 'osmatch' in nm[host]:
            for os in nm[host]['osmatch']:
                print(f"OS: {os['name']} ({os['accuracy']}%)")

        for proto_ in nm[host].all_protocols():
            for port in nm[host][proto_]:
                service = nm[host][proto_][port]
                state = service.get('state', '')
                name = service.get('name', '')
                product = service.get('product', '')
                version = service.get('version', '')
                line = {
                    "host": host,
                    "port": port,
                    "proto": proto_,
                    "state": state,
                    "service": name,
                    "product": product,
                    "version": version
                }
                results.append(line)
                if port not in [22, 80, 443]:  # liste pour ports inhabituels
                    unusual_ports.append(line)
                    color = 91  # rouge
                else:
                    color = 92  # vert
                styled_print(f"{port}/{proto_} -> {state} | {name} {product} {version}", color=color)

    # Export JSON
    if output_prefix:
        json_file = f"{output_prefix}_{target.replace('.', '_')}.json"
        with open(json_file, "w") as f:
            json.dump(results, f, indent=2)
        styled_print(f"\n[+] Résultats JSON enregistrés dans {json_file}", color=94)

    # MODIF OBLIGATOIRE : Résumé ports inhabituels
    if unusual_ports:
        styled_print("\n[!] Résumé des ports inhabituels détectés :", color=93)
        for line in unusual_ports:
            styled_print(f"{line['port']}/{line['proto']} -> {line['state']} | {line['service']} {line['product']} {line['version']}", color=93)

    return results

def scan(targets, mode, proto='tcp', use_threads=False, output_prefix=None):
    if isinstance(targets, str):
        targets = [targets]

    if use_threads:
        threads = []
        for t in targets:
            th = threading.Thread(target=scan_target, args=(t, mode, proto, output_prefix))
            th.start()
            threads.append(th)
        for th in threads:
            th.join()
    else:
        for t in targets:
            scan_target(t, mode, proto, output_prefix)

# ------------------------------------------------------------------
# 3. Menu CLI amélioré
# ------------------------------------------------------------------

def menu():
    banner()

    print("""
===== NMAP SCANNER =====
1. Scan rapide TCP
2. Scan complet TCP
3. Scan rapide UDP
4. Scan complet UDP
5. Quitter
""")
    choice = input("Choix : ")

    if choice == "1":
        mode, proto = "rapide", "tcp"
    elif choice == "2":
        mode, proto = "complet", "tcp"
    elif choice == "3":
        mode, proto = "rapide", "udp"
    elif choice == "4":
        mode, proto = "complet", "udp"
    else:
        exit()

    targets_input = input("IP(s) ou hostname(s) à scanner (séparés par des virgules) : ")
    targets = [t.strip() for t in targets_input.split(',')]

    thread_choice = input("Utiliser le mode multi-thread ? (o/N) : ").lower()
    use_threads = thread_choice == 'o'

    output_prefix = input("Préfixe pour fichier JSON (laisser vide pour aucun) : ").strip() or None

    scan(targets, mode, proto, use_threads, output_prefix)

# ------------------------------------------------------------------
# 4. Fonction principale inchangée
# ------------------------------------------------------------------

def scan_ports(target, ports='all', output_file=None):
    nm = nmap.PortScanner()
    try:
        print(f"Scan en cours sur {target}...")
        if ports == 'all':
            nm.scan(hosts=target, ports='1-65535', arguments='-T4')
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
