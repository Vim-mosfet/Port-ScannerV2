import argparse # pour le support de la ligne de commande
import os # pour la gestion des fichiers et dossiers
import time # pour le spinner
import itertools # pour le spinner
import threading # pour le spinner en multithread
import nmap # Assurez-vous d'avoir installé python-nmap (pip install python-nmap)
import json # export JSON

# ------------------------------------------------------------------
# 0. Détection de vulnérabilités (scripts NSE de Nmap)
# ------------------------------------------------------------------

VULN_SCRIPTS = "vuln"   # catégorie NSE "vuln" : CVE, ms17-010, heartbleed, etc.

def collect_scripts(service):
    """Récupère les scripts NSE exécutés sur un port (dict nom -> sortie)."""
    scripts = service.get('script', {})
    if isinstance(scripts, list):  # certaines versions renvoient une liste
        scripts = {s.get('id', str(i)): s.get('output', '') for i, s in enumerate(scripts)}
    return scripts or {}

def collect_host_scripts(host_data):
    """Récupère les scripts NSE de niveau hôte (liste de dicts ou dict)."""
    hostscript = host_data.get('hostscript', [])
    if isinstance(hostscript, dict):
        return dict(hostscript)
    scripts = {}
    for i, script in enumerate(hostscript or []):
        if isinstance(script, dict):
            scripts[script.get('id', f'hostscript{i}')] = script.get('output', '')
        else:
            scripts[f'hostscript{i}'] = str(script)
    return scripts

def clean_output(text):
    """Nettoie la sortie brute d'un script NSE pour l'affichage."""
    return (text or "").strip()

def is_vulnerable(output):
    """Heuristique : la sortie d'un script NSE signale-t-elle une vulnérabilité ?

    "NOT VULNERABLE" est ignoré ; les scripts affichant "State: VULNERABLE"
    ou "**VULNERABLE**" sont considérés comme vulnérables.
    """
    text = (output or "").upper()
    return "VULNERABLE" in text.replace("NOT VULNERABLE", "") or "EXPLOITABLE" in text

def print_script_output(script_name, script_out, port=None, proto=None):
    """Affiche le résultat d'un script NSE (rouge si vulnérabilité, bleu sinon)."""
    vuln = is_vulnerable(script_out)
    color = 91 if vuln else 94
    cible = f" ({port}/{proto})" if port is not None else " (hôte)"
    styled_print(f"    [{'VULNÉRABLE' if vuln else 'info'}] {script_name}{cible}", color=color)
    for line in clean_output(script_out).splitlines():
        styled_print(f"      {line}", color=color)
    return vuln

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
# 2. Scan amélioré (multi-cible, TCP/UDP, ports inhabituels, JSON, vulnérabilités)
# ------------------------------------------------------------------

def scan_target(target, mode, proto='tcp', output_prefix=None):
    nm = nmap.PortScanner()

    # Options de scan
    if mode == "rapide":
        args = f"-T4 -sS -sV --top-ports 200"  # scan rapide : top ports connus
    elif mode == "complet":
        args = f"-A -T4 -sS -sV -p-"          # scan complet : tous les ports, OS, scripts par défaut
    elif mode == "vuln":
        args = f"-T4 -sS -sV --script {VULN_SCRIPTS}"  # scan de vulnérabilités (scripts NSE "vuln")
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
    vuln_findings = []  # résultats des scripts NSE (vulnérabilités potentielles)

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
                scripts = collect_scripts(service)  # scripts NSE lancés en mode vuln
                line = {
                    "host": host,
                    "port": port,
                    "proto": proto_,
                    "state": state,
                    "service": name,
                    "product": product,
                    "version": version
                }
                if scripts:
                    line["scripts"] = scripts
                    line["vulnerable"] = any(is_vulnerable(o) for o in scripts.values())
                results.append(line)
                if port not in [22, 80, 443]:  # liste pour ports inhabituels
                    unusual_ports.append(line)
                    color = 91  # rouge
                else:
                    color = 92  # vert
                styled_print(f"{port}/{proto_} -> {state} | {name} {product} {version}", color=color)

                # NOUVEAU : résultats des scripts NSE exécutés sur ce port
                for script_name, script_out in scripts.items():
                    vuln_findings.append({
                        "host": host,
                        "port": port,
                        "proto": proto_,
                        "script": script_name,
                        "vulnerable": is_vulnerable(script_out),
                        "output": script_out
                    })
                    print_script_output(script_name, script_out, port, proto_)

        # NOUVEAU : scripts NSE au niveau de l'hôte (ex. smb-vuln-*)
        for script_name, script_out in collect_host_scripts(nm[host]).items():
            vuln_findings.append({
                "host": host,
                "port": None,
                "proto": "host",
                "script": script_name,
                "vulnerable": is_vulnerable(script_out),
                "output": script_out
            })
            print_script_output(script_name, script_out)

    # Export JSON
    if output_prefix:
        json_file = f"{output_prefix}_{target.replace('.', '_')}.json"
        with open(json_file, "w") as f:
            json.dump(results, f, indent=2)
        styled_print(f"\n[+] Résultats JSON enregistrés dans {json_file}", color=94)

        # Rapport dédié aux scripts NSE / vulnérabilités
        if vuln_findings:
            vuln_file = f"{output_prefix}_{target.replace('.', '_')}_vulns.json"
            with open(vuln_file, "w") as f:
                json.dump(vuln_findings, f, indent=2)
            styled_print(f"[+] Rapport de vulnérabilités enregistré dans {vuln_file}", color=94)

    # MODIF OBLIGATOIRE : Résumé ports inhabituels
    if unusual_ports:
        styled_print("\n[!] Résumé des ports inhabituels détectés :", color=93)
        for line in unusual_ports:
            styled_print(f"{line['port']}/{line['proto']} -> {line['state']} | {line['service']} {line['product']} {line['version']}", color=93)

    # NOUVEAU : Résumé des vulnérabilités détectées par les scripts NSE
    confirmed = [v for v in vuln_findings if v['vulnerable']]
    if vuln_findings:
        styled_print(f"\n[!] Scripts NSE exécutés : {len(vuln_findings)} | vulnérabilités potentielles : {len(confirmed)}", color=93)
    if confirmed:
        styled_print("\n[!] Résumé des vulnérabilités détectées :", color=91)
        for v in confirmed:
            cible = v['host'] if v['port'] is None else f"{v['host']}:{v['port']}/{v['proto']}"
            styled_print(f"{cible} -> {v['script']}", color=91)
    elif mode == "vuln":
        styled_print("\n[+] Aucune vulnérabilité connue détectée par les scripts NSE.", color=92)

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
5. Scan de vulnérabilités TCP (scripts NSE "vuln")
6. Scan de vulnérabilités UDP (scripts NSE "vuln")
7. Quitter
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
    elif choice == "5":
        mode, proto = "vuln", "tcp"
    elif choice == "6":
        mode, proto = "vuln", "udp"
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
