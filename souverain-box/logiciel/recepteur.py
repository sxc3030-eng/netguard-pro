#!/usr/bin/env python3
"""SouverainBox - recepteur (cote reseau).

Ecoute les messages UDP qui arrivent du cote sensible et les affiche.
Il ne renvoie JAMAIS rien : aucune reponse, aucun accuse de reception.
C'est le pendant logiciel du sens unique physique.

Usage :
    python3 recepteur.py [port]

Exemple :
    python3 recepteur.py 9000
"""
import socket
import sys
from datetime import datetime


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))

    print(f"[recepteur] Ecoute sur le port {port} (Ctrl+C pour arreter)")
    print("[recepteur] Ce programme ne renvoie jamais de reponse.")
    try:
        while True:
            donnees, origine = sock.recvfrom(65535)
            horodatage = datetime.now().isoformat(timespec="seconds")
            texte = donnees.decode("utf-8", errors="replace")
            print(f"[recepteur] {horodatage} recu de {origine[0]} : {texte}")
            # NOTE: on NE fait PAS sock.sendto(...) ici. Aucun retour, volontairement.
    except KeyboardInterrupt:
        print("\n[recepteur] arret.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
