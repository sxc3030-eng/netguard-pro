#!/usr/bin/env python3
"""SouverainBox - emetteur (cote sensible).

Envoie des messages en UDP vers le cote reseau. L'UDP n'attend AUCUNE reponse :
il n'y a pas d'accuse de reception, donc le flux est naturellement a sens unique.
Combine avec le diode physique (fibre), rien ne peut revenir.

Usage :
    python3 emetteur.py <ip_destination> [port]

Exemple :
    python3 emetteur.py 192.168.50.20 9000
"""
import socket
import sys
import time
from datetime import datetime


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 emetteur.py <ip_destination> [port]")
        sys.exit(1)

    destination = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9000

    # SOCK_DGRAM = UDP : on envoie "dans le vide", sans connexion de retour.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[emetteur] Envoi vers {destination}:{port} (Ctrl+C pour arreter)")
    compteur = 0
    try:
        while True:
            compteur += 1
            horodatage = datetime.now().isoformat(timespec="seconds")
            message = f"msg #{compteur} | {horodatage} | SouverainBox"
            sock.sendto(message.encode("utf-8"), (destination, port))
            print(f"[emetteur] envoye : {message}")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[emetteur] arret.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
