# Medjat — Contexte projet complet

> Ce fichier est lu automatiquement par Claude Code à chaque session.
> Il évite de réexpliquer le projet depuis zéro à chaque fois.

---

## C'est quoi Medjat ?

Medjat est un **OS custom basé sur Ubuntu/Debian**, conçu pour les PME.
- Apparence **camouflée Windows** (bureau similaire à Windows, barre des tâches en bas, menu démarrer)
- Architecture **plugin** : chaque fonctionnalité PME est un module Python indépendant
- Développé par **Simon Cantin** (sxc3030@gmail.com, GitHub: @sxc3030-eng)
- Objectif final : OS clé en main pour PME, installable comme Windows, zéro configuration

---

## Composante 1 — NetGuardPro Suite (cybersécurité)

**14 programmes Python** qui forment une suite de défense cyber complète.
Le code source réel est dans un **dépôt privé séparé** (accès 14 jours sur demande aux recruteurs).

| Programme | Rôle |
|-----------|------|
| Firewall/IDS | Détection intrusions réseau |
| Antivirus | Scan fichiers |
| VPN | Tunnel chiffré |
| SIEM | Corrélation d'événements sécurité |
| Honeypot | Leurre attaquants |
| FIM | File Integrity Monitor |
| StrikeBack | Contre-mesures actives |
| Forensic Recorder | Enregistrement preuves |
| Sandbox | Isolation exécution |
| RedTeam Simulator | 1522 lignes Python, port 8870, 9 types d'attaques |
| + 4 autres | ... |

**RedTeam Simulator** = programme phare :
- 9 types d'attaques : port scan, brute force, SYN flood, DNS tunnel, DPI trigger...
- 3 scénarios : script_kiddie, apt_simulation, full_redteam
- SafetyGuard : restreint les attaques à localhost/RFC1918 uniquement
- DefenseMonitor : mesure la couverture de détection
- Stack : Python 3.8+, WebSockets, scapy, SQLite

Dépôt public showcase : `github.com/sxc3030-eng/netguard-pro` (branche `main`)

---

## Composante 2 — Plugins PME (notre travail ensemble)

**5 plugins Python**, indépendants, tkinter + SQLite, zéro dépendance externe.

```
medjat-plugins/
├── launcher.py                  ← menu central (lance n'importe quel plugin)
├── requirements.txt             ← tout en stdlib Python, juste python3-tk à installer
├── data/                        ← créé au runtime (SQLite DBs + configs JSON)
└── plugins/
    ├── gestion_projet.py        ← projets, tâches, deadlines, statuts
    ├── support.py               ← tickets clients, priorités, notes, historique
    ├── calendrier.py            ← vue mensuelle, événements, clic pour ajouter
    ├── boite_mail.py            ← IMAP/SMTP, 3 panneaux style Outlook
    └── bot_rdv.py               ← scan inbox, détecte demandes RDV, répond auto
```

**Lancer les plugins :**
```bash
sudo apt install python3-tk
cd medjat-plugins
python3 launcher.py
```

**Branche GitHub :** `claude/medjat-i7-install-O2dJp`

**Plugins prévus mais pas encore faits :**
- CRM (gestion relation client)
- Facturation / Devis
- E-commerce (à la demande)
- Tableau de bord consolidé (KPIs de tous les plugins)

---

## État de l'installation sur le i7

### Situation actuelle (juin 2026)
- **Debian 13** installé sur le i7 mais **sans bureau graphique**
- Le système démarre sur une console texte (`tty1`, `localhost login:`)
- Cause : pendant l'install, le mot de passe WiFi a été refusé → pas d'internet → miroir "corrompu" → l'étape "Choisir et installer des logiciels" a échoué → aucun bureau installé

### Disques du i7
| Lettre Windows | Contenu | État |
|----------------|---------|------|
| C: | Windows principal | Intact |
| D: | Reformaté par l'install Linux | Maintenant ext4, disparu dans Windows |
| E:\d sauvegarde\ssd | **Sauvegarde du contenu D:** | À vérifier |
| G: | Projet Medjat (fichiers locaux) | À vérifier / comparer avec GitHub |

### Ce qui est sur GitHub vs local
- ✅ **Sur GitHub** : README, screenshots, 5 plugins PME, architecture NetGuardPro
- ❓ **Seulement en local (G:)** : code source des 14 programmes cyber, config OS Medjat, thèmes/apparence Windows, scripts système
- ⚠️ **Règle absolue** : ne jamais reformater/installer sans vérifier que `G:` et `E:\d sauvegarde\ssd` sont complets

### Pour réparer le bureau (Debian actuel, sans réinstaller)
```bash
# Brancher un câble Ethernet d'abord
ip a                          # vérifier la connexion
ping deb.debian.org           # tester internet
apt update
apt install kde-plasma-desktop sddm
systemctl set-default graphical.target
reboot
```

### Pour réinstaller proprement (si on repart à zéro)
- **NE PAS** utiliser l'ISO netinst (nécessite internet)
- Utiliser une **ISO complète** (DVD, ~3.7 Go) ou changer de base :
  - **Linux Mint** (recommandé, le plus proche Windows, installeur graphique simple)
  - **Zorin OS** (conçu pour ressembler à Windows pixel par pixel)
  - **Debian 13 DVD complet** (installable hors-ligne)
- Toujours brancher Ethernet pendant l'install
- AVANT de toucher aux partitions : `lsblk -f` pour inventaire disques

---

## Architecture prévue pour Medjat (vision complète)

```
Medjat OS
├── Base Ubuntu/Debian (camouflée Windows)
│   ├── Bureau KDE ou Zorin (barre tâches, menu démarrer)
│   └── Terminal intégré accessible depuis le bureau
├── NetGuardPro Suite (cybersécurité, 14 programmes)
└── Plugins PME (modules Python indépendants)
    ├── FAITS : Gestion projet, Support, Calendrier, Boîte mail, Bot RDV
    ├── FAITS (autres) : Marketing, Finance, Inventaire, RH
    └── À FAIRE : CRM, Facturation, E-commerce, Tableau de bord
```

---

## Rappels techniques

- **Language** : Python 3.8+
- **GUI** : tkinter (stdlib, zéro install sauf `python3-tk`)
- **DB** : SQLite (stdlib)
- **Mail** : imaplib + smtplib (stdlib)
- **OS cible** : Ubuntu/Debian (Linux), secondairement Windows 10/11
- **Dépôt GitHub** : `sxc3030-eng/netguard-pro`
- **Branche de travail** : `claude/medjat-i7-install-O2dJp`
- **Commit style** : `feat:`, `fix:`, `docs:` en minuscules

---

## Comment démarrer une session de travail

1. Claude lit ce fichier automatiquement → contexte complet chargé
2. Dire simplement ce sur quoi on travaille : "plugin X", "réparer le bureau", "nouveau plugin Y"
3. Pas besoin de réexpliquer Medjat, NetGuardPro, l'i7, les disques, etc.

**Pour mettre ce fichier à jour** : demander à Claude "mets à jour CLAUDE.md avec [info]"
