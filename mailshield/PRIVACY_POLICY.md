# Politique de Confidentialite / Privacy Policy

**MailShield Pro v2.0.0 — NetGuard Pro**
*Derniere mise a jour : Mars 2026*

---

## Francais

### 1. Principe fondamental : ZERO CLOUD

MailShield Pro est un client email **100% local**. Aucune donnee ne quitte jamais votre ordinateur.

- **Aucun serveur distant** : Pas de cloud, pas de serveur tiers, pas de stockage externe
- **Aucune telemetrie** : Aucune collecte de statistiques, aucun tracking, aucun analytics
- **Aucune transmission** : Vos emails, contacts, mots de passe et parametres ne sont JAMAIS envoyes a NetGuard Pro, a des tiers, ni a aucun serveur

### 2. Donnees stockees localement

| Donnee | Emplacement | Chiffrement |
|--------|-------------|-------------|
| Emails (contenu, en-tetes) | `mailshield.db` (SQLite local) | Non (fichier local protege par l'OS) |
| Contacts | `mailshield.db` | Non |
| Mots de passe des comptes | `mailshield_settings.json` | **Oui** (chiffrement AES-like avec cle machine-unique) |
| Token API de session | `.api_token` | Genere aleatoirement a chaque session |
| Pieces jointes en quarantaine | `mailshield_quarantine/` | Non |
| Journal des menaces | `mailshield.db` | Non |
| Liste noire | `mailshield.db` | Non |
| Brouillons | `mailshield.db` | Non |
| Logs applicatifs | `mailshield.log` | Non (aucun contenu email dans les logs) |

### 3. Connexions reseau

MailShield Pro ne se connecte qu'aux serveurs suivants, et **uniquement a votre demande** :

| Connexion | But | Quand |
|-----------|-----|-------|
| Serveur IMAP de votre fournisseur (Gmail, Outlook, Yahoo, etc.) | Recevoir vos emails | Lors de la synchronisation |
| Serveur SMTP de votre fournisseur | Envoyer vos emails | Lors de l'envoi d'un message |
| `login.microsoftonline.com` | Authentification OAuth2 Microsoft | Uniquement si vous utilisez un compte Microsoft |
| `cdn.jsdelivr.net` | Charger la bibliotheque de securite DOMPurify | Au chargement du dashboard |

**Aucune autre connexion n'est etablie.** Aucune donnee n'est envoyee a NetGuard Pro.

### 4. Securite des mots de passe

- Les mots de passe sont chiffres avec une cle derivee de votre machine (nom d'ordinateur + utilisateur + chemin d'installation)
- Le mot de passe chiffre ne peut etre dechiffre que sur VOTRE machine
- Les mots de passe ne sont JAMAIS affiches dans l'interface (masques par `--------`)
- Les mots de passe ne sont JAMAIS transmis via l'API locale (endpoint `/api/settings` les masque)

### 5. Securite de l'API locale

- L'API fonctionne uniquement sur `127.0.0.1` (localhost) — inaccessible depuis l'exterieur
- Chaque session genere un token unique de 64 caracteres
- Les requetes CORS sont restreintes a l'origine locale uniquement
- Les en-tetes de securite (`X-Frame-Options`, `X-Content-Type-Options`) sont actifs

### 6. Ce que MailShield Pro ne fait PAS

- **Ne collecte PAS** de donnees personnelles
- **N'envoie PAS** de statistiques d'utilisation
- **Ne partage PAS** vos contacts ou emails avec des tiers
- **Ne stocke PAS** vos donnees dans le cloud
- **N'affiche PAS** de publicites
- **Ne vend PAS** vos donnees
- **N'utilise PAS** d'intelligence artificielle distante sur vos emails
- **Ne fait PAS** de profilage utilisateur

### 7. Suppression des donnees

Pour supprimer toutes vos donnees :
1. Supprimez le fichier `mailshield.db` (emails, contacts, menaces, brouillons)
2. Supprimez le fichier `mailshield_settings.json` (comptes, parametres)
3. Supprimez le dossier `mailshield_quarantine/` (pieces jointes en quarantaine)
4. Supprimez le fichier `.api_token` et `mailshield.log`

Aucune donnee residuelle ne subsistera nulle part.

### 8. Conformite

- **RGPD / GDPR** : Conforme — aucune donnee ne quitte votre appareil, pas de traitement distant
- **CCPA** : Conforme — aucune vente de donnees
- **PIPEDA** : Conforme — aucune collecte par un tiers

### 9. Contact

Pour toute question relative a la confidentialite :
NetGuard Pro — [Votre email de contact ici]

---

## English

### 1. Core Principle: ZERO CLOUD

MailShield Pro is a **100% local** email client. No data ever leaves your computer.

- **No remote servers**: No cloud, no third-party servers, no external storage
- **No telemetry**: No statistics collection, no tracking, no analytics
- **No transmission**: Your emails, contacts, passwords and settings are NEVER sent to NetGuard Pro, third parties, or any server

### 2. Locally Stored Data

| Data | Location | Encrypted |
|------|----------|-----------|
| Emails (content, headers) | `mailshield.db` (local SQLite) | No (local file protected by OS) |
| Contacts | `mailshield.db` | No |
| Account passwords | `mailshield_settings.json` | **Yes** (AES-like encryption with machine-unique key) |
| Session API token | `.api_token` | Randomly generated per session |
| Quarantined attachments | `mailshield_quarantine/` | No |
| Threat log | `mailshield.db` | No |
| Blacklist | `mailshield.db` | No |
| Drafts | `mailshield.db` | No |
| Application logs | `mailshield.log` | No (no email content in logs) |

### 3. Network Connections

MailShield Pro only connects to the following servers, and **only when you request it**:

| Connection | Purpose | When |
|------------|---------|------|
| Your provider's IMAP server (Gmail, Outlook, Yahoo, etc.) | Receive emails | During sync |
| Your provider's SMTP server | Send emails | When sending a message |
| `login.microsoftonline.com` | Microsoft OAuth2 authentication | Only if using a Microsoft account |
| `cdn.jsdelivr.net` | Load DOMPurify security library | On dashboard load |

**No other connections are made.** No data is sent to NetGuard Pro.

### 4. What MailShield Pro does NOT do

- Does **NOT** collect personal data
- Does **NOT** send usage statistics
- Does **NOT** share your contacts or emails with third parties
- Does **NOT** store your data in the cloud
- Does **NOT** display advertisements
- Does **NOT** sell your data
- Does **NOT** use remote AI on your emails
- Does **NOT** profile users

### 5. Data Deletion

To delete all your data:
1. Delete `mailshield.db` (emails, contacts, threats, drafts)
2. Delete `mailshield_settings.json` (accounts, settings)
3. Delete `mailshield_quarantine/` folder (quarantined attachments)
4. Delete `.api_token` and `mailshield.log`

No residual data will remain anywhere.

### 6. Compliance

- **GDPR**: Compliant — no data leaves your device, no remote processing
- **CCPA**: Compliant — no data sales
- **PIPEDA**: Compliant — no third-party collection

### 7. Contact

For privacy-related questions:
NetGuard Pro — [Your contact email here]
