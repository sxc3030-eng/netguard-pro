"""
Medjat Plugin — Bot RDV
Scan la boite mail, detecte les demandes de rendez-vous,
verifie le calendrier, repond automatiquement
Peut tourner en daemon ou etre lance manuellement
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sqlite3
import json
import os
import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from email.header import decode_header
import threading
import re
from datetime import datetime, date, timedelta

CAL_DB = os.path.join(os.path.dirname(__file__), '..', 'data', 'calendrier.db')
CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'mail_config.json')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'bot_rdv.log')
BOT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'bot_rdv_config.json')

MOTS_CLES_RDV = [
    r'rendez.vous', r'r\.d\.v', r'rdv', r'réunion', r'meeting',
    r'disponible', r'appointment', r'schedule', r'book', r'réserver',
    r'rappel', r'rencontre', r'entretien', r'consultation',
]

MOTS_CLES_DATE = [
    r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}',
    r'\d{4}-\d{2}-\d{2}',
    r'(lundi|mardi|mercredi|jeudi|vendredi|samedi|dimanche)',
    r'(monday|tuesday|wednesday|thursday|friday|saturday|sunday)',
    r'(demain|après-demain|prochain|prochaine)',
    r'\d{1,2}h\d{0,2}',
    r'\d{1,2}:\d{2}',
]

DEFAULT_BOT_CONFIG = {
    'actif': True,
    'heures_debut': '09:00',
    'heures_fin': '17:00',
    'jours_ouvrables': [0, 1, 2, 3, 4],  # lundi-vendredi
    'duree_rdv_minutes': 60,
    'message_confirmation': (
        "Bonjour,\n\nMerci pour votre demande de rendez-vous.\n"
        "Je suis disponible le {date} à {heure}.\n\n"
        "Merci de confirmer votre présence.\n\nCordialement"
    ),
    'message_indisponible': (
        "Bonjour,\n\nMerci pour votre demande de rendez-vous.\n"
        "Malheureusement, je ne suis pas disponible aux dates mentionnées.\n"
        "Pourriez-vous proposer d'autres créneaux ?\n\nCordialement"
    ),
}


def load_mail_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}


def load_bot_config():
    if os.path.exists(BOT_CONFIG_PATH):
        with open(BOT_CONFIG_PATH) as f:
            return {**DEFAULT_BOT_CONFIG, **json.load(f)}
    return DEFAULT_BOT_CONFIG.copy()


def save_bot_config(cfg):
    os.makedirs(os.path.dirname(BOT_CONFIG_PATH), exist_ok=True)
    with open(BOT_CONFIG_PATH, 'w') as f:
        json.dump(cfg, f, indent=2)


def decode_str(s):
    if not s:
        return ''
    parts = decode_header(s)
    result = []
    for part, enc in parts:
        if isinstance(part, bytes):
            result.append(part.decode(enc or 'utf-8', errors='replace'))
        else:
            result.append(str(part))
    return ''.join(result)


def get_body_text(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode(
                    part.get_content_charset() or 'utf-8', errors='replace')
    else:
        return msg.get_payload(decode=True).decode(
            msg.get_content_charset() or 'utf-8', errors='replace') if msg.get_payload(decode=True) else ''
    return ''


def detecter_rdv(texte):
    texte_lower = texte.lower()
    for mot in MOTS_CLES_RDV:
        if re.search(mot, texte_lower):
            return True
    return False


def extraire_dates(texte):
    dates = []
    for pattern in MOTS_CLES_DATE:
        matches = re.findall(pattern, texte.lower())
        dates.extend(matches)
    return dates


def creneaux_disponibles(date_cible, duree_min=60, heures_debut='09:00', heures_fin='17:00'):
    """Renvoie les créneaux libres pour une date donnée."""
    try:
        if not os.path.exists(CAL_DB):
            return _generer_creneaux(date_cible, heures_debut, heures_fin, duree_min, [])
        conn = sqlite3.connect(CAL_DB)
        conn.row_factory = sqlite3.Row
        date_str = date_cible.strftime('%Y-%m-%d')
        evts = conn.execute(
            "SELECT heure_debut, heure_fin FROM evenements WHERE date_debut=?",
            (date_str,)).fetchall()
        conn.close()
        occupes = [(e['heure_debut'], e['heure_fin']) for e in evts if e['heure_debut']]
        return _generer_creneaux(date_cible, heures_debut, heures_fin, duree_min, occupes)
    except Exception:
        return []


def _generer_creneaux(date_cible, h_debut, h_fin, duree_min, occupes):
    creneaux = []
    def to_min(h):
        try:
            hh, mm = h.split(':')
            return int(hh) * 60 + int(mm)
        except Exception:
            return 0
    def from_min(m):
        return f"{m//60:02d}:{m%60:02d}"
    debut = to_min(h_debut)
    fin = to_min(h_fin)
    occupes_min = []
    for od, of_ in occupes:
        if od and of_:
            occupes_min.append((to_min(od), to_min(of_)))
    t = debut
    while t + duree_min <= fin:
        t_fin = t + duree_min
        libre = all(not (od < t_fin and of_ > t) for od, of_ in occupes_min)
        if libre:
            creneaux.append(from_min(t))
        t += 30
    return creneaux


def reserver_creneau(date_str, heure, titre, participant=''):
    """Ajoute l'événement dans le calendrier."""
    if not os.path.exists(CAL_DB):
        return False
    try:
        conn = sqlite3.connect(CAL_DB)
        h_parts = heure.split(':')
        h_fin_min = int(h_parts[0]) * 60 + int(h_parts[1]) + 60
        heure_fin = f"{h_fin_min//60:02d}:{h_fin_min%60:02d}"
        conn.execute(
            "INSERT INTO evenements (titre, date_debut, heure_debut, heure_fin, type, participant) VALUES (?,?,?,?,?,?)",
            (titre, date_str, heure, heure_fin, 'RDV Client', participant))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def log(msg, callback=None):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{now}] {msg}"
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(line + '\n')
    if callback:
        callback(line)


class BotRDVApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Medjat — Bot RDV")
        self.root.geometry("900x620")
        self.root.configure(bg='#1e1e2e')
        self.mail_cfg = load_mail_config()
        self.bot_cfg = load_bot_config()
        self.actif = False
        self.timer = None
        self._build_ui()
        self._charger_log()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', background='#313244', foreground='#cdd6f4',
                        fieldbackground='#313244', rowheight=26)
        style.configure('Treeview.Heading', background='#45475a', foreground='#cdd6f4')

        # Header
        header = tk.Frame(self.root, bg='#a6e3a1', height=50)
        header.pack(fill='x')
        tk.Label(header, text="  Bot Rendez-vous", font=('Helvetica', 16, 'bold'),
                 bg='#a6e3a1', fg='#1e1e2e').pack(side='left', pady=10)
        self.lbl_status = tk.Label(header, text="● Inactif", font=('Helvetica', 11, 'bold'),
                                    bg='#a6e3a1', fg='#f38ba8')
        self.lbl_status.pack(side='right', padx=15)

        # Controles
        ctrl = tk.Frame(self.root, bg='#181825', pady=8)
        ctrl.pack(fill='x', padx=10)
        self.btn_start = tk.Button(ctrl, text="Démarrer le bot", command=self._demarrer,
                                    bg='#a6e3a1', fg='#1e1e2e', relief='flat',
                                    padx=12, pady=5, font=('Helvetica', 10, 'bold'))
        self.btn_start.pack(side='left', padx=5)
        tk.Button(ctrl, text="Scan manuel", command=self._scan_manuel,
                  bg='#89b4fa', fg='#1e1e2e', relief='flat', padx=10,
                  font=('Helvetica', 10, 'bold')).pack(side='left', padx=5)
        tk.Button(ctrl, text="Paramètres", command=self._parametres,
                  bg='#6c7086', fg='#cdd6f4', relief='flat', padx=10).pack(side='left', padx=5)
        tk.Button(ctrl, text="Effacer log", command=self._effacer_log,
                  bg='#45475a', fg='#cdd6f4', relief='flat', padx=8).pack(side='right', padx=5)

        # Split
        pane = tk.PanedWindow(self.root, orient='horizontal', bg='#1e1e2e', sashwidth=4)
        pane.pack(fill='both', expand=True, padx=10, pady=8)

        # Historique détections
        left = tk.Frame(pane, bg='#1e1e2e')
        pane.add(left, minsize=380)
        tk.Label(left, text="Demandes détectées", font=('Helvetica', 11, 'bold'),
                 bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=5, pady=(5, 2))
        cols = ('date', 'expediteur', 'sujet', 'action')
        self.tree_det = ttk.Treeview(left, columns=cols, show='headings', height=18)
        for c, w, h in [('date', 110, 'Date'), ('expediteur', 130, 'Expéditeur'),
                         ('sujet', 140, 'Sujet'), ('action', 80, 'Action')]:
            self.tree_det.heading(c, text=h)
            self.tree_det.column(c, width=w)
        self.tree_det.pack(fill='both', expand=True, padx=5)
        self.tree_det.tag_configure('confirme', foreground='#a6e3a1')
        self.tree_det.tag_configure('indispo', foreground='#f38ba8')

        # Log
        right = tk.Frame(pane, bg='#181825')
        pane.add(right, minsize=300)
        tk.Label(right, text="Journal du bot", font=('Helvetica', 11, 'bold'),
                 bg='#181825', fg='#cdd6f4').pack(anchor='w', padx=10, pady=(5, 2))
        self.log_text = scrolledtext.ScrolledText(
            right, bg='#11111b', fg='#a6e3a1', font=('Courier', 9),
            wrap='word', relief='flat', state='disabled')
        self.log_text.pack(fill='both', expand=True, padx=10, pady=5)

        # Config rapide
        cfg_frame = tk.LabelFrame(right, text="Config rapide", bg='#181825',
                                   fg='#cdd6f4', relief='flat')
        cfg_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(cfg_frame, text="Horaires :", bg='#181825', fg='#cdd6f4').grid(row=0, column=0, padx=5, pady=3, sticky='w')
        self.var_h_debut = tk.StringVar(value=self.bot_cfg['heures_debut'])
        self.var_h_fin = tk.StringVar(value=self.bot_cfg['heures_fin'])
        tk.Entry(cfg_frame, textvariable=self.var_h_debut, width=6, bg='#313244',
                 fg='#cdd6f4', insertbackground='white').grid(row=0, column=1, padx=2)
        tk.Label(cfg_frame, text="à", bg='#181825', fg='#cdd6f4').grid(row=0, column=2)
        tk.Entry(cfg_frame, textvariable=self.var_h_fin, width=6, bg='#313244',
                 fg='#cdd6f4', insertbackground='white').grid(row=0, column=3, padx=2)
        tk.Label(cfg_frame, text="Durée RDV (min) :", bg='#181825', fg='#cdd6f4').grid(row=1, column=0, padx=5, pady=3, sticky='w')
        self.var_duree = tk.StringVar(value=str(self.bot_cfg['duree_rdv_minutes']))
        tk.Entry(cfg_frame, textvariable=self.var_duree, width=6, bg='#313244',
                 fg='#cdd6f4', insertbackground='white').grid(row=1, column=1, padx=2)
        tk.Button(cfg_frame, text="Appliquer", command=self._appliquer_config,
                  bg='#fab387', fg='#1e1e2e', relief='flat', padx=6).grid(row=1, column=3, padx=5)

    def _log(self, msg):
        log(msg)
        self.root.after(0, lambda: self._append_log(msg))

    def _append_log(self, msg):
        self.log_text.config(state='normal')
        self.log_text.insert('end', msg + '\n')
        self.log_text.see('end')
        self.log_text.config(state='disabled')

    def _charger_log(self):
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, encoding='utf-8') as f:
                lines = f.readlines()[-100:]
            for line in lines:
                self._append_log(line.strip())

    def _effacer_log(self):
        if os.path.exists(LOG_PATH):
            open(LOG_PATH, 'w').close()
        self.log_text.config(state='normal')
        self.log_text.delete('1.0', 'end')
        self.log_text.config(state='disabled')

    def _demarrer(self):
        if self.actif:
            self.actif = False
            if self.timer:
                self.root.after_cancel(self.timer)
            self.btn_start.config(text="Démarrer le bot", bg='#a6e3a1')
            self.lbl_status.config(text="● Inactif", fg='#f38ba8')
            self._log("Bot arrêté.")
        else:
            self.actif = True
            self.btn_start.config(text="Arrêter le bot", bg='#f38ba8')
            self.lbl_status.config(text="● Actif", fg='#a6e3a1')
            self._log("Bot démarré — scan toutes les 5 minutes.")
            self._boucle_scan()

    def _boucle_scan(self):
        if not self.actif:
            return
        self._scan_inbox()
        self.timer = self.root.after(5 * 60 * 1000, self._boucle_scan)

    def _scan_manuel(self):
        self._log("Scan manuel lancé...")
        threading.Thread(target=self._scan_inbox, daemon=True).start()

    def _scan_inbox(self):
        cfg = self.mail_cfg
        if not cfg.get('email') or not cfg.get('password'):
            self._log("ERREUR : Configurez d'abord la boîte mail (plugin Boîte Mail).")
            return
        try:
            self._log(f"Connexion à {cfg['imap_server']}...")
            conn = imaplib.IMAP4_SSL(cfg['imap_server'], cfg.get('imap_port', 993))
            conn.login(cfg['email'], cfg['password'])
            conn.select('INBOX')
            _, data = conn.search(None, 'UNSEEN')
            ids = data[0].split()
            self._log(f"{len(ids)} message(s) non lus.")
            for mid in ids:
                _, mdata = conn.fetch(mid, '(RFC822)')
                if not mdata or not mdata[0] or not mdata[0][1]:
                    continue
                msg = email.message_from_bytes(mdata[0][1])
                sujet = decode_str(msg.get('Subject', ''))
                expediteur = decode_str(msg.get('From', ''))
                corps = get_body_text(msg)
                texte_complet = f"{sujet} {corps}"
                if detecter_rdv(texte_complet):
                    self._log(f"Demande RDV détectée de {expediteur} : {sujet}")
                    self._traiter_demande(cfg, expediteur, sujet, corps)
            conn.logout()
            self._log("Scan terminé.")
        except Exception as e:
            self._log(f"ERREUR scan : {e}")

    def _traiter_demande(self, mail_cfg, expediteur, sujet, corps):
        dates_mentionnees = extraire_dates(f"{sujet} {corps}")
        duree = int(self.var_duree.get() or 60)
        h_debut = self.var_h_debut.get() or '09:00'
        h_fin = self.var_h_fin.get() or '17:00'
        # Chercher créneaux pour les 7 prochains jours ouvrables
        creneaux_trouves = []
        jours_ouvrables = self.bot_cfg.get('jours_ouvrables', [0, 1, 2, 3, 4])
        for delta in range(1, 15):
            d = date.today() + timedelta(days=delta)
            if d.weekday() in jours_ouvrables:
                creneaux = creneaux_disponibles(d, duree, h_debut, h_fin)
                if creneaux:
                    creneaux_trouves.append((d, creneaux))
                if len(creneaux_trouves) >= 3:
                    break

        # Extraire email destinataire
        email_dest = re.search(r'[\w.+-]+@[\w-]+\.[a-z]{2,}', expediteur)
        email_dest = email_dest.group(0) if email_dest else expediteur

        if creneaux_trouves:
            d, cs = creneaux_trouves[0]
            heure = cs[0]
            date_str = d.strftime('%Y-%m-%d')
            date_lisible = d.strftime('%d/%m/%Y')
            # Réserver dans le calendrier
            reserver_creneau(date_str, heure,
                             f"RDV avec {email_dest}",
                             email_dest)
            # Construire options
            options = "\n".join([
                f"  • {dd.strftime('%d/%m/%Y')} à {css[0]}" for dd, css in creneaux_trouves[:3]
            ])
            msg_template = self.bot_cfg['message_confirmation']
            corps_reponse = msg_template.format(date=date_lisible, heure=heure) + f"\n\nAutres créneaux disponibles :\n{options}"
            action = 'Confirmé'
            tag = 'confirme'
        else:
            corps_reponse = self.bot_cfg['message_indisponible']
            action = 'Indispo'
            tag = 'indispo'
            date_str, heure = '', ''

        # Envoyer réponse
        try:
            reponse = MIMEText(corps_reponse, 'plain', 'utf-8')
            reponse['From'] = mail_cfg['email']
            reponse['To'] = email_dest
            reponse['Subject'] = f"Re: {sujet}"
            with smtplib.SMTP(mail_cfg['smtp_server'], mail_cfg.get('smtp_port', 587)) as s:
                s.starttls()
                s.login(mail_cfg['email'], mail_cfg['password'])
                s.sendmail(mail_cfg['email'], email_dest, reponse.as_string())
            self._log(f"Réponse envoyée à {email_dest} — {action}")
        except Exception as e:
            self._log(f"ERREUR envoi réponse : {e}")

        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        self.root.after(0, lambda: self.tree_det.insert(
            '', 0, values=(now, email_dest[:20], sujet[:20], action), tags=(tag,)))

    def _appliquer_config(self):
        self.bot_cfg['heures_debut'] = self.var_h_debut.get()
        self.bot_cfg['heures_fin'] = self.var_h_fin.get()
        try:
            self.bot_cfg['duree_rdv_minutes'] = int(self.var_duree.get())
        except ValueError:
            pass
        save_bot_config(self.bot_cfg)
        self._log("Configuration mise à jour.")

    def _parametres(self):
        _BotParamDialog(self.root, self.bot_cfg, self._on_param_save)

    def _on_param_save(self, cfg):
        self.bot_cfg = cfg
        save_bot_config(cfg)
        self._log("Paramètres avancés sauvegardés.")


class _BotParamDialog:
    def __init__(self, parent, cfg, callback):
        self.callback = callback
        self.cfg = cfg.copy()
        self.top = tk.Toplevel(parent)
        self.top.title("Paramètres avancés Bot RDV")
        self.top.configure(bg='#1e1e2e')
        self.top.grab_set()
        self.vars = {}
        tk.Label(self.top, text="Message de confirmation :", bg='#1e1e2e',
                 fg='#cdd6f4').pack(anchor='w', padx=10, pady=(10, 2))
        self.txt_confirm = tk.Text(self.top, bg='#313244', fg='#cdd6f4', height=6,
                                    width=55, insertbackground='white', relief='flat')
        self.txt_confirm.pack(padx=10)
        self.txt_confirm.insert('end', cfg.get('message_confirmation', ''))
        tk.Label(self.top, text="Message indisponible :", bg='#1e1e2e',
                 fg='#cdd6f4').pack(anchor='w', padx=10, pady=(10, 2))
        self.txt_indispo = tk.Text(self.top, bg='#313244', fg='#cdd6f4', height=5,
                                    width=55, insertbackground='white', relief='flat')
        self.txt_indispo.pack(padx=10)
        self.txt_indispo.insert('end', cfg.get('message_indisponible', ''))
        tk.Label(self.top, text="(Variables disponibles : {date}, {heure})",
                 bg='#1e1e2e', fg='#6c7086', font=('Helvetica', 8)).pack(anchor='w', padx=10)
        tk.Button(self.top, text="Sauvegarder", command=self._save,
                  bg='#a6e3a1', fg='#1e1e2e', relief='flat', padx=12, pady=5).pack(pady=12)

    def _save(self):
        self.cfg['message_confirmation'] = self.txt_confirm.get('1.0', 'end').strip()
        self.cfg['message_indisponible'] = self.txt_indispo.get('1.0', 'end').strip()
        self.callback(self.cfg)
        self.top.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    BotRDVApp(root)
    root.mainloop()
