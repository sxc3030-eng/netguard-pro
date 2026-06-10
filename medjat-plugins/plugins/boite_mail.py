"""
Medjat Plugin — Boite Mail
Lecture IMAP, envoi SMTP, interface 3 panneaux
Config sauvegardee dans data/mail_config.json
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import os
import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
import threading

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'mail_config.json')

DEFAULT_CONFIG = {
    'imap_server': '',
    'imap_port': 993,
    'smtp_server': '',
    'smtp_port': 587,
    'email': '',
    'password': '',
    'nom': '',
}


def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG.copy()


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
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
            result.append(part)
    return ''.join(result)


def get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get('Content-Disposition', ''))
            if ct == 'text/plain' and 'attachment' not in cd:
                return part.get_payload(decode=True).decode(
                    part.get_content_charset() or 'utf-8', errors='replace')
    else:
        return msg.get_payload(decode=True).decode(
            msg.get_content_charset() or 'utf-8', errors='replace')
    return ''


class BoiteMailApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Medjat — Boîte Mail")
        self.root.geometry("1150x700")
        self.root.configure(bg='#1e1e2e')
        self.config = load_config()
        self.messages = []
        self.imap_conn = None
        self._build_ui()
        if self.config['email']:
            self._connecter()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', background='#313244', foreground='#cdd6f4',
                        fieldbackground='#313244', rowheight=26)
        style.configure('Treeview.Heading', background='#45475a', foreground='#cdd6f4')

        # Header
        header = tk.Frame(self.root, bg='#fab387', height=50)
        header.pack(fill='x')
        tk.Label(header, text="  Boîte Mail", font=('Helvetica', 16, 'bold'),
                 bg='#fab387', fg='#1e1e2e').pack(side='left', pady=10)
        self.lbl_status = tk.Label(header, text="Non connecté", font=('Helvetica', 10),
                                    bg='#fab387', fg='#1e1e2e')
        self.lbl_status.pack(side='right', padx=15)

        # Toolbar
        toolbar = tk.Frame(self.root, bg='#181825', pady=5)
        toolbar.pack(fill='x')
        for text, cmd, color in [
            ("Actualiser", self._actualiser, '#89b4fa'),
            ("Nouveau mail", self._composer, '#a6e3a1'),
            ("Répondre", self._repondre, '#fab387'),
            ("Paramètres", self._parametres, '#6c7086'),
        ]:
            tk.Button(toolbar, text=text, command=cmd, bg=color, fg='#1e1e2e',
                      relief='flat', padx=10, pady=4, font=('Helvetica', 9, 'bold'),
                      cursor='hand2').pack(side='left', padx=4)

        # 3 panneaux
        pane = tk.PanedWindow(self.root, orient='horizontal', bg='#1e1e2e', sashwidth=4)
        pane.pack(fill='both', expand=True, padx=8, pady=8)

        # Panneau 1: dossiers
        left = tk.Frame(pane, bg='#181825', width=140)
        pane.add(left, minsize=120)
        tk.Label(left, text="Dossiers", font=('Helvetica', 11, 'bold'),
                 bg='#181825', fg='#cdd6f4').pack(anchor='w', padx=8, pady=8)
        self.dossiers_list = tk.Listbox(left, bg='#313244', fg='#cdd6f4',
                                         selectbackground='#89b4fa', selectforeground='#1e1e2e',
                                         relief='flat', font=('Helvetica', 10), activestyle='none')
        self.dossiers_list.pack(fill='both', expand=True, padx=5, pady=5)
        self.dossiers_list.bind('<<ListboxSelect>>', self._on_dossier_select)
        for d in ['INBOX', 'Envoyés', 'Brouillons', 'Corbeille']:
            self.dossiers_list.insert('end', d)
        self.dossiers_list.selection_set(0)

        # Panneau 2: liste messages
        mid = tk.Frame(pane, bg='#1e1e2e')
        pane.add(mid, minsize=380)
        cols = ('de', 'sujet', 'date')
        self.tree_msgs = ttk.Treeview(mid, columns=cols, show='headings', height=28)
        for c, w, h in [('de', 160, 'De'), ('sujet', 220, 'Sujet'), ('date', 120, 'Date')]:
            self.tree_msgs.heading(c, text=h)
            self.tree_msgs.column(c, width=w)
        self.tree_msgs.pack(fill='both', expand=True)
        self.tree_msgs.bind('<<TreeviewSelect>>', self._on_msg_select)
        self.tree_msgs.tag_configure('non_lu', font=('Helvetica', 9, 'bold'), foreground='#f9e2af')

        # Panneau 3: corps du message
        right = tk.Frame(pane, bg='#181825')
        pane.add(right, minsize=320)
        self.lbl_de = tk.Label(right, text="", font=('Helvetica', 10, 'bold'),
                                bg='#181825', fg='#89b4fa', anchor='w')
        self.lbl_de.pack(fill='x', padx=10, pady=(8, 0))
        self.lbl_sujet = tk.Label(right, text="", font=('Helvetica', 11, 'bold'),
                                   bg='#181825', fg='#cdd6f4', anchor='w', wraplength=300)
        self.lbl_sujet.pack(fill='x', padx=10)
        self.lbl_date = tk.Label(right, text="", font=('Helvetica', 9),
                                  bg='#181825', fg='#6c7086', anchor='w')
        self.lbl_date.pack(fill='x', padx=10, pady=(0, 5))
        ttk.Separator(right, orient='horizontal').pack(fill='x', padx=10)
        self.corps_text = scrolledtext.ScrolledText(
            right, bg='#313244', fg='#cdd6f4', wrap='word',
            font=('Helvetica', 10), relief='flat', state='disabled')
        self.corps_text.pack(fill='both', expand=True, padx=10, pady=8)

    def _connecter(self):
        cfg = self.config
        if not cfg['email'] or not cfg['password']:
            return
        def connect():
            try:
                self.imap_conn = imaplib.IMAP4_SSL(cfg['imap_server'], cfg['imap_port'])
                self.imap_conn.login(cfg['email'], cfg['password'])
                self.root.after(0, lambda: self.lbl_status.config(
                    text=f"Connecté : {cfg['email']}"))
                self.root.after(0, self._charger_inbox)
            except Exception as e:
                self.root.after(0, lambda: self.lbl_status.config(text=f"Erreur : {e}"))
        threading.Thread(target=connect, daemon=True).start()

    def _charger_inbox(self, dossier='INBOX'):
        if not self.imap_conn:
            return
        def fetch():
            try:
                self.imap_conn.select(dossier)
                _, data = self.imap_conn.search(None, 'ALL')
                ids = data[0].split()[-50:]  # 50 derniers
                msgs = []
                for mid in reversed(ids):
                    _, mdata = self.imap_conn.fetch(mid, '(RFC822.SIZE ENVELOPE FLAGS)')
                    if mdata and mdata[0]:
                        raw = mdata[0][1].decode('utf-8', errors='replace')
                        msgs.append({'id': mid, 'raw_envelope': raw, 'flags': raw})
                # Fetch headers seulement pour performance
                result = []
                for mid in reversed(ids[-30:]):
                    _, mdata = self.imap_conn.fetch(mid, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
                    if mdata and mdata[0] and mdata[0][1]:
                        msg = email.message_from_bytes(mdata[0][1])
                        result.append({
                            'id': mid,
                            'de': decode_str(msg.get('From', '')),
                            'sujet': decode_str(msg.get('Subject', '(sans sujet)')),
                            'date': msg.get('Date', ''),
                        })
                self.messages = result
                self.root.after(0, self._afficher_messages)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Erreur IMAP", str(e)))
        threading.Thread(target=fetch, daemon=True).start()

    def _afficher_messages(self):
        self.tree_msgs.delete(*self.tree_msgs.get_children())
        for m in self.messages:
            de = m['de'][:30] if len(m['de']) > 30 else m['de']
            self.tree_msgs.insert('', 'end', iid=m['id'],
                                   values=(de, m['sujet'], m['date'][:16]))

    def _on_dossier_select(self, _):
        sel = self.dossiers_list.curselection()
        if not sel:
            return
        dossier = self.dossiers_list.get(sel[0])
        map_d = {'INBOX': 'INBOX', 'Envoyés': 'Sent', 'Brouillons': 'Drafts', 'Corbeille': 'Trash'}
        self._charger_inbox(map_d.get(dossier, 'INBOX'))

    def _on_msg_select(self, _):
        sel = self.tree_msgs.selection()
        if not sel:
            return
        msg_id = sel[0]
        def fetch_body():
            try:
                _, mdata = self.imap_conn.fetch(msg_id, '(RFC822)')
                if mdata and mdata[0] and mdata[0][1]:
                    msg = email.message_from_bytes(mdata[0][1])
                    de = decode_str(msg.get('From', ''))
                    sujet = decode_str(msg.get('Subject', ''))
                    date_str = msg.get('Date', '')
                    corps = get_body(msg)
                    self.root.after(0, lambda: self._afficher_corps(de, sujet, date_str, corps))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Erreur", str(e)))
        threading.Thread(target=fetch_body, daemon=True).start()

    def _afficher_corps(self, de, sujet, date_str, corps):
        self.lbl_de.config(text=f"De : {de}")
        self.lbl_sujet.config(text=sujet)
        self.lbl_date.config(text=date_str)
        self.corps_text.config(state='normal')
        self.corps_text.delete('1.0', 'end')
        self.corps_text.insert('end', corps)
        self.corps_text.config(state='disabled')

    def _actualiser(self):
        self._charger_inbox()

    def _composer(self, destinataire='', sujet='', corps_initial=''):
        ComposeDialog(self.root, self.config, destinataire, sujet, corps_initial)

    def _repondre(self):
        sel = self.tree_msgs.selection()
        if not sel:
            return
        for m in self.messages:
            if m['id'] == sel[0]:
                self._composer(m['de'], f"Re: {m['sujet']}", "\n\n--- Message original ---\n")
                break

    def _parametres(self):
        ParametresDialog(self.root, self.config, self._on_config_save)

    def _on_config_save(self, new_cfg):
        self.config = new_cfg
        save_config(new_cfg)
        self.imap_conn = None
        self._connecter()


class ComposeDialog:
    def __init__(self, parent, config, dest='', sujet='', corps=''):
        self.config = config
        self.top = tk.Toplevel(parent)
        self.top.title("Composer un message")
        self.top.configure(bg='#1e1e2e')
        self.top.geometry("600x500")
        self.vars = {}
        for label, key, val in [("À :", 'dest', dest), ("Sujet :", 'sujet', sujet)]:
            f = tk.Frame(self.top, bg='#1e1e2e')
            f.pack(fill='x', padx=10, pady=3)
            tk.Label(f, text=label, bg='#1e1e2e', fg='#cdd6f4', width=8,
                     anchor='e').pack(side='left')
            v = tk.StringVar(value=val)
            tk.Entry(f, textvariable=v, bg='#313244', fg='#cdd6f4',
                     insertbackground='white').pack(side='left', fill='x', expand=True)
            self.vars[key] = v
        tk.Label(self.top, text="Message :", bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=10)
        self.corps = scrolledtext.ScrolledText(self.top, bg='#313244', fg='#cdd6f4',
                                               wrap='word', font=('Helvetica', 10), relief='flat')
        self.corps.pack(fill='both', expand=True, padx=10, pady=5)
        self.corps.insert('end', corps)
        btn_f = tk.Frame(self.top, bg='#1e1e2e')
        btn_f.pack(fill='x', padx=10, pady=8)
        tk.Button(btn_f, text="Envoyer", command=self._envoyer,
                  bg='#a6e3a1', fg='#1e1e2e', relief='flat', padx=12, pady=5,
                  font=('Helvetica', 10, 'bold')).pack(side='left', padx=4)
        tk.Button(btn_f, text="Annuler", command=self.top.destroy,
                  bg='#6c7086', fg='#cdd6f4', relief='flat', padx=12).pack(side='left')

    def _envoyer(self):
        dest = self.vars['dest'].get().strip()
        sujet = self.vars['sujet'].get().strip()
        corps = self.corps.get('1.0', 'end').strip()
        if not dest:
            messagebox.showwarning("Requis", "Destinataire manquant.")
            return
        cfg = self.config
        try:
            msg = MIMEMultipart()
            msg['From'] = f"{cfg.get('nom', '')} <{cfg['email']}>"
            msg['To'] = dest
            msg['Subject'] = sujet
            msg.attach(MIMEText(corps, 'plain', 'utf-8'))
            with smtplib.SMTP(cfg['smtp_server'], cfg['smtp_port']) as s:
                s.starttls()
                s.login(cfg['email'], cfg['password'])
                s.sendmail(cfg['email'], dest, msg.as_string())
            messagebox.showinfo("Envoyé", "Message envoyé avec succès.")
            self.top.destroy()
        except Exception as e:
            messagebox.showerror("Erreur envoi", str(e))


class ParametresDialog:
    def __init__(self, parent, config, callback):
        self.callback = callback
        self.top = tk.Toplevel(parent)
        self.top.title("Paramètres mail")
        self.top.configure(bg='#1e1e2e')
        self.top.grab_set()
        self.vars = {}
        fields = [
            ("Nom affiché", 'nom'), ("Email", 'email'), ("Mot de passe", 'password'),
            ("Serveur IMAP", 'imap_server'), ("Port IMAP", 'imap_port'),
            ("Serveur SMTP", 'smtp_server'), ("Port SMTP", 'smtp_port'),
        ]
        for label, key in fields:
            tk.Label(self.top, text=label, bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=15, pady=(8, 0))
            v = tk.StringVar(value=str(config.get(key, '')))
            show = '*' if key == 'password' else ''
            tk.Entry(self.top, textvariable=v, bg='#313244', fg='#cdd6f4',
                     insertbackground='white', show=show, width=38).pack(padx=15)
            self.vars[key] = v
        tk.Button(self.top, text="Sauvegarder", command=self._save,
                  bg='#fab387', fg='#1e1e2e', relief='flat', padx=12, pady=5).pack(pady=15)

    def _save(self):
        new_cfg = {k: v.get() for k, v in self.vars.items()}
        try:
            new_cfg['imap_port'] = int(new_cfg['imap_port'])
            new_cfg['smtp_port'] = int(new_cfg['smtp_port'])
        except ValueError:
            messagebox.showwarning("Erreur", "Les ports doivent être des nombres.")
            return
        self.callback(new_cfg)
        self.top.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    BoiteMailApp(root)
    root.mainloop()
