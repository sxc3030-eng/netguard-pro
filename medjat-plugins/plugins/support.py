"""
Medjat Plugin — Support & Ticketing
Tickets clients, priorites, statuts, suivi
"""
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'support.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titre TEXT NOT NULL,
                description TEXT,
                client TEXT,
                assignee TEXT,
                categorie TEXT DEFAULT 'Général',
                priorite TEXT DEFAULT 'Normale',
                statut TEXT DEFAULT 'Ouvert',
                date_creation TEXT,
                date_maj TEXT
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER,
                auteur TEXT,
                contenu TEXT,
                date TEXT,
                FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
            );
        """)


COULEURS_PRIORITE = {'Faible': '#a6e3a1', 'Normale': '#89b4fa',
                     'Haute': '#fab387', 'Urgente': '#f38ba8'}
COULEURS_STATUT = {'Ouvert': '#f38ba8', 'En cours': '#fab387',
                   'Résolu': '#a6e3a1', 'Fermé': '#6c7086'}


class SupportApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Medjat — Support & Ticketing")
        self.root.geometry("1100x650")
        self.root.configure(bg='#1e1e2e')
        init_db()
        self.ticket_sel = None
        self._build_ui()
        self._load_tickets()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#1e1e2e')
        style.configure('Treeview', background='#313244', foreground='#cdd6f4',
                        fieldbackground='#313244', rowheight=28)
        style.configure('Treeview.Heading', background='#45475a', foreground='#cdd6f4')

        # Header
        header = tk.Frame(self.root, bg='#f38ba8', height=50)
        header.pack(fill='x')
        tk.Label(header, text="  Support & Ticketing", font=('Helvetica', 16, 'bold'),
                 bg='#f38ba8', fg='#1e1e2e').pack(side='left', pady=10)
        self.lbl_stats = tk.Label(header, text="", font=('Helvetica', 10),
                                   bg='#f38ba8', fg='#1e1e2e')
        self.lbl_stats.pack(side='right', padx=15)

        # Filtres
        filt = tk.Frame(self.root, bg='#181825', pady=5)
        filt.pack(fill='x', padx=10)
        tk.Label(filt, text="Filtre statut:", bg='#181825', fg='#cdd6f4').pack(side='left', padx=5)
        self.var_filtre = tk.StringVar(value='Tous')
        ttk.Combobox(filt, textvariable=self.var_filtre, width=12,
                     values=['Tous', 'Ouvert', 'En cours', 'Résolu', 'Fermé']).pack(side='left')
        tk.Label(filt, text="Priorité:", bg='#181825', fg='#cdd6f4').pack(side='left', padx=(15, 5))
        self.var_prio = tk.StringVar(value='Toutes')
        ttk.Combobox(filt, textvariable=self.var_prio, width=10,
                     values=['Toutes', 'Faible', 'Normale', 'Haute', 'Urgente']).pack(side='left')
        tk.Button(filt, text="Filtrer", command=self._load_tickets,
                  bg='#89b4fa', fg='#1e1e2e', relief='flat', padx=8).pack(side='left', padx=10)
        tk.Button(filt, text="Rechercher:", bg='#181825', fg='#cdd6f4',
                  relief='flat').pack(side='left')
        self.var_recherche = tk.StringVar()
        tk.Entry(filt, textvariable=self.var_recherche, bg='#313244', fg='#cdd6f4',
                 insertbackground='white', width=20).pack(side='left')

        # Split
        pane = tk.PanedWindow(self.root, orient='horizontal', bg='#1e1e2e', sashwidth=4)
        pane.pack(fill='both', expand=True, padx=10, pady=5)

        # Liste tickets
        left = tk.Frame(pane, bg='#1e1e2e')
        pane.add(left, minsize=550)

        cols = ('id', 'titre', 'client', 'priorite', 'statut', 'assignee', 'date')
        self.tree = ttk.Treeview(left, columns=cols, show='headings', height=22)
        headers = {'id': '#', 'titre': 'Titre', 'client': 'Client', 'priorite': 'Priorité',
                   'statut': 'Statut', 'assignee': 'Assigné', 'date': 'Créé le'}
        widths = {'id': 40, 'titre': 180, 'client': 100, 'priorite': 70,
                  'statut': 80, 'assignee': 90, 'date': 100}
        for c in cols:
            self.tree.heading(c, text=headers[c],
                              command=lambda col=c: self._sort(col))
            self.tree.column(c, width=widths[c])
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)

        btn_frame = tk.Frame(left, bg='#1e1e2e')
        btn_frame.pack(fill='x', pady=5)
        for text, cmd, color in [("+ Ticket", self._nouveau_ticket, '#89b4fa'),
                                   ("Changer statut", self._changer_statut, '#fab387'),
                                   ("Supprimer", self._suppr_ticket, '#f38ba8')]:
            tk.Button(btn_frame, text=text, command=cmd, bg=color, fg='#1e1e2e',
                      relief='flat', padx=8, pady=4, cursor='hand2',
                      font=('Helvetica', 9, 'bold')).pack(side='left', padx=3)

        # Détail ticket
        right = tk.Frame(pane, bg='#181825')
        pane.add(right, minsize=300)
        tk.Label(right, text="Détail du ticket", font=('Helvetica', 12, 'bold'),
                 bg='#181825', fg='#cdd6f4').pack(anchor='w', padx=10, pady=8)
        self.detail_text = tk.Text(right, bg='#313244', fg='#cdd6f4', wrap='word',
                                    height=10, font=('Helvetica', 10), state='disabled',
                                    relief='flat')
        self.detail_text.pack(fill='x', padx=10)

        tk.Label(right, text="Notes / Historique", font=('Helvetica', 10, 'bold'),
                 bg='#181825', fg='#a6e3a1').pack(anchor='w', padx=10, pady=(10, 2))
        self.notes_tree = ttk.Treeview(right, columns=('auteur', 'date', 'note'),
                                        show='headings', height=8)
        for c, w in [('auteur', 80), ('date', 100), ('note', 200)]:
            self.notes_tree.heading(c, text=c.capitalize())
            self.notes_tree.column(c, width=w)
        self.notes_tree.pack(fill='x', padx=10)

        note_frame = tk.Frame(right, bg='#181825')
        note_frame.pack(fill='x', padx=10, pady=5)
        self.var_auteur = tk.StringVar(value='Agent')
        tk.Entry(note_frame, textvariable=self.var_auteur, bg='#313244', fg='#cdd6f4',
                 insertbackground='white', width=10).pack(side='left', padx=(0, 5))
        self.var_note = tk.StringVar()
        tk.Entry(note_frame, textvariable=self.var_note, bg='#313244', fg='#cdd6f4',
                 insertbackground='white', width=25).pack(side='left')
        tk.Button(note_frame, text="Ajouter note", command=self._ajouter_note,
                  bg='#a6e3a1', fg='#1e1e2e', relief='flat', padx=6).pack(side='left', padx=5)

    def _load_tickets(self):
        self.tree.delete(*self.tree.get_children())
        query = "SELECT id, titre, client, priorite, statut, assignee, date_creation FROM tickets WHERE 1=1"
        params = []
        if self.var_filtre.get() != 'Tous':
            query += " AND statut=?"
            params.append(self.var_filtre.get())
        if self.var_prio.get() != 'Toutes':
            query += " AND priorite=?"
            params.append(self.var_prio.get())
        rech = self.var_recherche.get().strip()
        if rech:
            query += " AND (titre LIKE ? OR client LIKE ?)"
            params += [f'%{rech}%', f'%{rech}%']
        query += " ORDER BY id DESC"
        with get_db() as conn:
            rows = conn.execute(query, params).fetchall()
        ouverts = sum(1 for r in rows if r['statut'] == 'Ouvert')
        self.lbl_stats.config(text=f"{len(rows)} tickets  •  {ouverts} ouverts")
        for row in rows:
            self.tree.insert('', 'end', iid=row['id'],
                             values=(row['id'], row['titre'], row['client'] or '',
                                     row['priorite'], row['statut'],
                                     row['assignee'] or '', row['date_creation'] or ''))

    def _on_select(self, _):
        sel = self.tree.selection()
        if not sel:
            return
        self.ticket_sel = int(sel[0])
        with get_db() as conn:
            t = conn.execute("SELECT * FROM tickets WHERE id=?", (self.ticket_sel,)).fetchone()
            notes = conn.execute(
                "SELECT auteur, date, contenu FROM notes WHERE ticket_id=? ORDER BY id",
                (self.ticket_sel,)).fetchall()
        self.detail_text.config(state='normal')
        self.detail_text.delete('1.0', 'end')
        self.detail_text.insert('end',
            f"#{t['id']} — {t['titre']}\n"
            f"Client : {t['client'] or '-'}  |  Assigné : {t['assignee'] or '-'}\n"
            f"Priorité : {t['priorite']}  |  Statut : {t['statut']}\n"
            f"Catégorie : {t['categorie']}\n\n{t['description'] or ''}")
        self.detail_text.config(state='disabled')
        self.notes_tree.delete(*self.notes_tree.get_children())
        for n in notes:
            self.notes_tree.insert('', 'end', values=(n['auteur'], n['date'], n['contenu']))

    def _nouveau_ticket(self):
        dlg = _TicketDialog(self.root)
        self.root.wait_window(dlg.top)
        if dlg.result:
            now = datetime.now().strftime('%Y-%m-%d %H:%M')
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO tickets (titre, description, client, assignee, categorie, priorite, statut, date_creation, date_maj) VALUES (?,?,?,?,?,?,?,?,?)",
                    (*dlg.result, now, now))
            self._load_tickets()

    def _changer_statut(self):
        sel = self.tree.selection()
        if not sel:
            return
        statuts = ['Ouvert', 'En cours', 'Résolu', 'Fermé']
        actuel = self.tree.item(sel[0], 'values')[4]
        idx = statuts.index(actuel) if actuel in statuts else 0
        nouveau = statuts[(idx + 1) % len(statuts)]
        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        with get_db() as conn:
            conn.execute("UPDATE tickets SET statut=?, date_maj=? WHERE id=?",
                         (nouveau, now, int(sel[0])))
        self._load_tickets()

    def _suppr_ticket(self):
        sel = self.tree.selection()
        if not sel:
            return
        if messagebox.askyesno("Supprimer", "Supprimer ce ticket ?"):
            with get_db() as conn:
                conn.execute("DELETE FROM tickets WHERE id=?", (int(sel[0]),))
            self.ticket_sel = None
            self._load_tickets()

    def _ajouter_note(self):
        if not self.ticket_sel:
            return
        contenu = self.var_note.get().strip()
        if not contenu:
            return
        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        with get_db() as conn:
            conn.execute("INSERT INTO notes (ticket_id, auteur, contenu, date) VALUES (?,?,?,?)",
                         (self.ticket_sel, self.var_auteur.get(), contenu, now))
        self.var_note.set('')
        self._on_select(None)

    def _sort(self, col):
        pass  # tri simple possible en extension


class _TicketDialog:
    def __init__(self, parent):
        self.result = None
        self.top = tk.Toplevel(parent)
        self.top.title("Nouveau ticket")
        self.top.configure(bg='#1e1e2e')
        self.top.grab_set()
        self.vars = {}
        for label, key in [("Titre*", "titre"), ("Client", "client"),
                            ("Assigné à", "assignee"), ("Description", "desc")]:
            tk.Label(self.top, text=label, bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=10, pady=(8, 0))
            if key == 'desc':
                w = tk.Text(self.top, bg='#313244', fg='#cdd6f4', height=4, width=38,
                            insertbackground='white')
                w.pack(padx=10)
            else:
                v = tk.StringVar()
                tk.Entry(self.top, textvariable=v, bg='#313244', fg='#cdd6f4',
                         insertbackground='white', width=38).pack(padx=10)
                self.vars[key] = v
        self.desc_widget = self.top.winfo_children()[-1]
        for label, key, vals, default in [
            ("Catégorie", "cat", ['Général', 'Facturation', 'Technique', 'Livraison', 'Autre'], 'Général'),
            ("Priorité", "priorite", ['Faible', 'Normale', 'Haute', 'Urgente'], 'Normale'),
            ("Statut", "statut", ['Ouvert', 'En cours'], 'Ouvert'),
        ]:
            tk.Label(self.top, text=label, bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=10, pady=(8, 0))
            v = tk.StringVar(value=default)
            ttk.Combobox(self.top, textvariable=v, values=vals, width=35).pack(padx=10)
            self.vars[key] = v
        tk.Button(self.top, text="Créer ticket", command=self._ok, bg='#f38ba8', fg='#1e1e2e',
                  relief='flat', padx=12, pady=5).pack(pady=15)

    def _ok(self):
        titre = self.vars['titre'].get().strip()
        if not titre:
            messagebox.showwarning("Requis", "Le titre est obligatoire.")
            return
        desc = self.desc_widget.get('1.0', 'end').strip()
        self.result = (titre, desc, self.vars['client'].get(), self.vars['assignee'].get(),
                       self.vars['cat'].get(), self.vars['priorite'].get(), self.vars['statut'].get())
        self.top.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    SupportApp(root)
    root.mainloop()
