"""
Medjat Plugin — Gestion de Projet
Projets, taches, statuts, deadlines
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'gestion_projet.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS projets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom TEXT NOT NULL,
                description TEXT,
                date_debut TEXT,
                date_fin TEXT,
                statut TEXT DEFAULT 'En cours'
            );
            CREATE TABLE IF NOT EXISTS taches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                projet_id INTEGER,
                titre TEXT NOT NULL,
                assignee TEXT,
                priorite TEXT DEFAULT 'Normale',
                statut TEXT DEFAULT 'À faire',
                deadline TEXT,
                FOREIGN KEY (projet_id) REFERENCES projets(id) ON DELETE CASCADE
            );
        """)


class GestionProjetApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Medjat — Gestion de Projet")
        self.root.geometry("1000x600")
        self.root.configure(bg='#1e1e2e')
        init_db()
        self.projet_selectionne = None
        self._build_ui()
        self._load_projets()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#1e1e2e')
        style.configure('TLabel', background='#1e1e2e', foreground='#cdd6f4')
        style.configure('Treeview', background='#313244', foreground='#cdd6f4',
                        fieldbackground='#313244', rowheight=28)
        style.configure('Treeview.Heading', background='#45475a', foreground='#cdd6f4')

        # Header
        header = tk.Frame(self.root, bg='#89b4fa', height=50)
        header.pack(fill='x')
        tk.Label(header, text="  Gestion de Projet", font=('Helvetica', 16, 'bold'),
                 bg='#89b4fa', fg='#1e1e2e').pack(side='left', pady=10)

        # Main panes
        pane = tk.PanedWindow(self.root, orient='horizontal', bg='#1e1e2e', sashwidth=4)
        pane.pack(fill='both', expand=True, padx=10, pady=10)

        # Left: projets
        left = tk.Frame(pane, bg='#1e1e2e', width=280)
        pane.add(left, minsize=220)

        tk.Label(left, text="Projets", font=('Helvetica', 12, 'bold'),
                 bg='#1e1e2e', fg='#89b4fa').pack(anchor='w', padx=5, pady=(5, 2))

        self.tree_projets = ttk.Treeview(left, columns=('nom', 'statut'), show='headings', height=20)
        self.tree_projets.heading('nom', text='Nom')
        self.tree_projets.heading('statut', text='Statut')
        self.tree_projets.column('nom', width=160)
        self.tree_projets.column('statut', width=90)
        self.tree_projets.pack(fill='both', expand=True, padx=5)
        self.tree_projets.bind('<<TreeviewSelect>>', self._on_projet_select)

        btn_frame_p = tk.Frame(left, bg='#1e1e2e')
        btn_frame_p.pack(fill='x', padx=5, pady=5)
        self._btn(btn_frame_p, "+ Projet", self._ajouter_projet).pack(side='left', padx=2)
        self._btn(btn_frame_p, "Suppr.", self._suppr_projet, color='#f38ba8').pack(side='left', padx=2)

        # Right: tâches
        right = tk.Frame(pane, bg='#1e1e2e')
        pane.add(right, minsize=500)

        self.lbl_projet = tk.Label(right, text="Sélectionne un projet",
                                   font=('Helvetica', 12, 'bold'), bg='#1e1e2e', fg='#a6e3a1')
        self.lbl_projet.pack(anchor='w', padx=5, pady=(5, 2))

        cols = ('titre', 'assignee', 'priorite', 'statut', 'deadline')
        self.tree_taches = ttk.Treeview(right, columns=cols, show='headings', height=20)
        headers = {'titre': 'Tâche', 'assignee': 'Assigné', 'priorite': 'Priorité',
                   'statut': 'Statut', 'deadline': 'Deadline'}
        widths = {'titre': 200, 'assignee': 100, 'priorite': 80, 'statut': 90, 'deadline': 100}
        for c in cols:
            self.tree_taches.heading(c, text=headers[c])
            self.tree_taches.column(c, width=widths[c])
        self.tree_taches.pack(fill='both', expand=True, padx=5)

        btn_frame_t = tk.Frame(right, bg='#1e1e2e')
        btn_frame_t.pack(fill='x', padx=5, pady=5)
        self._btn(btn_frame_t, "+ Tâche", self._ajouter_tache).pack(side='left', padx=2)
        self._btn(btn_frame_t, "Changer statut", self._changer_statut, color='#fab387').pack(side='left', padx=2)
        self._btn(btn_frame_t, "Suppr.", self._suppr_tache, color='#f38ba8').pack(side='left', padx=2)

    def _btn(self, parent, text, cmd, color='#89b4fa'):
        return tk.Button(parent, text=text, command=cmd, bg=color, fg='#1e1e2e',
                         relief='flat', padx=8, pady=4, cursor='hand2',
                         font=('Helvetica', 9, 'bold'))

    def _load_projets(self):
        self.tree_projets.delete(*self.tree_projets.get_children())
        with get_db() as conn:
            for row in conn.execute("SELECT id, nom, statut FROM projets ORDER BY id DESC"):
                self.tree_projets.insert('', 'end', iid=row['id'],
                                         values=(row['nom'], row['statut']))

    def _load_taches(self, projet_id):
        self.tree_taches.delete(*self.tree_taches.get_children())
        with get_db() as conn:
            for row in conn.execute(
                "SELECT id, titre, assignee, priorite, statut, deadline FROM taches WHERE projet_id=?",
                    (projet_id,)):
                self.tree_taches.insert('', 'end', iid=row['id'],
                                         values=(row['titre'], row['assignee'] or '',
                                                 row['priorite'], row['statut'], row['deadline'] or ''))

    def _on_projet_select(self, _):
        sel = self.tree_projets.selection()
        if not sel:
            return
        self.projet_selectionne = int(sel[0])
        nom = self.tree_projets.item(sel[0], 'values')[0]
        self.lbl_projet.config(text=f"Tâches — {nom}")
        self._load_taches(self.projet_selectionne)

    def _ajouter_projet(self):
        dlg = _ProjetDialog(self.root)
        self.root.wait_window(dlg.top)
        if dlg.result:
            with get_db() as conn:
                conn.execute("INSERT INTO projets (nom, description, date_debut, date_fin, statut) VALUES (?,?,?,?,?)",
                             dlg.result)
            self._load_projets()

    def _suppr_projet(self):
        sel = self.tree_projets.selection()
        if not sel:
            return
        if messagebox.askyesno("Supprimer", "Supprimer ce projet et ses tâches ?"):
            with get_db() as conn:
                conn.execute("DELETE FROM projets WHERE id=?", (int(sel[0]),))
            self.projet_selectionne = None
            self.lbl_projet.config(text="Sélectionne un projet")
            self.tree_taches.delete(*self.tree_taches.get_children())
            self._load_projets()

    def _ajouter_tache(self):
        if not self.projet_selectionne:
            messagebox.showinfo("Info", "Sélectionne un projet d'abord.")
            return
        dlg = _TacheDialog(self.root)
        self.root.wait_window(dlg.top)
        if dlg.result:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO taches (projet_id, titre, assignee, priorite, statut, deadline) VALUES (?,?,?,?,?,?)",
                    (self.projet_selectionne, *dlg.result))
            self._load_taches(self.projet_selectionne)

    def _changer_statut(self):
        sel = self.tree_taches.selection()
        if not sel:
            return
        statuts = ['À faire', 'En cours', 'Terminé']
        actuel = self.tree_taches.item(sel[0], 'values')[3]
        idx = statuts.index(actuel) if actuel in statuts else 0
        nouveau = statuts[(idx + 1) % len(statuts)]
        with get_db() as conn:
            conn.execute("UPDATE taches SET statut=? WHERE id=?", (nouveau, int(sel[0])))
        self._load_taches(self.projet_selectionne)

    def _suppr_tache(self):
        sel = self.tree_taches.selection()
        if not sel:
            return
        with get_db() as conn:
            conn.execute("DELETE FROM taches WHERE id=?", (int(sel[0]),))
        self._load_taches(self.projet_selectionne)


class _ProjetDialog:
    def __init__(self, parent):
        self.result = None
        self.top = tk.Toplevel(parent)
        self.top.title("Nouveau projet")
        self.top.configure(bg='#1e1e2e')
        self.top.grab_set()
        fields = [("Nom*", "nom"), ("Description", "desc"),
                  ("Date début (AAAA-MM-JJ)", "debut"), ("Date fin (AAAA-MM-JJ)", "fin")]
        self.vars = {}
        for label, key in fields:
            tk.Label(self.top, text=label, bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=10, pady=(8, 0))
            v = tk.StringVar()
            tk.Entry(self.top, textvariable=v, bg='#313244', fg='#cdd6f4', insertbackground='white',
                     width=35).pack(padx=10)
            self.vars[key] = v
        statut_var = tk.StringVar(value='En cours')
        tk.Label(self.top, text="Statut", bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=10, pady=(8, 0))
        ttk.Combobox(self.top, textvariable=statut_var,
                     values=['En cours', 'En attente', 'Terminé', 'Annulé'],
                     width=32).pack(padx=10)
        self.vars['statut'] = statut_var
        tk.Button(self.top, text="Créer", command=self._ok, bg='#89b4fa', fg='#1e1e2e',
                  relief='flat', padx=12, pady=5).pack(pady=15)

    def _ok(self):
        nom = self.vars['nom'].get().strip()
        if not nom:
            messagebox.showwarning("Requis", "Le nom est obligatoire.")
            return
        self.result = (nom, self.vars['desc'].get(), self.vars['debut'].get(),
                       self.vars['fin'].get(), self.vars['statut'].get())
        self.top.destroy()


class _TacheDialog:
    def __init__(self, parent):
        self.result = None
        self.top = tk.Toplevel(parent)
        self.top.title("Nouvelle tâche")
        self.top.configure(bg='#1e1e2e')
        self.top.grab_set()
        fields = [("Titre*", "titre"), ("Assigné à", "assignee"), ("Deadline (AAAA-MM-JJ)", "deadline")]
        self.vars = {}
        for label, key in fields:
            tk.Label(self.top, text=label, bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=10, pady=(8, 0))
            v = tk.StringVar()
            tk.Entry(self.top, textvariable=v, bg='#313244', fg='#cdd6f4',
                     insertbackground='white', width=35).pack(padx=10)
            self.vars[key] = v
        for label, key, vals in [("Priorité", "priorite", ['Faible', 'Normale', 'Haute', 'Urgente']),
                                   ("Statut", "statut", ['À faire', 'En cours', 'Terminé'])]:
            tk.Label(self.top, text=label, bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=10, pady=(8, 0))
            v = tk.StringVar(value=vals[1])
            ttk.Combobox(self.top, textvariable=v, values=vals, width=32).pack(padx=10)
            self.vars[key] = v
        tk.Button(self.top, text="Ajouter", command=self._ok, bg='#a6e3a1', fg='#1e1e2e',
                  relief='flat', padx=12, pady=5).pack(pady=15)

    def _ok(self):
        titre = self.vars['titre'].get().strip()
        if not titre:
            messagebox.showwarning("Requis", "Le titre est obligatoire.")
            return
        self.result = (titre, self.vars['assignee'].get(), self.vars['priorite'].get(),
                       self.vars['statut'].get(), self.vars['deadline'].get())
        self.top.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    GestionProjetApp(root)
    root.mainloop()
