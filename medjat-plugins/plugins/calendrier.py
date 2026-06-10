"""
Medjat Plugin — Calendrier
Vue mensuelle, evenements, rappels
"""
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import os
import calendar
from datetime import datetime, date

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'calendrier.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS evenements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titre TEXT NOT NULL,
                description TEXT,
                date_debut TEXT NOT NULL,
                date_fin TEXT,
                heure_debut TEXT,
                heure_fin TEXT,
                lieu TEXT,
                type TEXT DEFAULT 'Réunion',
                participant TEXT,
                rappel INTEGER DEFAULT 0
            );
        """)


TYPES_COLOR = {
    'Réunion': '#89b4fa',
    'RDV Client': '#a6e3a1',
    'Tâche': '#fab387',
    'Personnel': '#cba6f7',
    'Congé': '#f38ba8',
}

JOURS = ['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim']
MOIS = ['Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
        'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre']


class CalendrierApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Medjat — Calendrier")
        self.root.geometry("1050x680")
        self.root.configure(bg='#1e1e2e')
        init_db()
        today = date.today()
        self.annee = today.year
        self.mois = today.month
        self.today = today
        self.date_sel = None
        self._build_ui()
        self._draw_calendrier()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', background='#313244', foreground='#cdd6f4',
                        fieldbackground='#313244', rowheight=26)
        style.configure('Treeview.Heading', background='#45475a', foreground='#cdd6f4')

        # Header
        header = tk.Frame(self.root, bg='#cba6f7', height=50)
        header.pack(fill='x')
        tk.Label(header, text="  Calendrier", font=('Helvetica', 16, 'bold'),
                 bg='#cba6f7', fg='#1e1e2e').pack(side='left', pady=10)

        # Navigation
        nav = tk.Frame(self.root, bg='#181825', pady=6)
        nav.pack(fill='x')
        tk.Button(nav, text="◀◀", command=self._annee_prec, bg='#181825', fg='#cdd6f4',
                  relief='flat', font=('Helvetica', 11)).pack(side='left', padx=5)
        tk.Button(nav, text="◀", command=self._mois_prec, bg='#181825', fg='#cdd6f4',
                  relief='flat', font=('Helvetica', 11)).pack(side='left', padx=2)
        self.lbl_mois = tk.Label(nav, text="", font=('Helvetica', 14, 'bold'),
                                  bg='#181825', fg='#cdd6f4', width=20)
        self.lbl_mois.pack(side='left', padx=15)
        tk.Button(nav, text="▶", command=self._mois_suiv, bg='#181825', fg='#cdd6f4',
                  relief='flat', font=('Helvetica', 11)).pack(side='left', padx=2)
        tk.Button(nav, text="▶▶", command=self._annee_suiv, bg='#181825', fg='#cdd6f4',
                  relief='flat', font=('Helvetica', 11)).pack(side='left', padx=5)
        tk.Button(nav, text="Aujourd'hui", command=self._aller_aujd,
                  bg='#cba6f7', fg='#1e1e2e', relief='flat', padx=8).pack(side='left', padx=15)
        tk.Button(nav, text="+ Événement", command=self._nouvel_evenement,
                  bg='#a6e3a1', fg='#1e1e2e', relief='flat', padx=8,
                  font=('Helvetica', 10, 'bold')).pack(side='right', padx=10)

        # Split
        pane = tk.PanedWindow(self.root, orient='horizontal', bg='#1e1e2e', sashwidth=4)
        pane.pack(fill='both', expand=True, padx=10, pady=8)

        # Grille calendrier
        self.cal_frame = tk.Frame(pane, bg='#1e1e2e')
        pane.add(self.cal_frame, minsize=560)

        # Entêtes jours
        for i, j in enumerate(JOURS):
            color = '#f38ba8' if i >= 5 else '#89b4fa'
            tk.Label(self.cal_frame, text=j, font=('Helvetica', 10, 'bold'),
                     bg='#313244', fg=color, width=9, relief='flat',
                     pady=5).grid(row=0, column=i, padx=1, pady=1, sticky='ew')

        self.cells = {}
        for r in range(6):
            for c in range(7):
                cell = tk.Frame(self.cal_frame, bg='#313244', width=90, height=80,
                                cursor='hand2', relief='flat', bd=1)
                cell.grid(row=r + 1, column=c, padx=1, pady=1, sticky='nsew')
                cell.grid_propagate(False)
                self.cells[(r, c)] = cell
        for c in range(7):
            self.cal_frame.columnconfigure(c, weight=1)

        # Panel droit: événements du jour
        right = tk.Frame(pane, bg='#181825')
        pane.add(right, minsize=280)
        self.lbl_jour = tk.Label(right, text="Événements", font=('Helvetica', 12, 'bold'),
                                  bg='#181825', fg='#cdd6f4')
        self.lbl_jour.pack(anchor='w', padx=10, pady=8)

        cols = ('heure', 'titre', 'type', 'lieu')
        self.tree_events = ttk.Treeview(right, columns=cols, show='headings', height=20)
        for c, w, h in [('heure', 60, 'Heure'), ('titre', 130, 'Titre'),
                         ('type', 80, 'Type'), ('lieu', 80, 'Lieu')]:
            self.tree_events.heading(c, text=h)
            self.tree_events.column(c, width=w)
        self.tree_events.pack(fill='both', expand=True, padx=10)
        self.tree_events.bind('<Double-1>', self._modifier_evenement)

        btn_f = tk.Frame(right, bg='#181825')
        btn_f.pack(fill='x', padx=10, pady=5)
        tk.Button(btn_f, text="+ Ici", command=self._nouvel_evenement_jour,
                  bg='#a6e3a1', fg='#1e1e2e', relief='flat', padx=8).pack(side='left', padx=2)
        tk.Button(btn_f, text="Supprimer", command=self._suppr_evenement,
                  bg='#f38ba8', fg='#1e1e2e', relief='flat', padx=8).pack(side='left', padx=2)

    def _draw_calendrier(self):
        self.lbl_mois.config(text=f"{MOIS[self.mois - 1]}  {self.annee}")
        # Vider cellules
        for cell in self.cells.values():
            for w in cell.winfo_children():
                w.destroy()
            cell.config(bg='#313244', relief='flat')
            cell.unbind('<Button-1>')

        cal = calendar.monthcalendar(self.annee, self.mois)
        # Charger événements du mois
        mois_str = f"{self.annee}-{self.mois:02d}"
        with get_db() as conn:
            evts = conn.execute(
                "SELECT id, titre, date_debut, heure_debut, type FROM evenements WHERE date_debut LIKE ?",
                (f"{mois_str}%",)).fetchall()
        evts_par_jour = {}
        for e in evts:
            try:
                j = int(e['date_debut'].split('-')[2])
                evts_par_jour.setdefault(j, []).append(e)
            except Exception:
                pass

        for r, semaine in enumerate(cal):
            for c, jour in enumerate(semaine):
                if jour == 0:
                    continue
                cell = self.cells[(r, c)]
                d = date(self.annee, self.mois, jour)
                is_today = (d == self.today)
                is_weekend = c >= 5
                bg = '#45475a' if is_today else ('#2a2a3e' if is_weekend else '#313244')
                cell.config(bg=bg)

                # Numéro du jour
                fg = '#f9e2af' if is_today else ('#f38ba8' if is_weekend else '#cdd6f4')
                lbl = tk.Label(cell, text=str(jour), font=('Helvetica', 9, 'bold'),
                               bg=bg, fg=fg)
                lbl.place(x=4, y=2)

                # Pastilles événements
                evs = evts_par_jour.get(jour, [])
                for i, ev in enumerate(evs[:3]):
                    color = TYPES_COLOR.get(ev['type'], '#89b4fa')
                    dot = tk.Label(cell, text=f"• {ev['titre'][:12]}",
                                   font=('Helvetica', 7), bg=bg, fg=color)
                    dot.place(x=2, y=18 + i * 16)

                # Click
                def on_click(e, d=d, j=jour):
                    self._select_jour(d, j)
                for w in [cell, lbl] + cell.winfo_children():
                    w.bind('<Button-1>', on_click)

        # Charger le jour sélectionné si valide
        if self.date_sel and self.date_sel.year == self.annee and self.date_sel.month == self.mois:
            self._load_events_jour(self.date_sel)

    def _select_jour(self, d, jour):
        self.date_sel = d
        self.lbl_jour.config(text=f"Événements — {d.strftime('%d %B %Y')}")
        self._load_events_jour(d)

    def _load_events_jour(self, d):
        self.tree_events.delete(*self.tree_events.get_children())
        date_str = d.strftime('%Y-%m-%d')
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id, titre, heure_debut, heure_fin, type, lieu FROM evenements WHERE date_debut=? ORDER BY heure_debut",
                (date_str,)).fetchall()
        for row in rows:
            heure = f"{row['heure_debut'] or ''}"
            if row['heure_fin']:
                heure += f"-{row['heure_fin']}"
            self.tree_events.insert('', 'end', iid=row['id'],
                                     values=(heure, row['titre'], row['type'], row['lieu'] or ''))

    def _mois_prec(self):
        if self.mois == 1:
            self.mois, self.annee = 12, self.annee - 1
        else:
            self.mois -= 1
        self._draw_calendrier()

    def _mois_suiv(self):
        if self.mois == 12:
            self.mois, self.annee = 1, self.annee + 1
        else:
            self.mois += 1
        self._draw_calendrier()

    def _annee_prec(self):
        self.annee -= 1
        self._draw_calendrier()

    def _annee_suiv(self):
        self.annee += 1
        self._draw_calendrier()

    def _aller_aujd(self):
        today = date.today()
        self.annee, self.mois = today.year, today.month
        self._draw_calendrier()

    def _nouvel_evenement(self, date_str=None):
        dlg = _EvenementDialog(self.root, date_str)
        self.root.wait_window(dlg.top)
        if dlg.result:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO evenements (titre, description, date_debut, date_fin, heure_debut, heure_fin, lieu, type, participant) VALUES (?,?,?,?,?,?,?,?,?)",
                    dlg.result)
            self._draw_calendrier()

    def _nouvel_evenement_jour(self):
        if not self.date_sel:
            messagebox.showinfo("Info", "Clique sur un jour d'abord.")
            return
        self._nouvel_evenement(self.date_sel.strftime('%Y-%m-%d'))

    def _modifier_evenement(self, _):
        sel = self.tree_events.selection()
        if not sel:
            return
        with get_db() as conn:
            ev = conn.execute("SELECT * FROM evenements WHERE id=?", (int(sel[0]),)).fetchone()
        if not ev:
            return
        dlg = _EvenementDialog(self.root, ev['date_debut'], ev=dict(ev))
        self.root.wait_window(dlg.top)
        if dlg.result:
            with get_db() as conn:
                conn.execute(
                    "UPDATE evenements SET titre=?,description=?,date_debut=?,date_fin=?,heure_debut=?,heure_fin=?,lieu=?,type=?,participant=? WHERE id=?",
                    (*dlg.result, int(sel[0])))
            self._draw_calendrier()

    def _suppr_evenement(self):
        sel = self.tree_events.selection()
        if not sel:
            return
        if messagebox.askyesno("Supprimer", "Supprimer cet événement ?"):
            with get_db() as conn:
                conn.execute("DELETE FROM evenements WHERE id=?", (int(sel[0]),))
            self._draw_calendrier()
            if self.date_sel:
                self._load_events_jour(self.date_sel)


class _EvenementDialog:
    def __init__(self, parent, date_str=None, ev=None):
        self.result = None
        self.top = tk.Toplevel(parent)
        self.top.title("Événement")
        self.top.configure(bg='#1e1e2e')
        self.top.grab_set()
        self.vars = {}
        today = date.today().strftime('%Y-%m-%d')
        defaults = {
            'titre': ev['titre'] if ev else '',
            'desc': ev['description'] if ev else '',
            'date_debut': ev['date_debut'] if ev else (date_str or today),
            'date_fin': ev['date_fin'] if ev else '',
            'heure_debut': ev['heure_debut'] if ev else '09:00',
            'heure_fin': ev['heure_fin'] if ev else '10:00',
            'lieu': ev['lieu'] if ev else '',
            'participant': ev['participant'] if ev else '',
        }
        for label, key in [("Titre*", 'titre'), ("Description", 'desc'),
                            ("Date début* (AAAA-MM-JJ)", 'date_debut'),
                            ("Date fin (AAAA-MM-JJ)", 'date_fin'),
                            ("Heure début (HH:MM)", 'heure_debut'),
                            ("Heure fin (HH:MM)", 'heure_fin'),
                            ("Lieu", 'lieu'), ("Participants", 'participant')]:
            tk.Label(self.top, text=label, bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=10, pady=(6, 0))
            v = tk.StringVar(value=defaults[key])
            tk.Entry(self.top, textvariable=v, bg='#313244', fg='#cdd6f4',
                     insertbackground='white', width=36).pack(padx=10)
            self.vars[key] = v
        tk.Label(self.top, text="Type", bg='#1e1e2e', fg='#cdd6f4').pack(anchor='w', padx=10, pady=(6, 0))
        type_var = tk.StringVar(value=ev['type'] if ev else 'Réunion')
        ttk.Combobox(self.top, textvariable=type_var,
                     values=list(TYPES_COLOR.keys()), width=34).pack(padx=10)
        self.vars['type'] = type_var
        label_btn = "Modifier" if ev else "Créer"
        tk.Button(self.top, text=label_btn, command=self._ok, bg='#cba6f7', fg='#1e1e2e',
                  relief='flat', padx=12, pady=5).pack(pady=12)

    def _ok(self):
        titre = self.vars['titre'].get().strip()
        date_debut = self.vars['date_debut'].get().strip()
        if not titre or not date_debut:
            messagebox.showwarning("Requis", "Titre et date de début sont obligatoires.")
            return
        self.result = (titre, self.vars['desc'].get(), date_debut,
                       self.vars['date_fin'].get(), self.vars['heure_debut'].get(),
                       self.vars['heure_fin'].get(), self.vars['lieu'].get(),
                       self.vars['type'].get(), self.vars['participant'].get())
        self.top.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    CalendrierApp(root)
    root.mainloop()
