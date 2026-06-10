"""
Medjat Plugin Launcher
Lance les plugins individuellement ou via ce menu central
"""
import tkinter as tk
from tkinter import ttk
import subprocess
import sys
import os

PLUGINS = [
    {
        'nom': 'Gestion de Projet',
        'fichier': 'plugins/gestion_projet.py',
        'couleur': '#89b4fa',
        'description': 'Projets, tâches, deadlines, équipe',
        'icone': '📋',
    },
    {
        'nom': 'Support & Ticketing',
        'fichier': 'plugins/support.py',
        'couleur': '#f38ba8',
        'description': 'Tickets clients, priorités, historique',
        'icone': '🎫',
    },
    {
        'nom': 'Calendrier',
        'fichier': 'plugins/calendrier.py',
        'couleur': '#cba6f7',
        'description': 'Événements, rendez-vous, vue mensuelle',
        'icone': '📅',
    },
    {
        'nom': 'Boîte Mail',
        'fichier': 'plugins/boite_mail.py',
        'couleur': '#fab387',
        'description': 'IMAP/SMTP, lecture et envoi de mails',
        'icone': '✉️',
    },
    {
        'nom': 'Bot RDV',
        'fichier': 'plugins/bot_rdv.py',
        'couleur': '#a6e3a1',
        'description': 'Détecte les demandes de RDV et répond auto',
        'icone': '🤖',
    },
]


class Launcher:
    def __init__(self, root):
        self.root = root
        self.root.title("Medjat — Plugins PME")
        self.root.geometry("560x520")
        self.root.configure(bg='#1e1e2e')
        self.root.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg='#cdd6f4', height=70)
        header.pack(fill='x')
        header.pack_propagate(False)
        tk.Label(header, text="Medjat", font=('Helvetica', 24, 'bold'),
                 bg='#cdd6f4', fg='#1e1e2e').pack(side='left', padx=20, pady=10)
        tk.Label(header, text="Suite PME", font=('Helvetica', 12),
                 bg='#cdd6f4', fg='#45475a').pack(side='left', pady=18)

        tk.Label(self.root, text="Sélectionne un plugin à lancer",
                 font=('Helvetica', 11), bg='#1e1e2e', fg='#6c7086').pack(pady=(15, 8))

        # Grille de plugins
        grid = tk.Frame(self.root, bg='#1e1e2e')
        grid.pack(fill='both', expand=True, padx=20)

        for i, plugin in enumerate(PLUGINS):
            row, col = divmod(i, 2)
            card = tk.Frame(grid, bg='#313244', relief='flat', cursor='hand2',
                            bd=0, padx=15, pady=12)
            card.grid(row=row, column=col, padx=8, pady=8, sticky='ew')
            grid.columnconfigure(col, weight=1)

            top_row = tk.Frame(card, bg='#313244')
            top_row.pack(fill='x')
            dot = tk.Label(top_row, text="●", font=('Helvetica', 14),
                           bg='#313244', fg=plugin['couleur'])
            dot.pack(side='left', padx=(0, 8))
            nom_lbl = tk.Label(top_row, text=plugin['nom'],
                                font=('Helvetica', 11, 'bold'),
                                bg='#313244', fg='#cdd6f4')
            nom_lbl.pack(side='left')

            desc_lbl = tk.Label(card, text=plugin['description'],
                                 font=('Helvetica', 9), bg='#313244', fg='#6c7086',
                                 anchor='w')
            desc_lbl.pack(fill='x', pady=(4, 0))

            btn = tk.Button(card, text="Lancer →",
                            command=lambda p=plugin: self._lancer(p),
                            bg=plugin['couleur'], fg='#1e1e2e',
                            relief='flat', padx=10, pady=3,
                            font=('Helvetica', 9, 'bold'), cursor='hand2')
            btn.pack(anchor='e', pady=(8, 0))

            for w in [card, top_row, dot, nom_lbl, desc_lbl]:
                w.bind('<Double-1>', lambda e, p=plugin: self._lancer(p))

        # Footer
        footer = tk.Frame(self.root, bg='#181825', height=35)
        footer.pack(fill='x', side='bottom')
        footer.pack_propagate(False)
        tk.Label(footer, text="Données stockées dans medjat-plugins/data/",
                 font=('Helvetica', 8), bg='#181825', fg='#45475a').pack(pady=8)

    def _lancer(self, plugin):
        script = os.path.join(os.path.dirname(__file__), plugin['fichier'])
        subprocess.Popen([sys.executable, script])


if __name__ == '__main__':
    root = tk.Tk()
    Launcher(root)
    root.mainloop()
