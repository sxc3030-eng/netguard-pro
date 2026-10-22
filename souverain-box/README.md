# SouverainBox — diode de données (sens unique)

Objectif : laisser sortir les données d'un côté sensible vers le réseau, **sans jamais**
laisser revenir quoi que ce soit. Le sens unique est garanti **physiquement** par la lumière
(fibre optique), pas par du logiciel.

```
  Côté sensible                 Côté réseau
  (ta Dell)                     (Internet / collecte)
     │                               │
  [Convertisseur fibre] ──lumière──> [Convertisseur fibre]
     │   (un seul brin branché : TX -> RX)   │
     └── ne peut qu'ÉMETTRE          └── ne peut que RECEVOIR
```

## Les 3 niveaux possibles
| Niveau | Coût | Garantie | Pour quoi |
|---|---|---|---|
| Câble 100 Mbit, fils RX coupés | ~10 $ | faible | expérience rapide |
| **Fibre maison (ce projet)** | ~130–180 $ CA | bonne (lumière = sens unique) | tester, démontrer |
| Produit certifié (Owl, Waterfall) | 2 000–10 000 $ US | certifiée | vendre à Hydro, villes, hôpitaux |

## ⚠️ Avertissement honnête
Ce montage maison **n'est pas une sécurité certifiée**. Il sert à tester et démontrer le
principe. Ne pas l'utiliser en production critique sans validation par un expert.

## Fichiers
- `liste-achat.md` — quoi acheter et où
- `montage.md` — comment brancher et créer le sens unique
- `logiciel/` — programmes de test (émetteur / récepteur) et procédure de test
