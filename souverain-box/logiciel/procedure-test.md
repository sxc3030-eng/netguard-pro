# Procédure de test — SouverainBox

Le but : prouver que les données passent **du côté sensible vers le réseau**, mais
**jamais dans l'autre sens**.

## Test A — sans matériel (sur une seule machine, pour valider le logiciel)
Ouvre deux terminaux sur ta Dell.

Terminal 1 (récepteur) :
```
python3 recepteur.py 9000
```
Terminal 2 (émetteur) :
```
python3 emetteur.py 127.0.0.1 9000
```
✅ Attendu : le récepteur affiche les messages. Ça confirme que le logiciel marche.

## Test B — avec deux machines sur le réseau (avant le diode)
- Machine 1 (sensible) lance `emetteur.py <ip_machine_2> 9000`
- Machine 2 (collecte) lance `recepteur.py 9000`

✅ Attendu : la machine 2 reçoit les messages de la machine 1.

## Test C — le vrai test du sens unique (avec le diode fibre)
Branche le diode fibre selon `../montage.md` (un seul brin).

1. **Sens autorisé** : `emetteur.py` sur la Dell → `recepteur.py` sur la collecte.
   ✅ Attendu : les messages arrivent.

2. **Sens interdit (le test qui compte)** : inverse les rôles.
   Lance `emetteur.py` sur la machine de **collecte**, vers la **Dell**, et
   `recepteur.py` sur la Dell.
   ✅ Attendu : **AUCUN message n'arrive.** Le diode bloque physiquement le retour.

3. **Test ping** : depuis la collecte, `ping <ip_dell>`.
   ✅ Attendu : 100 % de perte. Le ping a besoin d'un aller-retour, donc il échoue.
   C'est la preuve que rien ne revient.

## Noter les résultats
| Test | Résultat attendu | Observé |
|---|---|---|
| A (local) | messages reçus | |
| B (réseau) | messages reçus | |
| C.1 (sens autorisé) | messages reçus | |
| C.2 (sens interdit) | rien reçu | |
| C.3 (ping retour) | 100 % perte | |
