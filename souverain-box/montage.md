# Montage — créer le sens unique

## Étape 1 — assembler
1. Insère un module SFP dans chaque convertisseur.
2. Branche ta **Dell (côté sensible)** au port RJ45 du **convertisseur A**.
3. Branche le **réseau / le PC de collecte** au port RJ45 du **convertisseur B**.

## Étape 2 — brancher la fibre en SENS UNIQUE
Un câble fibre duplex a **deux brins** : un TX (émission) et un RX (réception).

- Branche **seulement** le brin qui va du **TX du convertisseur A** vers le **RX du convertisseur B**.
- Laisse l'autre brin (B → A) **débranché**.

Résultat : A peut envoyer de la lumière vers B. B n'a aucun moyen physique de renvoyer
de la lumière vers A. **C'est le sens unique.**

```
Convertisseur A (Dell)          Convertisseur B (réseau)
      TX  ───────── fibre ─────────►  RX
      RX  ◄···· (débranché) ····       TX
```

## Étape 3 — le problème du lien qui ne « monte » pas
Beaucoup de convertisseurs refusent d'activer le port s'ils ne voient pas de lumière sur
leur RX. Le convertisseur A ne reçoit rien, donc son port RJ45 risque de rester éteint et
la Dell ne pourra pas envoyer.

Solutions possibles (à tester) :
1. Choisir des convertisseurs « simples » qui activent le port TX même sans RX.
2. Alimenter le RX du convertisseur A avec un **signal leurre** : brancher un 3e module
   SFP qui émet dans le vide juste pour garder le port « vivant ».
3. Se rabattre sur l'astuce 100 Mbit (fils RX coupés) qui, elle, n'a pas ce problème.

C'est le vrai défi du montage maison. Note ici ce qui marche avec ton matériel.

## Étape 4 — tester
Voir `logiciel/procedure-test.md`.
