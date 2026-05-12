# CLAUDE.md — Project rules

## ⛔ Règle CRITIQUE : indépendance des repos

**JAMAIS** créer un nouveau projet à l'intérieur d'un autre repo existant.

### Pourquoi cette règle

Chaque projet doit vivre dans **son propre repo Git** sur GitHub. Mélanger plusieurs projets dans un même repo :
- Casse la séparation des responsabilités
- Pollue l'historique git du repo principal
- Rend le déploiement (Vercel, etc.) confus
- Empêche un partage propre par projet

### Application concrète

Si l'utilisateur demande de créer un nouveau projet (ex: "fais-moi une formation", "crée un dashboard", "ajoute un outil"), je dois :

1. **Demander d'abord** : "C'est un nouveau projet indépendant ? On crée un repo séparé ?"
2. Si OUI → guider la création d'un nouveau repo GitHub avant de commencer le code
3. Si NON (sous-fonctionnalité du projet courant) → travailler dans le repo courant uniquement

### Erreur historique à ne pas répéter

⚠️ Le 11/12 mai 2026 : j'ai créé `AI Builder Academy` (formation) dans le repo `netguard-pro` (projet NetGuard Pro, sans rapport). C'était une erreur d'architecture qui a généré confusion et migration douloureuse. **Ne jamais reproduire ce schéma.**

## Repos de l'utilisateur (sxc3030-eng)

- `netguard-pro` : projet NetGuard Pro (firewall/sécurité)
- `ai-builder-academy` : formation IA (à terme, en cours de migration)
- `genia.social` : plateforme principale, contient un dossier `builder/`
- Autres : `mamy`, `pechepro`, `FORGE`

**Chaque repo = un projet indépendant. Pas de mélange.**

## Contexte AI Builder Academy

- 11 modules, 39 leçons, Next.js 14 + TypeScript + Tailwind + Web Speech API
- Stack : statique, déployable n'importe où
- Branche de travail historique : `claude/ai-builder-training-course-MY1Ub`
- Dossier actuel : `ai-builder-academy/` (à migrer vers son propre repo)

## Style de communication

- Réponses courtes et directes en français
- Pas d'emojis sauf si l'utilisateur en met
- Confirmer avant actions destructives (delete, force push, rename)
