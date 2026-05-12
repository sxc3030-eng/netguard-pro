# AI Builder Academy 🎓

Une formation **bilingue FR/EN**, **vocale et visuelle**, niveau **intermédiaire à expert**, pour devenir un AI builder de haut niveau.

- **11 modules · 39 leçons · ~14 heures de contenu**
- Lecture vocale intégrée (Web Speech API — gratuit, mobile-compatible)
- Lab pratique RAG + Agents (10 exercices)
- **Projet capstone 10h** : agent IA production-grade bout-en-bout
- Quiz à la fin de chaque leçon
- Progression sauvée dans le navigateur (localStorage)
- 100% statique, déployable n'importe où

## Démarrage rapide

```bash
npm install
npm run dev
# → http://localhost:3000
```

Pour accéder depuis ton téléphone sur le même Wi-Fi :

```bash
npm run dev:wifi
# → http://192.168.x.x:3000 (ton IP locale)
```

Build de production :

```bash
npm run build
npm start
```

## Curriculum

1. **Fondations LLM** — anatomie d'un transformer, tokens, pricing, choisir son modèle
2. **Prompt engineering avancé** — system prompts, XML, few-shot, CoT, extended thinking
3. **Tool use & function calling** — design de tools, parallel tools, retry, circuit breaker
4. **RAG avancé** — chunking, hybrid search (BM25 + vector), reranking, eval RAGAS
5. **Agents** — architecture, ReAct, Plan-and-Execute, Reflexion, subagents
6. **MCP (Model Context Protocol)** — comprendre + construire ton propre serveur
7. **Multi-agents & orchestration** — router, supervisor, pipeline, swarm
8. **Production** — eval golden sets, observability, prompt injection, guardrails
9. **Business & scale** — coût, latence, déploiement, pricing, business case
10. **Lab pratique RAG + Agents** — 10 exercices ciblés sur les gaps les plus courants
11. **Capstone — agent IA production-grade** — projet guidé 10h, bout-en-bout

## Format de chaque leçon

- Objectifs (4-5)
- 🎙️ Script vocal jouable (Web Speech API)
- 🖼️ Visuels narrés + ASCII art
- 📚 Cours markdown détaillé
- 🛠️ Exercice pipeline pratique
- ✅ Quiz 3 QCM avec explications
- 📖 Ressources (papers, docs)

## Stack

- Next.js 14 (App Router, statique)
- React 18 + TypeScript strict
- Tailwind CSS
- react-markdown + rehype-highlight
- Web Speech API (synthèse vocale, browser-native)

## Déploiement

Site 100% statique : déployable sur Vercel, Netlify, Cloudflare Pages, GitHub Pages, ou n'importe quel CDN.

### Vercel (recommandé)

1. Va sur [vercel.com/new](https://vercel.com/new)
2. Importe ce repo
3. Deploy (build et déploiement automatiques)

## Licence

Curriculum open. Adapte, fork, redistribue.
