# AI Builder Academy

Une formation **bilingue FR/EN**, **vocale et visuelle**, niveau **intermédiaire à expert**, pour devenir un AI builder de haut niveau.

- 9 modules · 22 leçons · ~6 heures de contenu
- Lecture vocale intégrée (Web Speech API — gratuit, mobile-compatible)
- Exercices pipeline et mini-projets RAG / agents
- Quiz à la fin de chaque leçon
- Progression sauvée dans le navigateur (localStorage)
- 100% statique, déployable n'importe où

## Démarrage rapide

```bash
cd ai-builder-academy
npm install
npm run dev
# → http://localhost:3000
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

## Structure

```
ai-builder-academy/
├── app/                    # Pages Next.js
│   ├── page.tsx            # Home
│   ├── modules/            # Liste des modules
│   ├── lessons/[slug]/     # Page leçon
│   ├── roadmap/            # Roadmap 10 semaines
│   └── about/              # À propos
├── components/             # UI components
│   ├── VocalPlayer.tsx     # Lecture audio Web Speech
│   ├── Quiz.tsx            # Quiz interactif
│   ├── LessonNav.tsx       # Sidebar navigation
│   └── ...
├── lib/
│   ├── curriculum.ts       # Index des modules
│   ├── types.ts            # Types Lesson/Module/Quiz
│   ├── progress.ts         # Hook localStorage
│   └── lessons/            # Contenu des 9 modules
└── ...
```

## Étendre la formation

Ajoute un module en créant `lib/lessons/moduleX-xxx.ts` puis enregistre-le dans `lib/curriculum.ts`. Le router dynamique `/lessons/[slug]` génère automatiquement les pages.

Chaque leçon respecte le type `Lesson` (cf. `lib/types.ts`) :

```ts
{
  slug, moduleSlug, index, title, subtitle, level, durationMin,
  objectives: string[],
  vocalScript: string,        // narré via Web Speech API
  visuals: VisualSlide[],     // descriptions + optional ASCII
  content: string,            // markdown
  practice: string,           // exercice pratique markdown
  quiz: Quiz[],               // 3+ QCM
  resources: { label, href }[]
}
```

## Déploiement

Site 100% statique : déployable sur Vercel, Netlify, Cloudflare Pages, GitHub Pages, ou n'importe quel CDN.

```bash
npm run build
# le dossier .next/ peut être servi par n'importe quel host Next.js
# ou bien faire un export statique avec next export si besoin
```

## Roadmap recommandée

Voir [`/roadmap`](/roadmap) une fois lancé : un parcours en 10 semaines pour passer de "je connais les bases" à "j'ai un produit IA en production".

## Licence

Curriculum open. Adapte, fork, redistribue.
