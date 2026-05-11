import type { Module } from "../types";

export const module2: Module = {
  slug: "prompt-engineering",
  index: 2,
  title: "Prompt Engineering avancé",
  tagline: "Le craft qui sépare les amateurs des pros",
  description:
    "System prompts, XML structuring, few-shot, chain-of-thought, extended thinking, prompt caching avancé. Les techniques qui transforment un modèle moyen en assistant chirurgical.",
  color: "from-cyan-500 to-blue-500",
  lessons: [
    {
      slug: "system-prompts-xml-fewshot",
      moduleSlug: "prompt-engineering",
      index: 1,
      title: "System prompts, XML structuring et few-shot",
      subtitle: "Donner au modèle un rôle, une structure, des exemples",
      level: "advanced",
      durationMin: 20,
      objectives: [
        "Écrire un system prompt qui tient en production",
        "Utiliser les balises XML pour le suivi d'instructions",
        "Choisir entre zero-shot, few-shot et many-shot",
        "Mesurer l'impact de chaque ajout sur la qualité",
      ],
      vocalScript: `[Intro]
Le prompt engineering n'est pas mort, contrairement à ce qu'on lit. Il s'est juste déplacé : moins de hacks, plus d'ingénierie. Cette leçon te donne le standard de qualité d'un AI builder pro.

[Section 1 - System prompt]
Le system prompt, c'est le contrat entre toi et le modèle. Il définit qui il est, ce qu'il sait, comment il répond, ce qu'il refuse. Un bon system prompt tient en sept sections : identité, contexte, objectif, contraintes, style, exemples, garde-fous. On va décortiquer chacune.

[Section 2 - XML]
Claude est entraîné à suivre des balises XML avec une discipline quasi-religieuse. Tu enveloppes ton document dans des balises "document", tes exemples dans "examples", ton output attendu dans "output_format". Le modèle traite chaque balise comme une instruction structurelle. Magique.

[Section 3 - Few-shot]
Les exemples valent mille adjectifs. "Sois concis" est vague. Trois exemples concis sont sans appel. La règle empirique : trois exemples bien choisis battent trente lignes d'instructions. Et si trois ne suffisent pas, monte à dix, vingt, parfois cent — c'est ce qu'on appelle le many-shot.

[Conclusion]
Le mantra : moins d'adjectifs, plus de structure, plus d'exemples. Mesure tout.`,
      visuals: [
        {
          title: "Anatomie d'un system prompt pro",
          description:
            "Diagramme vertical en 7 blocs : Identity / Context / Objective / Constraints / Style / Examples / Guardrails. Chaque bloc avec une mini-icône.",
        },
        {
          title: "Balises XML qui marchent",
          description:
            "Liste des balises les plus utiles : <task>, <context>, <document>, <example>, <output_format>, <thinking>, <answer>. Avec exemple compact à droite.",
        },
        {
          title: "Few-shot impact curve",
          description:
            "Courbe qualité (y) vs nombre d'exemples (x). Croissance forte de 0 à 3, plateau, puis nouvelle pente vers 50+ (many-shot regime).",
        },
      ],
      content: `## Le system prompt : ton contrat avec le modèle

Un system prompt pro tient sur 7 sections :

\`\`\`xml
<identity>
You are a senior backend engineer specialized in distributed systems.
</identity>

<context>
You're embedded in a CLI tool that helps developers debug Kubernetes deployments.
</context>

<objective>
Diagnose the user's problem in 3 hypotheses ranked by likelihood, then propose
ONE concrete next command to run.
</objective>

<constraints>
- Never invent error codes; if uncertain, say "I'd need to see X".
- Always cite the source (logs, manifest, command output) for each hypothesis.
</constraints>

<style>
Terse, technical, no preamble. Bulleted hypotheses. Code blocks for commands.
</style>

<examples>
[2-3 examples here]
</examples>

<guardrails>
If asked to perform destructive operations (delete, drop, force), require explicit confirmation.
</guardrails>
\`\`\`

Chaque section est **fonctionnelle**, pas décorative.

## Les balises XML : la grammaire de Claude

Claude est entraîné massivement avec du XML structurel. Utilise-le.

| Balise | Usage |
|---|---|
| \`<task>\` | Définir clairement la tâche |
| \`<context>\` | Donner du background |
| \`<document>\` | Délimiter un texte source |
| \`<example>\` | Few-shot examples |
| \`<output_format>\` | Format attendu |
| \`<thinking>\` | Espace de raisonnement |
| \`<answer>\` | Réponse finale |

**Astuce** : utilise des **noms cohérents** dans tout ton produit. \`<doc>\` partout, ou \`<document>\` partout, mais pas les deux.

## Few-shot : la puissance des exemples

\`\`\`
Sans exemples : "Reformule en plus concis."
Avec exemples :
  Input: "Je voudrais savoir si vous pourriez peut-être m'aider à comprendre comment..."
  Output: "Comment puis-je..."

  Input: "Il est important de noter que dans certains cas particuliers..."
  Output: "Parfois..."
\`\`\`

**Règles d'or des exemples** :
1. **Diversifie** — couvre les cas extrêmes, pas trois variantes du même.
2. **Format identique** — Input/Output avec des balises stables.
3. **Inclus l'erreur** — un exemple "anti-pattern" avec un commentaire \`<!-- wrong -->\` est très puissant.
4. **3 → 5 → 20** — commence à 3, monte si la qualité plafonne.

## Many-shot : le regime caché

Sur des modèles modernes (Claude, Gemini), passer de 5 à 50 exemples peut donner un nouveau gain. C'est presque du fine-tuning, sans entraînement.

\`\`\`python
system = "You classify support tickets into [billing, technical, sales, other]."
examples = load_50_real_examples()  # avec leurs labels
prompt = format_examples(examples) + f"\\n\\nNew ticket: {ticket}\\nLabel:"
\`\`\`

Combine avec **prompt caching** → tu paies les exemples 1 fois.

## Anti-patterns à bannir

- ❌ "Sois précis et utile" → vague, le modèle pense déjà l'être
- ❌ "Ne fais pas X, Y, Z" → mieux vaut dire ce qu'il **doit** faire
- ❌ "Réponds en JSON" sans schéma → utilise structured output
- ❌ "Réfléchis bien avant de répondre" → utilise \`<thinking>\` ou extended thinking
- ❌ Mégaprompt non testé → mesure chaque ajout sur un eval set

## À retenir

- System prompt = 7 sections fonctionnelles, pas un blob d'adjectifs.
- Balises XML = grammaire native de Claude, exploite-la.
- Few-shot bat instructions verbales — diversité + format stable.
- Many-shot + caching = quasi fine-tuning gratuit.
- Tout changement de prompt doit être mesuré sur un eval set.`,
      practice: `**Exercice : refactor de prompt**

Voici un mauvais prompt :
> "Tu es un assistant qui aide à reformuler des emails. Sois professionnel, clair et concis. Ne sois pas trop long. Évite le jargon."

1. Réécris-le avec la structure 7 sections.
2. Ajoute 3 exemples diversifiés.
3. Formate en XML.
4. Bonus : crée 5 cas de test pour mesurer la qualité avant/après.`,
      quiz: [
        {
          question: "Pourquoi les balises XML fonctionnent-elles si bien avec Claude ?",
          choices: [
            "C'est un hack obscur",
            "Claude est entraîné massivement à les reconnaître comme structure sémantique",
            "Elles compressent le texte",
            "Aucun effet réel",
          ],
          answerIndex: 1,
          explanation:
            "L'entraînement de Claude inclut beaucoup de XML structuré, ce qui en fait une grammaire native pour le modèle.",
        },
        {
          question: "Quelle est la meilleure pratique pour les few-shot examples ?",
          choices: [
            "Trois variantes très proches du même cas",
            "Diversité maximale (cas extrêmes inclus), format strictement identique",
            "Toujours mettre 50 exemples",
            "Mettre juste un exemple parfait",
          ],
          answerIndex: 1,
          explanation:
            "Diversité > quantité brute. Et un format identique entre exemples permet au modèle de capter le pattern.",
        },
        {
          question: "Quand basculer du few-shot au many-shot (20-100 exemples) ?",
          choices: [
            "Jamais, c'est trop cher",
            "Quand la qualité plafonne avec ~5 exemples ET que tu peux activer le prompt caching pour absorber le coût",
            "Toujours par défaut",
            "Uniquement avec GPT",
          ],
          answerIndex: 1,
          explanation:
            "Le many-shot est puissant mais coûteux à l'input. Combiné au caching, il devient quasi gratuit.",
        },
      ],
      resources: [
        { label: "Anthropic — Prompt Engineering Guide", href: "https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/overview" },
        { label: "Many-shot In-Context Learning (Google DeepMind)", href: "https://arxiv.org/abs/2404.11018" },
      ],
    },
    {
      slug: "chain-of-thought-extended-thinking",
      moduleSlug: "prompt-engineering",
      index: 2,
      title: "Chain-of-thought et extended thinking",
      subtitle: "Faire raisonner le modèle au lieu de deviner",
      level: "advanced",
      durationMin: 16,
      objectives: [
        "Distinguer CoT explicite, implicite et extended thinking",
        "Choisir le bon mode selon la tâche",
        "Maîtriser le budget thinking",
        "Combiner thinking + tools sans casser l'agent",
      ],
      vocalScript: `[Intro]
Quand un modèle se trompe sur une question complexe, c'est rarement un manque de connaissance. C'est un manque d'espace pour réfléchir. Cette leçon te montre comment lui en donner.

[Section 1 - CoT classique]
Le chain-of-thought, ou CoT, c'est l'idée de demander explicitement au modèle de décomposer son raisonnement avant de conclure. Une seule phrase magique : "réfléchis étape par étape avant de répondre". Sur des problèmes math ou logique, ça peut doubler la précision. Et c'est gratuit.

[Section 2 - Extended thinking]
Les modèles modernes — Claude, GPT, Gemini — proposent maintenant un mode "extended thinking" ou "reasoning". Tu réserves un budget de tokens internes que le modèle utilise pour penser à voix basse, sans que ce soit visible. Ces tokens coûtent comme de l'output mais ne pollutent pas la réponse finale. C'est un game changer pour le code, le debugging, la planif d'agents.

[Section 3 - quand l'utiliser]
Règle simple : si la tâche prend plus de trente secondes à un humain expert, active le thinking. Sinon laisse-le off. Et attention : ne combine pas naïvement thinking + tool use sans lire la doc — l'ordre des messages compte.

[Conclusion]
Le thinking, c'est de la RAM pour le modèle. Donne-lui-en quand le problème le mérite, pas par défaut.`,
      visuals: [
        {
          title: "3 modes de raisonnement",
          description:
            "Comparaison côte-à-côte : (1) Direct answer → tokens output. (2) CoT explicite → 'Step 1... Step 2... Final answer'. (3) Extended thinking → bloc invisible <thinking> + answer.",
        },
        {
          title: "Quand activer le thinking",
          description:
            "Arbre de décision : Tâche < 5s humain ? → off. Tâche 5–30s ? → CoT prompt. Tâche > 30s ou multi-step ? → extended thinking avec budget 8k–32k tokens.",
        },
      ],
      content: `## Trois modes, trois cas d'usage

### 1. Direct (zero reasoning)

\`\`\`
User: What is 23 × 47?
Assistant: 1081
\`\`\`

Pour les tâches triviales. Aucun overhead.

### 2. Chain-of-thought (CoT) explicite

\`\`\`
User: Think step by step. What is 23 × 47?
Assistant: 23 × 47 = 23 × 50 − 23 × 3 = 1150 − 69 = 1081.
\`\`\`

Coût : tokens visibles dans la réponse. Gain : précision en hausse sur tout ce qui demande plus d'une étape.

**Variante structurée** :
\`\`\`xml
<thinking>
[le modèle pose son raisonnement]
</thinking>
<answer>
[réponse finale propre]
</answer>
\`\`\`

Tu peux ensuite **stripper** le \`<thinking>\` pour l'affichage user.

### 3. Extended thinking (mode reasoning)

Sur Claude 4.x, GPT o-series, Gemini Thinking : un **budget** de tokens internes que le modèle dépense pour penser, séparé de l'output utilisateur.

\`\`\`python
response = client.messages.create(
    model="claude-opus-4-7",
    thinking={"type": "enabled", "budget_tokens": 16000},
    messages=[{"role": "user", "content": HARD_PROBLEM}],
)
# response.content contient :
# - bloc 'thinking' (pensée interne)
# - bloc 'text' (réponse utilisateur)
\`\`\`

**Coût** : ces tokens sont facturés comme output. **Gain** : sur du code complexe, du debugging, du multi-step planning, on observe couramment +20 à +40% de réussite.

## Décider en 5 secondes

| Tâche | Mode |
|---|---|
| QA simple, lookup | Direct |
| Math basique, format change | Direct |
| Math/logique > 1 étape | CoT prompt |
| Choix multi-critères | CoT prompt |
| Code review, planif d'agent | Extended thinking |
| Debug, refactor multi-fichiers | Extended thinking 16k+ |

## Pièges à éviter

1. **Thinking par défaut** → tu paies pour rien sur 80% des requêtes.
2. **CoT + structured output mal géré** → le JSON peut sortir cassé. Mets le thinking dans un champ JSON dédié, ou utilise extended thinking natif.
3. **Thinking + tool use sans lire la doc** → l'ordre des blocs compte (thinking, tool_use, tool_result, etc.).
4. **Budget thinking trop petit** → le modèle se coupe au milieu de son raisonnement → réponse pire que sans thinking.

## Pattern : thinking guidé

Tu peux **structurer** le thinking :

\`\`\`xml
<thinking>
1. Restate the user's actual goal in one sentence.
2. List the constraints (explicit and implicit).
3. Brainstorm 3 approaches; eliminate 2 with reasoning.
4. Choose the surviving approach and outline 5 concrete steps.
</thinking>
\`\`\`

Effet : la qualité du raisonnement explose, parce que tu lui as donné un **plan de pensée**.

## À retenir

- 3 modes : direct, CoT explicite, extended thinking — choisis selon la difficulté.
- Le thinking coûte mais ramène typiquement +20–40% sur tâches complexes.
- N'active jamais par défaut. Et budgétise correctement.
- Structurer le thinking (4–5 étapes) > laisser libre.`,
      practice: `**Exercice : A/B test thinking**

1. Prends 10 prompts variés de ton produit (faciles + complexes).
2. Lance chaque prompt en 3 modes : direct, CoT prompt, extended thinking 8k tokens.
3. Note pour chacun : coût, latence, qualité (1–5).
4. Trace : pour quelles tâches le thinking est-il rentable ?

Tu auras ta **politique de routing thinking** pour ton produit.`,
      quiz: [
        {
          question: "Quel est le principal avantage de l'extended thinking vs CoT classique ?",
          choices: [
            "C'est plus rapide",
            "Le raisonnement est isolé du texte de réponse, ne pollue pas l'output, et bénéficie d'un budget dédié",
            "C'est gratuit",
            "Aucune différence",
          ],
          answerIndex: 1,
          explanation:
            "Extended thinking sépare proprement raisonnement interne et réponse user, et donne au modèle de l'espace explicite pour penser.",
        },
        {
          question: "Quand activer le thinking par défaut ?",
          choices: [
            "Toujours, par sécurité",
            "Jamais — c'est cher et inutile sur 80% des requêtes simples",
            "Uniquement le week-end",
            "Pour toutes les requêtes en français",
          ],
          answerIndex: 1,
          explanation:
            "Le thinking coûte. Active-le quand la tâche est complexe (multi-step, planif, debug). Sinon, off.",
        },
        {
          question: "Pourquoi structurer le thinking en étapes (1, 2, 3, 4) ?",
          choices: [
            "Pour que ce soit joli",
            "Parce qu'un plan de pensée explicite augmente significativement la qualité du raisonnement",
            "C'est obligatoire dans l'API",
            "Pour réduire les tokens",
          ],
          answerIndex: 1,
          explanation:
            "Comme un humain : penser de façon structurée donne de meilleurs résultats que de penser en vrac.",
        },
      ],
      resources: [
        { label: "Anthropic — Extended Thinking", href: "https://docs.anthropic.com/en/docs/build-with-claude/extended-thinking" },
        { label: "Chain-of-Thought Prompting (Wei et al. 2022)", href: "https://arxiv.org/abs/2201.11903" },
      ],
    },
  ],
};
