import type { Module } from "../types";

export const module1: Module = {
  slug: "llm-foundations",
  index: 1,
  title: "Fondations des LLM modernes",
  tagline: "Comprendre la machine avant de la dompter",
  description:
    "Architecture transformer, attention, MoE, tokens, context window, pricing, comparaison Claude / GPT / Gemini / Llama. Le socle technique d'un AI builder.",
  color: "from-fuchsia-500 to-violet-500",
  lessons: [
    {
      slug: "anatomie-llm",
      moduleSlug: "llm-foundations",
      index: 1,
      title: "Anatomie d'un LLM moderne",
      subtitle: "Transformer, attention, MoE — ce qui se passe vraiment dans la boîte",
      level: "intermediate",
      durationMin: 18,
      objectives: [
        "Décrire le pipeline d'inférence d'un LLM",
        "Expliquer self-attention en une phrase",
        "Distinguer dense vs Mixture-of-Experts (MoE)",
        "Identifier les implications pratiques pour un builder",
      ],
      vocalScript: `[Intro - ton calme]
Bienvenue dans la première leçon. Avant d'écrire le moindre prompt sérieux, il faut comprendre ce qu'est réellement un Large Language Model. Pas la version marketing — la version technique, simplifiée mais juste.

[Section 1 - 2 min]
Un LLM, c'est un réseau de neurones de type transformer entraîné à prédire le prochain token. Token, pas mot. Le modèle voit ton prompt comme une séquence de petits morceaux de texte, et pour chaque position il calcule une distribution de probabilité sur tout son vocabulaire — typiquement 100 000 à 200 000 tokens possibles.

[Section 2 - self-attention]
Le mécanisme central s'appelle self-attention. Pour chaque token, le modèle calcule à quel point chaque autre token de la séquence est pertinent. C'est ce qui lui permet de relier "il" à "Pierre" trois phrases plus haut. Retiens ça : un LLM, c'est un système de pertinence contextuelle, pas une base de données.

[Section 3 - MoE]
Les modèles modernes — GPT-4, Claude, Gemini, Mixtral — utilisent souvent une architecture Mixture of Experts. Au lieu d'activer tous les paramètres pour chaque token, un routeur sélectionne deux ou trois "experts" parmi des dizaines. Résultat : un modèle avec mille milliards de paramètres au total peut n'en activer que cent milliards par token. Plus rapide, moins cher, parfois meilleur.

[Conclusion]
Implication pratique pour toi en tant que builder : la qualité de la réponse dépend de ce que le modèle peut "regarder" en un seul forward pass. Tout ce qui n'entre pas dans son contexte est invisible. Tout ce qui y entre coûte. C'est la fondation de tout le reste du cours.`,
      visuals: [
        {
          title: "Pipeline d'inférence",
          description:
            "Schéma horizontal en 4 étapes : Texte → Tokenizer → Embeddings → Stack de transformers (N layers) → Logits → Sampling → Token suivant. Mettre en évidence la boucle auto-régressive.",
          ascii: `texte ──► tokens ──► embeddings ──► [transformer × N] ──► logits ──► sample ──┐
                                                                                  │
       ◄───────────────── token ajouté à la séquence ──────────────────────────┘`,
        },
        {
          title: "Self-attention en une image",
          description:
            "Matrice carrée tokens×tokens, cases plus sombres = plus d'attention. Exemple : phrase 'Le chat dort car il est fatigué.' avec une case sombre entre 'il' et 'chat'.",
        },
        {
          title: "Dense vs Mixture-of-Experts",
          description:
            "Deux schémas côte à côte. À gauche : tous les neurones s'allument. À droite : un routeur dirige vers 2 experts sur 8. Annotation : 'Active params << Total params'.",
        },
      ],
      content: `## Pourquoi cette leçon

Beaucoup de "AI builders" écrivent des prompts sans jamais comprendre ce qui se passe dans le modèle. Ça fonctionne — jusqu'à ce que ça casse. Cette leçon te donne le **modèle mental** correct.

## Le LLM en une phrase

> Un LLM est une fonction \`P(token_suivant | tokens_précédents)\`, paramétrée par des milliards de poids appris.

Tout le reste — chat, agents, RAG — n'est qu'un wrapper autour de cette fonction.

## Tokenisation

Le modèle ne lit pas du texte. Il lit des **tokens**, des sous-mots produits par un *Byte-Pair Encoding* (BPE) ou variante.

| Texte | Tokens (Claude/GPT approx) |
|---|---|
| "hello" | 1 |
| "anthropomorphisation" | 5–7 |
| "你好" | 2–3 |
| Code Python | ~1 token / 3 caractères |

**Implication** : ton choix de langue, de format, de noms de variables impacte le coût et la latence.

## Self-attention

Pour chaque position \`i\`, le modèle calcule trois vecteurs : Query, Key, Value. Le poids d'attention de \`i\` vers \`j\` est :

\`\`\`
attention(i, j) = softmax( Q_i · K_j / √d )
\`\`\`

C'est ce qui permet à "il" de pointer vers "Pierre" trois phrases plus haut. Sans attention, pas de contexte long.

## Mixture of Experts (MoE)

Les modèles frontière modernes (GPT-4, Claude, Gemini, Mixtral, DeepSeek) utilisent souvent du MoE :

- **N experts** (typiquement 8 à 256), chacun étant un sous-réseau feed-forward
- Un **routeur** sélectionne **k experts** par token (souvent k=2)
- Les params **totaux** sont énormes, mais les params **actifs** par token restent gérables

Concrètement : meilleure qualité, moins de FLOPs par token, mais plus complexe à servir.

## Ce que ça change pour toi, builder

1. **Le contexte est tout** — le modèle ne "sait" rien hors du prompt + son entraînement figé.
2. **Les tokens coûtent** — tu paies à l'input et à l'output. Optimiser = compter.
3. **Les capacités émergent** — un modèle plus gros ≠ un modèle plus stupide. Mais "plus gros" inclut MoE actif, pas total.
4. **Latence ≈ tokens output** — l'input est traité en parallèle, l'output token par token.

## À retenir

- LLM = prédiction du prochain token, point.
- Self-attention = mécanisme de pertinence contextuelle.
- MoE = qualité d'un gros modèle au coût d'un petit.
- Tout ce que tu construis vit ou meurt par la qualité du contexte que tu fournis.`,
      practice: `**Exercice : token economy**

1. Va sur le tokenizer Claude (https://platform.openai.com/tokenizer pour OpenAI ou la doc Anthropic) et tokenise :
   - Une phrase en anglais
   - La même phrase en français
   - La même phrase en japonais
   - 10 lignes de Python
2. Note le ratio tokens/caractères pour chacun.
3. Calcule combien coûterait 1 million de requêtes de cette taille à $3/M tokens input.

**Livrable** : un petit tableau dans tes notes.`,
      quiz: [
        {
          question: "Quelle est la fonction fondamentale apprise par un LLM ?",
          choices: [
            "Récupérer des documents pertinents",
            "Prédire la probabilité du prochain token",
            "Stocker des connaissances dans une base",
            "Exécuter du code de manière déterministe",
          ],
          answerIndex: 1,
          explanation:
            "Un LLM est entraîné par next-token prediction. Toutes les capacités émergent de cet objectif simple.",
        },
        {
          question: "Dans une architecture MoE, qu'est-ce qui distingue 'paramètres actifs' et 'paramètres totaux' ?",
          choices: [
            "Rien, les deux sont synonymes",
            "Les actifs sont ceux utilisés pour un token donné, les totaux incluent tous les experts",
            "Les actifs sont post-quantization, les totaux sont pré-quantization",
            "Les actifs concernent l'inférence, les totaux concernent l'entraînement uniquement",
          ],
          answerIndex: 1,
          explanation:
            "Le routeur n'active qu'un sous-ensemble d'experts (souvent k=2) par token. Les autres dorment, d'où la différence.",
        },
        {
          question: "Pourquoi la latence d'output domine-t-elle la latence d'input ?",
          choices: [
            "Parce que l'output est toujours plus long",
            "Parce que l'input est traité en parallèle alors que l'output est généré token par token (auto-régressif)",
            "Parce que le serveur priorise l'input",
            "C'est faux, l'input est plus lent",
          ],
          answerIndex: 1,
          explanation:
            "Un prompt de 10 000 tokens est traité en un seul forward pass. Une réponse de 500 tokens nécessite 500 forward passes séquentiels.",
        },
      ],
      resources: [
        { label: "Attention Is All You Need (Vaswani 2017)", href: "https://arxiv.org/abs/1706.03762" },
        { label: "Mixtral of Experts (Mistral AI)", href: "https://arxiv.org/abs/2401.04088" },
        { label: "The Illustrated Transformer (Jay Alammar)", href: "https://jalammar.github.io/illustrated-transformer/" },
      ],
    },
    {
      slug: "tokens-context-pricing",
      moduleSlug: "llm-foundations",
      index: 2,
      title: "Tokens, context window et pricing",
      subtitle: "Le triangle économique de tout AI builder",
      level: "intermediate",
      durationMin: 15,
      objectives: [
        "Comprendre le coût marginal d'un appel LLM",
        "Calculer le budget tokens d'une feature",
        "Distinguer context window utile vs annoncée",
        "Utiliser le prompt caching pour diviser les coûts par 10",
      ],
      vocalScript: `[Intro]
La leçon précédente t'a montré l'intérieur de la machine. Celle-ci te montre comment elle facture. Si tu veux construire des produits IA viables, tu dois maîtriser trois variables : tokens, context window, prix.

[Section 1 - tokens]
Un token, c'est en moyenne 4 caractères en anglais, 3 en français, 1 en chinois ou japonais. Quand un fournisseur annonce "1$ par million de tokens", c'est 250 000 mots — environ trois romans. Ça paraît énorme jusqu'au moment où ton agent fait dix tours dans une boucle, chacun renvoyant tout l'historique.

[Section 2 - context window]
Le context window, c'est la longueur maximale que le modèle peut ingérer. Aujourd'hui, tu vois 200 000, 1 million, voire 2 millions de tokens. Mais attention : utilisable n'est pas égal à efficace. Au-delà d'un certain seuil, la qualité d'attention chute. C'est ce qu'on appelle le "lost in the middle" — le modèle oublie ce qui est au milieu d'un long document.

[Section 3 - prompt caching]
Voici le secret le mieux gardé : le prompt caching. Si ton system prompt fait 50 000 tokens et que tu le réutilises 1000 fois par jour, sans cache tu paies 50 millions de tokens d'input quotidiens. Avec cache, tu paies une fois plein tarif puis dix pour cent ensuite. Un facteur dix sur ta facture. C'est la première optimisation à mettre en place dès qu'un produit dépasse cent utilisateurs.

[Conclusion]
Règle d'or : avant de scaler une feature, fais le calcul tokens × prix × volume. Tu seras surpris de ce que tu trouves.`,
      visuals: [
        {
          title: "Budget tokens d'un agent",
          description:
            "Diagramme en cascade : input prompt (5k) + 10 itérations × (output 500 + tool result 2k + reinjection 7.5k) = budget total. Mettre en rouge la croissance quadratique de la réinjection.",
        },
        {
          title: "Lost in the Middle",
          description:
            "Courbe de précision en fonction de la position de l'info dans le contexte : haute aux extrémités, creux au milieu. Annoter 'attention au-delà de 100k tokens'.",
        },
        {
          title: "Prompt caching économies",
          description:
            "Barres comparées : sans cache (100% du coût input chaque appel) vs avec cache (10% pour les hits). Annotation '90% d'économie sur les tokens cachés'.",
        },
      ],
      content: `## Le triangle économique

Tout produit IA tient sur trois variables :

\`\`\`
coût ≈ (tokens_input × prix_input + tokens_output × prix_output) × nombre_d'appels
\`\`\`

Maîtriser cette équation, c'est la différence entre une démo virale qui faillite et un produit rentable.

## Pricing typique (ordres de grandeur 2025)

| Modèle | Input ($/M tok) | Output ($/M tok) | Notes |
|---|---|---|---|
| Claude Opus 4.x | ~15 | ~75 | Frontière, raisonnement |
| Claude Sonnet 4.x | ~3 | ~15 | Sweet spot prix/perf |
| Claude Haiku 4.x | ~0.25 | ~1.25 | Routing, tâches simples |
| GPT-4 class | ~2.5–10 | ~10–30 | Variable |
| Open source self-hosted | $0 (mais GPU) | $0 (mais GPU) | TCO réel à calculer |

L'**output coûte 4 à 5× l'input**. C'est pour ça que les techniques qui réduisent l'output (résumés, structured output minimal, streaming early-stop) ont un ROI massif.

## Context window — utilisable ≠ annoncée

Un modèle annonce 1M tokens de contexte ? Excellent. Mais :

- **Lost in the middle** : la précision chute pour les infos au milieu d'un long contexte.
- **Latence** : un prompt de 200k tokens prend 5–15 secondes rien qu'à le lire.
- **Coût** : 200k tokens d'input à 3$/M = 0,60$ par appel. ×10 000 utilisateurs/jour = 6 000$/jour.

**Règle pratique** : optimise pour le plus petit contexte qui résout le problème. Pas pour le plus gros.

## Prompt caching : la divison par 10

Le prompt caching te permet de **mettre en cache** un préfixe de prompt côté serveur. Chaque réutilisation coûte ~10% du prix normal en input (et un cache write coûte ~1.25× un input normal).

**Cas d'usage idéal** : system prompt long, exemples few-shot, RAG context stable, documents de référence.

**Exemple** : 50k tokens de system prompt + 1k de query par appel.
- Sans cache : 51k × 3$/M = **0,153$ par appel**
- Avec cache (hit) : 5k (cached) × 0,30$/M + 1k × 3$/M = **0,0045$ par appel**
- **Économie : ~97%** sur la portion cachée.

\`\`\`python
# Anthropic SDK — exemple
client.messages.create(
    model="claude-sonnet-4-6",
    system=[{
        "type": "text",
        "text": LONG_SYSTEM_PROMPT,
        "cache_control": {"type": "ephemeral"}
    }],
    messages=[{"role": "user", "content": user_query}],
)
\`\`\`

## Compter avant de coder

Avant chaque feature, fais ce calcul napkin :

\`\`\`
tokens_par_appel × appels_par_user_par_jour × users × 30 × prix = coût mensuel
\`\`\`

Si le résultat te fait pâlir, change l'architecture **avant** d'écrire le code.

## À retenir

- Output >> Input en coût. Réduis l'output en priorité.
- Context window utile < context window annoncée. Reste compact.
- Prompt caching = 10× moins cher sur les préfixes stables. Active-le toujours.
- Le calcul tokens × volume × prix doit précéder toute décision d'archi.`,
      practice: `**Exercice : audit budgétaire**

Imagine un chatbot support qui :
- A un system prompt de 8 000 tokens
- Reçoit en moyenne 50 mots par message utilisateur
- Répond ~200 mots
- Sert 10 000 conversations/jour, 5 messages chacune

Calcule le coût mensuel **avec** et **sans** prompt caching, en utilisant Sonnet (3$/M input, 15$/M output).

Bonus : combien économises-tu en routant 70% des cas simples vers Haiku ?`,
      quiz: [
        {
          question: "Pourquoi optimiser l'output token est-il généralement plus rentable que l'input ?",
          choices: [
            "L'output est plus court donc plus visible",
            "Le prix output est typiquement 4–5× le prix input et l'output est généré séquentiellement (latence)",
            "L'output est facturé en double",
            "Il n'y a pas de différence",
          ],
          answerIndex: 1,
          explanation:
            "Double effet : prix unitaire plus élevé ET latence dominée par l'output. Réduire l'output économise temps et argent.",
        },
        {
          question: "Quel est l'effet 'lost in the middle' ?",
          choices: [
            "Le modèle perd les tokens en milieu de génération",
            "La qualité d'attention chute pour les infos placées au milieu d'un long contexte",
            "Le tokenizer perd les caractères spéciaux",
            "Le cache se vide après 50% d'utilisation",
          ],
          answerIndex: 1,
          explanation:
            "Étudié notamment par Stanford : à très long contexte, le modèle se rappelle mieux du début et de la fin que du milieu.",
        },
        {
          question: "Dans quel cas le prompt caching est-il rentable ?",
          choices: [
            "Quand chaque requête utilisateur est unique et différente",
            "Quand un préfixe de prompt long est réutilisé sur de nombreux appels",
            "Uniquement pour les modèles open-source",
            "Jamais, c'est trop complexe à mettre en place",
          ],
          answerIndex: 1,
          explanation:
            "Le caching brille sur les préfixes stables : system prompt long, RAG context fixe, exemples few-shot répétés.",
        },
      ],
      resources: [
        { label: "Lost in the Middle (Stanford 2023)", href: "https://arxiv.org/abs/2307.03172" },
        { label: "Anthropic — Prompt Caching", href: "https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching" },
      ],
    },
    {
      slug: "choisir-son-modele",
      moduleSlug: "llm-foundations",
      index: 3,
      title: "Choisir son modèle : la matrice de décision",
      subtitle: "Claude, GPT, Gemini, Llama — quand utiliser quoi",
      level: "intermediate",
      durationMin: 14,
      objectives: [
        "Construire une matrice modèle × usage",
        "Identifier les forces propres à chaque famille",
        "Mettre en place une stratégie multi-modèle (router)",
        "Évaluer un nouveau modèle en 30 minutes",
      ],
      vocalScript: `[Intro]
Le piège classique du builder débutant : choisir un modèle parce qu'il est à la mode, ou pire, parce que son fournisseur a la meilleure documentation. Le bon réflexe c'est de mapper modèle ↔ tâche.

[Section 1 - taxonomie]
Aujourd'hui tu as quatre familles dominantes. Anthropic Claude, OpenAI GPT, Google Gemini, et l'écosystème open-source emmené par Llama, Qwen, DeepSeek, Mistral. Chaque famille a une signature : Claude excelle sur le raisonnement long et l'agentique, GPT sur l'écosystème et le multimodal, Gemini sur le très long contexte, l'open-source sur le coût et la souveraineté.

[Section 2 - matrice]
Pour chaque tâche, pose-toi quatre questions : quelle qualité minimale tu acceptes, quelle latence maximale, quel coût par appel, quelles contraintes de données — souveraineté, on-premise, fine-tuning. Croise les réponses avec une matrice et tu obtiens ton choix en deux minutes.

[Section 3 - routing]
Le secret des produits matures : ils utilisent plusieurs modèles. Un petit modèle rapide pour classifier la requête. Un gros modèle pour les cas complexes. Un modèle spécialisé pour le code. C'est ce qu'on appelle le "model routing" et c'est ce qui te permet de réduire ta facture par cinq sans dégrader l'expérience.

[Conclusion]
Règle finale : n'épouse jamais un modèle. Code une couche d'abstraction et reste libre de switcher.`,
      visuals: [
        {
          title: "Matrice de décision",
          description:
            "Tableau 4×4. Lignes : Claude Opus, Sonnet, Haiku ; GPT-4o ; Gemini 1.5 Pro ; Llama 70B. Colonnes : Raisonnement, Coût, Latence, Très long contexte. Cases coloriées vert/jaune/rouge.",
        },
        {
          title: "Architecture de routing",
          description:
            "Diagramme : User → Classifier (Haiku) → switch → [Sonnet pour 80%, Opus pour 15%, code-specialist pour 5%]. Annoter '60% d'économie typique'.",
        },
      ],
      content: `## Les 4 familles à connaître

| Famille | Force signature | Idéal pour |
|---|---|---|
| **Claude (Anthropic)** | Raisonnement long, agentique, suivi d'instructions strict | Agents, code, analyse de docs |
| **GPT (OpenAI)** | Écosystème, multimodal, fine-tuning | Apps grand public, multimodal natif |
| **Gemini (Google)** | Très long contexte (1M+), intégration Google | Recherche docs massifs, vidéo |
| **Open-source (Llama/Qwen/DeepSeek/Mistral)** | Coût, contrôle, on-premise | Souveraineté, scale extrême, embedded |

## Les 4 questions à te poser

Pour chaque tâche dans ton produit :

1. **Qualité minimale acceptable ?** Tolère-t-on une erreur 1 fois sur 10 ? Sur 1000 ?
2. **Latence maximale ?** Sub-seconde (chat live), 5s (form), 30s+ (batch) ?
3. **Coût cible par appel ?** $0.001, $0.01, $0.10 ?
4. **Contraintes data ?** RGPD strict ? Données médicales ? On-premise obligatoire ?

Croise avec la matrice → tu as ton modèle.

## Pattern : le model router

Le pattern le plus rentable en production. Un petit modèle classifie, puis dispatch :

\`\`\`python
def route(query: str) -> str:
    classification = haiku.classify(query)  # ~$0.0001
    if classification == "simple_qa":
        return haiku.answer(query)            # ~$0.001
    elif classification == "code_task":
        return sonnet.answer(query)           # ~$0.01
    elif classification == "deep_reasoning":
        return opus.answer(query)             # ~$0.10
\`\`\`

**Effet typique** : 60–80% d'économie vs "tout-Opus", avec qualité perçue identique.

## Évaluer un nouveau modèle en 30 minutes

Quand un nouveau modèle sort (ça arrive toutes les 6 semaines) :

1. **Récupère 20 cas réels** de ton produit (pas synthétiques).
2. **Lance les 20 sur le nouveau modèle ET le modèle actuel**.
3. **Note 4 critères** : exactitude, format, latence, coût.
4. **Décision** : passe au nouveau si gain > 20% sur un critère sans régression sur les autres.

Pas besoin de leaderboards publics — ils mesurent rarement ton cas d'usage.

## Couche d'abstraction obligatoire

\`\`\`python
class LLM:
    def complete(self, messages, **kwargs) -> str: ...

class ClaudeProvider(LLM): ...
class OpenAIProvider(LLM): ...
class GeminiProvider(LLM): ...
\`\`\`

Tu coderas ça une fois. Tu remercieras ton toi-passé chaque trimestre.

## À retenir

- 4 familles, 4 signatures distinctes — connais-les.
- 4 questions pour choisir : qualité / latence / coût / data.
- Le routing multi-modèle est la norme en production mature.
- Couche d'abstraction = liberté de switcher.`,
      practice: `**Exercice : ta matrice**

1. Liste 5 features de ton produit (réel ou imaginaire).
2. Pour chacune, complète :
   - Qualité min (sur 10)
   - Latence max (en s)
   - Coût cible / appel
3. Choisis le modèle pour chaque feature.
4. Identifie au moins une feature où le routing apporterait > 50% d'économie.`,
      quiz: [
        {
          question: "Quelle est la signature typique de Claude vs GPT ?",
          choices: [
            "Claude pour multimodal natif, GPT pour le raisonnement long",
            "Claude pour le raisonnement long et l'agentique, GPT pour l'écosystème et le multimodal",
            "Aucune différence en pratique",
            "Claude est meilleur partout",
          ],
          answerIndex: 1,
          explanation:
            "Anthropic a investi tôt dans l'agentique et le suivi d'instruction strict ; OpenAI a un avantage écosystème et multimodal natif.",
        },
        {
          question: "Pourquoi mettre en place une couche d'abstraction LLM ?",
          choices: [
            "Pour respecter le clean code",
            "Pour pouvoir switcher de provider sans réécrire l'app, et faire du routing multi-modèle",
            "Pour cacher le code des junior devs",
            "Ce n'est jamais utile",
          ],
          answerIndex: 1,
          explanation:
            "L'industrie évolue trop vite pour s'enchaîner à un provider. Abstraction = optionalité.",
        },
        {
          question: "Approche recommandée pour évaluer un nouveau modèle ?",
          choices: [
            "Lire les benchmarks publics et trancher",
            "Tester sur 20 cas réels de ton produit avec 4 critères : exactitude, format, latence, coût",
            "Attendre 6 mois pour voir",
            "Demander sur Twitter",
          ],
          answerIndex: 1,
          explanation:
            "Les benchmarks publics sont rarement représentatifs de ton usage. Eval custom = 30 min bien investis.",
        },
      ],
      resources: [
        { label: "Anthropic Model Card", href: "https://docs.anthropic.com/en/docs/about-claude/models" },
        { label: "LMSYS Chatbot Arena", href: "https://chat.lmsys.org/" },
      ],
    },
  ],
};
