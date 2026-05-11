import type { Module } from "../types";

export const module5: Module = {
  slug: "agents",
  index: 5,
  title: "Agents IA : architecture et patterns",
  tagline: "De l'appel LLM unique au système autonome qui agit",
  description:
    "Architecture d'un agent, ReAct, Plan-and-Execute, subagents, gestion d'état. Construire des agents qui terminent leurs tâches sans dérailler.",
  color: "from-violet-500 to-fuchsia-500",
  lessons: [
    {
      slug: "architecture-agent",
      moduleSlug: "agents",
      index: 1,
      title: "Architecture d'un agent : la boucle de raison-action",
      subtitle: "Anatomie d'un agent qui marche en prod",
      level: "advanced",
      durationMin: 18,
      objectives: [
        "Décomposer un agent en 4 composants : LLM, tools, memory, controller",
        "Implémenter une agent loop minimale en ~50 lignes",
        "Choisir une stratégie de stop (max_steps, budget, completion signal)",
        "Éviter les boucles infinies et les blow-ups de coût",
      ],
      vocalScript: `[Intro]
Un agent, c'est un LLM qui boucle sur lui-même en utilisant des tools jusqu'à compléter une tâche. Simple à dire. Mille pièges à l'implémentation. Cette leçon te donne le squelette robuste.

[Section 1 - composants]
Quatre composants. Le LLM, qui décide. Les tools, qui agissent. La memory, qui se souvient — historique de la conversation, résultats précédents, observations. Le controller, qui orchestre la boucle et décide quand s'arrêter. Confondre ces rôles, c'est planter ton agent.

[Section 2 - loop]
La boucle agent classique : tu envoies au LLM le prompt + l'historique + les tools dispo. Il répond soit avec du texte final — terminé — soit avec un ou plusieurs tool_use. Tu exécutes les tools. Tu réinjectes les résultats. Tu reboucles. Cinquante lignes de code. Mais chaque ligne mérite réflexion.

[Section 3 - stop conditions]
Sans stop conditions, ton agent peut tourner indéfiniment et brûler ta facture. Trois garde-fous obligatoires : max_steps — typiquement vingt à cinquante, max_tokens budget — typiquement cent mille, et un completion signal — le LLM dit explicitement "done" ou retourne un text bloc final sans tool_use. Implémente les trois.

[Conclusion]
Cinquante lignes. Quatre composants. Trois stop conditions. C'est tout. Mais sans ce squelette correct, aucun framework ne te sauvera.`,
      visuals: [
        {
          title: "Agent loop",
          description:
            "Boucle visuelle : LLM → (text? STOP) | (tool_uses?) → execute → tool_results → reinject → LLM. Avec compteurs step et budget en bordure.",
        },
        {
          title: "4 composants d'un agent",
          description:
            "Diagramme 4 boîtes connectées : LLM (cerveau) ↔ Memory (mémoire) ↔ Controller (orchestration) → Tools (mains). Annoter les responsabilités.",
        },
      ],
      content: `## Le squelette d'agent en 50 lignes

\`\`\`python
async def run_agent(
    user_message: str,
    tools: list,
    *,
    max_steps: int = 30,
    max_tokens_budget: int = 100_000,
):
    messages = [{"role": "user", "content": user_message}]
    tokens_used = 0

    for step in range(max_steps):
        response = await llm.complete(
            system=AGENT_SYSTEM_PROMPT,
            messages=messages,
            tools=tools,
        )
        tokens_used += response.usage.total_tokens
        if tokens_used > max_tokens_budget:
            return {"status": "budget_exceeded", "messages": messages}

        messages.append({"role": "assistant", "content": response.content})

        # Stop condition: pure text response = done
        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            return {"status": "done", "messages": messages, "answer": response.text}

        # Execute tool calls (in parallel)
        tool_results = await asyncio.gather(*[
            execute_tool(t.name, t.input) for t in tool_uses
        ])
        messages.append({
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": tu.id, "content": tr}
                for tu, tr in zip(tool_uses, tool_results)
            ],
        })

    return {"status": "max_steps_reached", "messages": messages}
\`\`\`

C'est **tout**. Tout le reste — frameworks, visualisations, mémoire — n'est qu'amélioration de cette base.

## Les 4 composants

### 1. LLM (le cerveau)
Le modèle qui décide. Choisis selon la complexité (Sonnet par défaut, Opus pour tâches dures).

### 2. Tools (les mains)
Les actions disponibles. Voir Module 3 pour le design.

### 3. Memory (la mémoire)
Trois types :
- **Working memory** : l'historique de la conversation actuelle.
- **Short-term** : résumés cross-turns (notes de session).
- **Long-term** : RAG sur conversations passées, profil user, faits persistants.

### 4. Controller (l'orchestrateur)
Implémente la boucle, applique les stop conditions, log, fait du retry, gère les erreurs.

## Stop conditions : 3 obligatoires

\`\`\`python
# 1. Max steps
if step >= MAX_STEPS:
    return abort("too many steps")

# 2. Token budget
if tokens_used > BUDGET:
    return abort("budget exceeded")

# 3. Completion signal (pure text = done)
if not any_tool_use(response):
    return done()
\`\`\`

**Bonus** : timeout total (ex: 5 min) + signal d'interruption user.

## Pièges classiques

1. **Tool result trop gros** → tu réinjectes 50k tokens à chaque step. Truncate ou résume.
2. **Pas de retry sur tool errors** → l'agent abandonne au premier hoquet.
3. **Stream sans gestion** → tu coupes en plein tool_use.
4. **System prompt qui change au cours de la session** → casse le prompt cache.
5. **Pas de logging des décisions** → impossible à débugger.

## Pattern : agent observable

\`\`\`python
class AgentTrace:
    def log_step(self, step, llm_response, tool_calls, tool_results, latency, tokens):
        # Persiste pour debugging et eval
        ...

    def replay(self, trace_id):
        # Permet de rejouer une session entière en local
        ...
\`\`\`

Sans tracing, tu débugges à l'aveugle. Module 8 (Production) y revient en détail.

## À retenir

- Agent = LLM + Tools + Memory + Controller. Pas plus.
- 50 lignes pour la base ; le reste, c'est de l'amélioration progressive.
- 3 stop conditions obligatoires : max_steps, budget, completion signal.
- Tracing dès le jour 1 — sinon tu paieras cher en debug.`,
      practice: `**Exercice pipeline #3 : agent minimal**

Implémente l'agent loop ci-dessus en Python avec :
- 3 tools : \`web_search\`, \`fetch_url\`, \`summarize\`.
- Tâche test : "Trouve les 3 dernières features sorties par Anthropic et résume chacune en 2 phrases."
- Logs : pour chaque step, tokens utilisés, tool appelé, latence.
- Stop : max 10 steps, budget 50k tokens.

**Bonus** : ajoute un \`thinking\` block (extended thinking) au premier step pour planifier.`,
      quiz: [
        {
          question: "Quels sont les 4 composants d'un agent ?",
          choices: [
            "LLM, prompt, tokens, output",
            "LLM, Tools, Memory, Controller",
            "Frontend, backend, database, cache",
            "Question, réponse, score, log",
          ],
          answerIndex: 1,
          explanation:
            "Le LLM décide, les tools agissent, la memory se souvient, le controller orchestre. Confondre ces rôles = bugs.",
        },
        {
          question: "Quelle stop condition est SUFFISANTE seule ?",
          choices: [
            "max_steps seulement",
            "Aucune seule ne suffit — il faut au moins max_steps + budget tokens + completion signal",
            "Le user qui ferme l'onglet",
            "Le LLM qui se fatigue",
          ],
          answerIndex: 1,
          explanation:
            "Un agent peut consommer un énorme budget en peu de steps (gros prompts), ou boucler sur des steps minuscules. Combine les trois.",
        },
        {
          question: "Pourquoi tracer chaque step de l'agent ?",
          choices: [
            "Par décoration",
            "Pour pouvoir débugger, mesurer, et rejouer une session — sans trace, debug impossible",
            "Pour gonfler les logs",
            "Aucune utilité",
          ],
          answerIndex: 1,
          explanation:
            "Les agents échouent de façon non-déterministe. Sans trace complète (LLM in/out, tool call/result), tu ne peux pas reproduire ni corriger.",
        },
      ],
      resources: [
        { label: "Anthropic — Building Effective Agents", href: "https://www.anthropic.com/research/building-effective-agents" },
        { label: "ReAct paper (Yao et al. 2022)", href: "https://arxiv.org/abs/2210.03629" },
      ],
    },
    {
      slug: "react-plan-execute",
      moduleSlug: "agents",
      index: 2,
      title: "Patterns : ReAct, Plan-and-Execute, Reflexion",
      subtitle: "Choisir l'architecture cognitive de ton agent",
      level: "expert",
      durationMin: 18,
      objectives: [
        "Distinguer 3 patterns cognitifs majeurs",
        "Choisir le pattern selon la tâche (exploration vs planification)",
        "Implémenter Plan-and-Execute avec replanification",
        "Ajouter Reflexion pour l'auto-correction",
      ],
      vocalScript: `[Intro]
Tu sais faire boucler un agent. Maintenant, donne-lui une stratégie cognitive. Trois patterns dominent : ReAct, Plan-and-Execute, et Reflexion. Chacun a son terrain de jeu.

[Section 1 - ReAct]
ReAct, c'est Reasoning + Acting. À chaque tour le modèle pense puis agit puis observe. Adapté quand tu ne sais pas à l'avance ce qu'il faudra faire — typiquement, exploration, recherche, debugging interactif. C'est le pattern par défaut.

[Section 2 - Plan-and-Execute]
Plan-and-Execute : le modèle commence par établir un plan complet — sept étapes par exemple — puis exécute pas à pas. À chaque étape, il vérifie que le plan tient toujours, sinon il replanifie. Adapté aux tâches complexes structurées : génération de code, analyse multi-fichiers, workflows.

[Section 3 - Reflexion]
Reflexion : après chaque échec ou résultat médiocre, le modèle se critique lui-même et stocke des "leçons" pour les prochaines tentatives. Adapté aux tâches où la première tentative rate souvent : math compétitif, génération de tests, optim de prompt.

[Conclusion]
Pas de pattern universel. Identifie la nature de ta tâche, choisis ton pattern. Tu peux les combiner — Plan-and-Execute avec Reflexion intra-step est puissant.`,
      visuals: [
        {
          title: "3 patterns cognitifs",
          description:
            "Trois schémas verticaux : ReAct (Think→Act→Observe loop), Plan-and-Execute (Plan once → execute steps with replan checkpoints), Reflexion (Try → Reflect on failure → Retry with lessons).",
        },
        {
          title: "Quel pattern pour quelle tâche ?",
          description:
            "Tableau : Exploration/recherche → ReAct. Workflow structuré → Plan-and-Execute. Tâches difficiles avec retry → Reflexion. Combine si tâche longue + complexe.",
        },
      ],
      content: `## ReAct : Reasoning + Acting

\`\`\`
Thought: I need to find the customer's email.
Action: search_customer(name="Pierre Dupont")
Observation: Found 3 matches. Need more info.
Thought: I should narrow by city.
Action: search_customer(name="Pierre Dupont", city="Lyon")
Observation: 1 match. Email: pierre@example.com
Thought: I have what I need.
Final Answer: pierre@example.com
\`\`\`

**Force** : flexibilité, adapte à l'inconnu.
**Faiblesse** : peut errer sans direction sur tâches longues.
**Quand l'utiliser** : exploration, debugging, recherche.

C'est le pattern **par défaut** de la plupart des frameworks (LangChain agents, CrewAI, Anthropic SDK).

## Plan-and-Execute

\`\`\`python
async def plan_and_execute(task):
    # Étape 1 : planification
    plan = await llm.complete(
        system="Output a numbered plan with 3-7 concrete steps.",
        messages=[{"role": "user", "content": task}],
    )

    # Étape 2 : exécution avec replanification
    state = {"task": task, "plan": plan, "completed": [], "remaining": parse_steps(plan)}
    while state["remaining"]:
        next_step = state["remaining"][0]
        result = await execute_step(next_step, state)
        state["completed"].append({"step": next_step, "result": result})
        state["remaining"].pop(0)

        # Replan if necessary
        if needs_replan(result):
            new_plan = await llm.replan(state)
            state["remaining"] = parse_steps(new_plan)

    return state["completed"]
\`\`\`

**Force** : structure, prévisibilité, parallélisation possible.
**Faiblesse** : plan rigide si environnement change.
**Quand l'utiliser** : code generation, multi-file refactor, workflows business.

## Reflexion : auto-critique

\`\`\`python
async def reflexion(task, max_retries=3):
    lessons = []
    for attempt in range(max_retries):
        result = await execute(task, lessons=lessons)
        evaluation = await self_critic(task, result)
        if evaluation.success:
            return result
        # Stocker une leçon pour le prochain essai
        lessons.append(evaluation.lesson)
    return result  # best effort
\`\`\`

**Force** : amélioration progressive, auto-apprentissage intra-session.
**Faiblesse** : multiplie les coûts (×N retries).
**Quand l'utiliser** : génération de code complexe, math, tâches où on peut **vérifier** la sortie.

## Pattern combiné : Plan-Execute avec Reflexion intra-step

\`\`\`
1. PLAN (7 steps)
2. For each step:
   a. Execute (ReAct mini-loop)
   b. Self-critic
   c. If fail and step is critical, retry with lessons
3. Final synthesis
\`\`\`

C'est le pattern utilisé par les agents les plus performants (Devin, AutoCodeRover, etc.).

## Décider en 30 secondes

| Caractéristique de la tâche | Pattern recommandé |
|---|---|
| Inconnue, exploratoire | ReAct |
| Structurée, multi-step prévisible | Plan-and-Execute |
| Erreurs vérifiables (tests, validation) | Reflexion |
| Longue ET complexe | Plan-and-Execute + Reflexion |

## À retenir

- ReAct = défaut flexible.
- Plan-and-Execute = défaut structuré.
- Reflexion = défaut auto-correctif (si vérification possible).
- Combiner = puissance maximale, coût maximal — mesure l'overhead.`,
      practice: `**Exercice pipeline #4 : Plan-and-Execute en action**

Construis un agent "researcher" qui :
1. Reçoit une question recherche : "Quelles sont les 3 startups IA françaises les plus financées en 2024 ?"
2. **Plan phase** : produit un plan de 4–6 étapes.
3. **Execute phase** : exécute chaque étape avec ReAct mini-loop.
4. **Replan** : si une étape rate, replanifie le reste.
5. **Synthesize** : produit la réponse finale citée.

Tools : \`web_search\`, \`fetch_url\`, \`extract_text\`.

Mesure : nombre de steps, replans, total tokens, qualité de la réponse vs un agent ReAct pur.`,
      quiz: [
        {
          question: "Quel pattern choisir pour une tâche exploratoire dont on ne connaît pas le déroulé ?",
          choices: [
            "Plan-and-Execute",
            "ReAct — il s'adapte step par step à l'inconnu",
            "Reflexion seul",
            "Aucun, faire du non-agent",
          ],
          answerIndex: 1,
          explanation:
            "ReAct (Think-Act-Observe) est conçu pour explorer. Plan-and-Execute suppose qu'on peut planifier, ce qui n'est pas le cas en exploration.",
        },
        {
          question: "Quel est le coût principal de Reflexion ?",
          choices: [
            "Le code est compliqué",
            "Multiplie les coûts par N retries — à utiliser quand la vérification automatique est possible",
            "Pas de coût",
            "Seulement la latence",
          ],
          answerIndex: 1,
          explanation:
            "Reflexion = essais multiples. Rentable seulement si tu peux vérifier la sortie (tests qui passent, format valide, etc.).",
        },
        {
          question: "Quelle combinaison est la plus puissante ?",
          choices: [
            "ReAct seul",
            "Plan-and-Execute avec Reflexion sur les steps critiques",
            "Aucune combinaison ne marche",
            "Reflexion seul",
          ],
          answerIndex: 1,
          explanation:
            "Pattern utilisé par les meilleurs agents : structure du plan + flexibilité ReAct dans chaque step + auto-correction sur les steps critiques.",
        },
      ],
      resources: [
        { label: "ReAct paper (Yao et al. 2022)", href: "https://arxiv.org/abs/2210.03629" },
        { label: "Plan-and-Solve (Wang et al. 2023)", href: "https://arxiv.org/abs/2305.04091" },
        { label: "Reflexion paper (Shinn et al. 2023)", href: "https://arxiv.org/abs/2303.11366" },
      ],
    },
    {
      slug: "subagents-delegation",
      moduleSlug: "agents",
      index: 3,
      title: "Subagents et délégation",
      subtitle: "Quand un agent ne suffit pas",
      level: "expert",
      durationMin: 14,
      objectives: [
        "Identifier quand déléguer à un subagent",
        "Concevoir l'interface parent ↔ subagent",
        "Gérer le coût et la latence de la délégation",
        "Éviter les anti-patterns (sub-sub-sub agents)",
      ],
      vocalScript: `[Intro]
À un moment, ton agent a trop de tools, trop de contexte, trop de responsabilités. Au lieu de continuer à empiler, tu délègues. C'est l'idée du subagent — un agent enfant spécialisé, lancé par le parent, qui retourne une synthèse.

[Section 1 - quand]
Trois signes qu'il faut un subagent. Un : tu dépasses vingt tools dispo. Deux : ton context window se remplit de résultats intermédiaires que le parent n'a pas besoin de voir. Trois : une tâche bien identifiée et auto-contenue revient souvent — par exemple "fais une revue de code" ou "explore ce répertoire".

[Section 2 - interface]
Le subagent reçoit une mission précise, ses propres tools, son propre contexte vierge. Il bosse, il termine, il retourne un résumé court au parent. Le parent ne voit jamais les détails — c'est ça la magie. Le contexte du parent reste compact.

[Section 3 - pièges]
Piège un : sub-sub-sub agents. Au-delà de deux niveaux de profondeur, tu perds en lisibilité et en debug. Piège deux : tu paies les tokens deux fois — parent ET subagent. Mesure. Piège trois : le parent perd le contrôle si le subagent ment ou se trompe — implémente un check de plausibilité.

[Conclusion]
Les subagents sont un outil de réduction de complexité, pas un gadget. À utiliser quand le bénéfice cognitive et token l'emporte sur le coût d'orchestration.`,
      visuals: [
        {
          title: "Parent ↔ Subagent",
          description:
            "Schéma : Agent parent (10 tools, contexte court) → call delegate_to(subagent_X, mission) → Subagent (5 tools spécialisés, contexte propre) → renvoie summary → parent continue.",
        },
        {
          title: "Quand déléguer",
          description:
            "Checklist : > 20 tools / contexte saturé d'intermédiaires / sous-tâche réutilisable / sous-tâche longue qui pollue. Si 2 cases cochées → subagent.",
        },
      ],
      content: `## Le subagent en pattern

\`\`\`python
def delegate_to_subagent(mission: str, agent_type: str) -> str:
    """Spawn a subagent with its own context and tools.
    Returns a concise summary to the parent."""

    sub_tools = TOOL_REGISTRY[agent_type]
    sub_system = SYSTEM_PROMPTS[agent_type]

    result = run_agent(
        user_message=mission,
        system=sub_system,
        tools=sub_tools,
        max_steps=15,
        max_tokens_budget=20_000,
    )

    # Le parent ne voit que ce résumé
    return result["answer"]
\`\`\`

Le **parent** voit uniquement \`{tool: delegate_to_subagent, input: mission, output: summary}\`. Tout le bruit reste dans la sandbox du subagent.

## Quand déléguer (et quand pas)

| Situation | Délégation ? |
|---|---|
| > 20 tools potentiels | ✅ Subagent par domaine |
| Tâche autonome récurrente (review, recherche) | ✅ |
| Contexte parent qui explose | ✅ |
| Tâche simple en 2 étapes | ❌ Surenchère |
| Besoin de garder le détail dans le parent | ❌ |
| Tâche < 5 steps | ❌ Overhead non rentable |

## Interface parent → subagent

Toujours sous forme d'un **tool** dans le parent :

\`\`\`json
{
  "name": "delegate_research",
  "description": "Spawn a research subagent. Use when you need to gather information from multiple sources.\\n\\nReturns a concise summary, not raw data.",
  "input_schema": {
    "type": "object",
    "properties": {
      "mission": {
        "type": "string",
        "description": "Self-contained task description with success criteria"
      },
      "max_sources": {"type": "integer", "default": 5}
    },
    "required": ["mission"]
  }
}
\`\`\`

Le \`mission\` doit être **auto-contenu** — le subagent ne sait rien du parent.

## Anti-patterns

### 1. Profondeur > 2

Subagent → sub-sub-agent → sub-sub-sub-agent. Catastrophe à débugger. Limite : **2 niveaux max**.

### 2. Tokens doublés sans gain

Si ton subagent traite 5k tokens et te rend 200 tokens, mais que tu le fais dans 80% des steps, tu as juste **multiplié ta facture par 5**.

\`\`\`python
# Garde-fou
if estimated_subagent_tokens(mission) < 3000:
    # Ne délègue pas — fais inline
    return inline_handle(mission)
\`\`\`

### 3. Pas de plausibility check

Le subagent peut halluciner. Le parent doit **vérifier** :

\`\`\`python
result = subagent.run(mission)
if not parent.plausibility_check(result, mission):
    return parent.retry_or_fallback()
\`\`\`

## Pattern : pool de subagents spécialisés

\`\`\`
Orchestrator agent
├── researcher subagent (web_search, fetch_url)
├── code_reviewer subagent (read_file, grep, lint)
├── data_analyst subagent (sql, stats, plot)
└── writer subagent (no tools — pure synthesis)
\`\`\`

L'orchestrateur ne fait **que** déléguer. Chaque subagent est expert d'un domaine.

## À retenir

- Subagent = isolation contextuelle + spécialisation.
- Délégue quand : > 20 tools, contexte sature, tâche réutilisable.
- Ne délègue pas pour < 5 steps ou tâche simple — overhead.
- Profondeur max 2 niveaux. Plausibility check au retour.`,
      practice: `**Exercice : orchestrator + 2 subagents**

Construis :
- Un **orchestrator** qui répond à : "Analyse ce repo GitHub et propose 3 améliorations prioritaires."
- Un **explorer subagent** : tools \`list_files\`, \`read_file\`, \`grep\`.
- Un **code_reviewer subagent** : tools \`read_file\`, \`run_linter\`, \`run_tests\`.

L'orchestrator délègue : (1) explorer pour cartographier, (2) reviewer pour analyser les fichiers clés, (3) lui-même synthétise.

Mesure tokens parent vs subagents et compare à un agent monolithique.`,
      quiz: [
        {
          question: "Quel est le principal bénéfice d'utiliser un subagent ?",
          choices: [
            "C'est à la mode",
            "Isolation du contexte (le bruit reste dans le subagent) + spécialisation par domaine",
            "Économie automatique de tokens",
            "Aucun bénéfice",
          ],
          answerIndex: 1,
          explanation:
            "Le parent reste compact, chaque subagent est expert. Le coût total peut monter, mais la complexité par agent baisse.",
        },
        {
          question: "Quelle est la profondeur maximale recommandée pour les subagents ?",
          choices: [
            "Aucune limite",
            "2 niveaux — au-delà, debug devient cauchemardesque",
            "10 niveaux",
            "Toujours 1 seul niveau",
          ],
          answerIndex: 1,
          explanation:
            "Sub-sub-sub-agents sont impossibles à tracer. Limite-toi à parent → subagent.",
        },
        {
          question: "Comment éviter qu'un subagent multiplie ta facture pour rien ?",
          choices: [
            "Croiser les doigts",
            "Estimer les tokens du subagent, ne déléguer que si le bénéfice (contexte/spécialisation) le justifie",
            "Toujours déléguer",
            "Jamais déléguer",
          ],
          answerIndex: 1,
          explanation:
            "Un subagent qui traite 5k tokens pour rendre 200 tokens, multiplié par chaque step, peut décupler ta facture sans ROI.",
        },
      ],
      resources: [
        { label: "Anthropic — Multi-agent research system", href: "https://www.anthropic.com/research/multi-agent-research-system" },
      ],
    },
  ],
};
