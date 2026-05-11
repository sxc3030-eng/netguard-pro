import type { Module } from "../types";

export const module7: Module = {
  slug: "multi-agents",
  index: 7,
  title: "Multi-agents et orchestration",
  tagline: "Quand plusieurs agents valent mieux qu'un",
  description:
    "Patterns d'orchestration : router, supervisor, swarm. Communication, partage d'état, coordination. Construire des systèmes multi-agents qui ne se marchent pas dessus.",
  color: "from-blue-500 to-indigo-600",
  lessons: [
    {
      slug: "orchestration-patterns",
      moduleSlug: "multi-agents",
      index: 1,
      title: "Patterns d'orchestration",
      subtitle: "Router, Supervisor, Pipeline, Swarm — choisir le bon",
      level: "expert",
      durationMin: 16,
      objectives: [
        "Distinguer 4 patterns d'orchestration",
        "Choisir selon la nature du problème",
        "Implémenter chaque pattern minimal",
        "Évaluer le surcoût orchestration vs agent monolithique",
      ],
      vocalScript: `[Intro]
Multi-agents, c'est sexy sur les slides, dangereux en prod. Avant de te lancer, comprends les quatre patterns dominants et choisis le bon. Mal orchestrés, deux agents valent moins qu'un.

[Section 1 - Router]
Router : un agent classifie la requête et la dispatch vers le bon spécialiste. Simple, efficace, sous-estimé. Quatre-vingts pour cent des cas d'usage "multi-agent" sont en fait du routing déguisé.

[Section 2 - Supervisor]
Supervisor : un agent coordinateur orchestre N spécialistes. Il décompose la tâche, alloue les sous-tâches, agrège les résultats. C'est le pattern le plus utilisé en production sérieuse. Anthropic l'utilise pour la recherche.

[Section 3 - Pipeline et Swarm]
Pipeline : agents en série, chacun transforme l'output du précédent. Idéal pour ETL ou content gen. Swarm : agents pairs sans hiérarchie qui se passent le contrôle. Très flexible, très dur à débugger. À réserver aux cas où la nature du problème l'exige vraiment.

[Conclusion]
Ne fais pas du multi-agent par mode. Fais-en quand le bénéfice cognitif ou la parallélisation l'emportent sur l'overhead. Sinon, un bon agent monolithique gagne.`,
      visuals: [
        {
          title: "4 patterns",
          description:
            "Quadrant : Router (1 classifier → N spécialistes), Supervisor (1 coord ↔ N workers), Pipeline (A → B → C), Swarm (réseau pair-à-pair).",
        },
        {
          title: "Décision rapide",
          description:
            "Arbre : tâche bien typée ? → Router. Tâche complexe à décomposer ? → Supervisor. Transformations en cascade ? → Pipeline. Sinon → mono-agent (souvent suffit).",
        },
      ],
      content: `## Pattern 1 : Router

\`\`\`python
async def router(query):
    intent = await classifier_agent.classify(query)
    if intent == "billing":
        return await billing_agent.handle(query)
    elif intent == "technical":
        return await tech_agent.handle(query)
    elif intent == "sales":
        return await sales_agent.handle(query)
\`\`\`

**Cas d'usage** : assistant multi-domaine, support client, dispatch.
**Bénéfice** : chaque spécialiste a un prompt focalisé, ses propres tools, ses propres exemples.
**Coût** : un appel LLM supplémentaire pour la classification (utilise Haiku).

## Pattern 2 : Supervisor (orchestrator-workers)

\`\`\`python
async def supervisor(task):
    plan = await orchestrator.plan(task)  # → list of subtasks
    results = await asyncio.gather(*[
        worker_for(subtask).execute(subtask)
        for subtask in plan
    ])
    return await orchestrator.synthesize(task, results)
\`\`\`

**Cas d'usage** : recherche multi-source, génération de rapport multi-section, code review multi-fichier.
**Bénéfice** : parallélisation native, isolation des contextes.
**Coût** : orchestration ajoute des tokens et de la latence (offset par parallélisation).

C'est le pattern utilisé par les agents de recherche modernes (Anthropic Research, Perplexity, etc.).

## Pattern 3 : Pipeline (sequential)

\`\`\`python
async def pipeline(input):
    extracted = await extract_agent.run(input)
    structured = await structure_agent.run(extracted)
    enriched = await enrich_agent.run(structured)
    return await format_agent.run(enriched)
\`\`\`

**Cas d'usage** : ETL, content generation (draft → edit → polish), data transformation.
**Bénéfice** : chaque agent fait UNE chose, simple à raisonner et tester.
**Coût** : latence cumulée (pas parallélisable par nature).

## Pattern 4 : Swarm

Agents pairs qui se passent le control flow :

\`\`\`python
class Agent:
    def step(self, state) -> tuple[str, dict]:
        # Returns (next_agent_name, updated_state)
        ...

state = initial_state
current = "starter_agent"
while current != "DONE":
    current, state = AGENTS[current].step(state)
\`\`\`

**Cas d'usage** : simulations, jeux, débats agent-vs-agent.
**Bénéfice** : flexibilité maximale, pas de bottleneck central.
**Coût** : très dur à tracer, à débugger, à mesurer. Risque de boucles.

**Verdict** : 95% des cas n'en ont pas besoin. Si tu hésites, n'utilise pas.

## Décider en 30 secondes

| Caractéristique | Pattern |
|---|---|
| Plusieurs domaines distincts | Router |
| Tâche complexe décomposable | Supervisor |
| Transformations en cascade | Pipeline |
| Interactions dynamiques | Swarm (rare) |
| Aucun bénéfice clair | Mono-agent |

## Anti-patterns à fuir

1. **Multi-agent par mode** sans bénéfice mesurable.
2. **Trop d'agents** (> 5 actifs) → coordination explose.
3. **Pas de timeout/budget global** → un agent bloqué fige tout.
4. **Pas de logging cross-agents** → impossible à débugger.
5. **State partagé sans contrat clair** → race conditions.

## À retenir

- 4 patterns : Router (dispatch), Supervisor (decompose), Pipeline (sequence), Swarm (peer).
- Router = sous-estimé, suffit dans 80% des "multi-agent".
- Supervisor = standard pour décomposition.
- Multi-agent = coût d'orchestration → mesure le ROI vs mono-agent.`,
      practice: `**Exercice : router vs supervisor**

Construis :
1. Un **router** support client : classifier (Haiku) + 3 spécialistes (billing, tech, general).
2. Un **supervisor** rapport hebdo : orchestrator + 3 workers (sales metrics, product metrics, support metrics) → synthesizer.

Mesure pour chaque : tokens totaux, latence, qualité.
Compare avec une version mono-agent qui fait tout.

Quel pattern bat le mono-agent ? Pourquoi ?`,
      quiz: [
        {
          question: "Pourquoi un router est-il souvent suffisant alors qu'on parle 'multi-agent' ?",
          choices: [
            "Parce que c'est à la mode",
            "Beaucoup de problèmes 'multi-agent' sont en fait du dispatch — un classifier + spécialistes focalisés",
            "Le router est toujours supérieur",
            "Faux, mono-agent gagne toujours",
          ],
          answerIndex: 1,
          explanation:
            "Le bénéfice 'multi-agent' = isolation contextuelle + spécialisation, qui sont déjà obtenus par un router simple.",
        },
        {
          question: "Quel est le pattern le plus utilisé en production sérieuse pour décomposer une tâche complexe ?",
          choices: [
            "Swarm",
            "Supervisor (orchestrator-workers)",
            "Mono-agent",
            "Pipeline rigide",
          ],
          answerIndex: 1,
          explanation:
            "Supervisor permet décomposition + parallélisation + synthèse contrôlée. Standard de l'industrie pour les agents de recherche, code review, etc.",
        },
        {
          question: "Pourquoi éviter le swarm dans la majorité des cas ?",
          choices: [
            "C'est trop simple",
            "Très dur à débugger, à mesurer, et à empêcher de boucler — overhead opérationnel énorme",
            "Trop cher en compute",
            "Il n'y a pas de SDK",
          ],
          answerIndex: 1,
          explanation:
            "Sans hiérarchie centrale, tu perds la vue d'ensemble. À réserver aux cas où la nature pair-à-pair est intrinsèque (simulations, débats).",
        },
      ],
      resources: [
        { label: "Anthropic — Building Effective Agents", href: "https://www.anthropic.com/research/building-effective-agents" },
        { label: "OpenAI Swarm (reference)", href: "https://github.com/openai/swarm" },
      ],
    },
    {
      slug: "communication-state",
      moduleSlug: "multi-agents",
      index: 2,
      title: "Communication et partage d'état",
      subtitle: "Comment des agents s'échangent l'info sans tout casser",
      level: "expert",
      durationMin: 14,
      objectives: [
        "Choisir un canal de communication (message passing vs shared state)",
        "Définir un contrat d'API entre agents",
        "Gérer la cohérence d'un état partagé",
        "Tracer une conversation multi-agents",
      ],
      vocalScript: `[Intro]
Une fois que tu as plusieurs agents, ils doivent communiquer. C'est ici que ça part en cacahuète si tu ne poses pas de règles. Cette leçon te donne les rails.

[Section 1 - canaux]
Deux modèles. Message passing : agent A appelle agent B comme une fonction, A passe un message, B retourne un résultat. Synchrone, simple, traçable. Shared state : tous les agents lisent et écrivent dans un store commun — mémoire, base, blackboard. Asynchrone, puissant, dangereux.

[Section 2 - contrats]
Pour chaque interaction, définis un contrat : input attendu, output garanti, erreurs possibles. Comme une API. Sinon, agent B reçoit un blob inattendu de A, panique, et tout déraille.

[Section 3 - tracing]
Tracing absolu. Chaque message inter-agent doit avoir : id de session, agent émetteur, agent destinataire, timestamp, contenu, parent message id. Sans ça, debugger une session multi-agents échouée, c'est plonger dans le brouillard.

[Conclusion]
Communication agent à agent = système distribué. Applique les règles des systèmes distribués : contrats, idempotence, observabilité.`,
      visuals: [
        {
          title: "Message passing vs shared state",
          description:
            "À gauche : agent A → message → agent B → reply (RPC-like). À droite : agents A, B, C ↔ blackboard partagé. Pros/cons sous chaque schéma.",
        },
        {
          title: "Trace d'une session multi-agents",
          description:
            "Ligne du temps verticale : t=0 user→supervisor, t=1 supervisor→worker1 (parallel), supervisor→worker2 (parallel), t=2 results, t=3 supervisor synthesize → user. Chaque ligne avec id et tokens.",
        },
      ],
      content: `## Modèle 1 : Message passing (RPC-like)

\`\`\`python
class Message:
    sender: str
    recipient: str
    content: dict
    parent_id: str | None
    session_id: str

async def send(msg: Message) -> Message:
    return await AGENTS[msg.recipient].handle(msg)
\`\`\`

**Avantages** :
- Synchrone, traçable.
- Contrat clair (input → output).
- Pas de race condition.

**Inconvénients** :
- Pas de partage de contexte commun (chaque message contient ce qu'il faut).
- Latence en série si non parallélisé.

C'est le **default**. 90% des multi-agents l'utilisent.

## Modèle 2 : Shared state (blackboard)

\`\`\`python
class SharedState:
    def get(key) -> any: ...
    def set(key, value): ...
    def append(key, value): ...
    def subscribe(key, callback): ...

# Agents lisent/écrivent
state.set("research_findings", findings)
state.append("decisions_log", decision)
\`\`\`

**Avantages** :
- Tous les agents voient la même chose, sans repassage manuel.
- Pattern utile pour des conversations longues (Module 8 : memory).

**Inconvénients** :
- Race conditions, lost updates.
- Couplage fort (changer le schéma casse tout).
- Dur à tester (état mutable).

**Quand l'utiliser** : sessions persistantes longues, mémoire commune (résumés, faits validés).

## Contrats d'API entre agents

\`\`\`json
{
  "input_schema": {
    "type": "object",
    "properties": {
      "task": {"type": "string"},
      "context": {"type": "string", "description": "Background"},
      "deadline_iso": {"type": "string"}
    },
    "required": ["task"]
  },
  "output_schema": {
    "type": "object",
    "properties": {
      "status": {"enum": ["success", "partial", "failed"]},
      "summary": {"type": "string", "maxLength": 500},
      "details": {"type": "object"}
    },
    "required": ["status", "summary"]
  },
  "errors": [
    {"code": "no_data_found", "recovery": "abort and report to user"},
    {"code": "tool_unavailable", "recovery": "retry once then escalate"}
  ]
}
\`\`\`

Ce contrat est **public** entre agents. Tout changement = breaking change versionné.

## Tracing minimal indispensable

\`\`\`json
{
  "session_id": "sess_abc",
  "trace_id": "trace_xyz",
  "events": [
    {"t": 0, "type": "user_input", "content": "..."},
    {"t": 50, "type": "agent_call", "from": "supervisor", "to": "researcher", "msg_id": "m1", "input": {...}},
    {"t": 1200, "type": "agent_response", "from": "researcher", "to": "supervisor", "msg_id": "m1", "tokens": 4500, "output": {...}},
    {"t": 1300, "type": "agent_call", "from": "supervisor", "to": "writer", "msg_id": "m2", ...},
    {"t": 3400, "type": "user_output", "content": "..."}
  ]
}
\`\`\`

Stocke en JSONL ou OTel. Re-jouable, analysable, facturable.

## Patterns de communication avancés

- **Pub/sub** : un agent émet un event, N agents s'abonnent (ex : audit, monitoring).
- **Request/respond timeout** : tout call inter-agent doit timeout.
- **Bulk ops** : éviter d'appeler N fois → un appel batch quand possible.
- **Idempotency keys** : pour les calls qui mutent l'état.

## À retenir

- Message passing par défaut. Shared state seulement si nécessaire.
- Contrat I/O explicite entre chaque paire d'agents.
- Tracing complet de toute interaction (session + parent_id).
- Multi-agent = système distribué — applique les patterns correspondants.`,
      practice: `**Exercice : trace propre**

Sur ton router/supervisor du module précédent :
1. Ajoute un \`session_id\` propagé partout.
2. Logge chaque message inter-agent en JSONL avec : timestamp, sender, recipient, msg_id, parent_id, tokens, latency.
3. Écris un script qui prend un \`session_id\` et reconstruit la timeline visuelle (texte ou Mermaid).

**Bonus** : ajoute un \`trace_id\` plus large qui survit aux retries et republications.`,
      quiz: [
        {
          question: "Pourquoi le message passing est-il le default ?",
          choices: [
            "Plus rapide",
            "Synchrone, traçable, contrat clair, pas de race condition — système simple à raisonner",
            "Imposé par les SDK",
            "Aucune raison",
          ],
          answerIndex: 1,
          explanation:
            "Shared state apporte de la flexibilité au prix d'une complexité (concurrence, schéma) qui n'est pas justifiée dans la majorité des cas.",
        },
        {
          question: "Que doit contenir un trace minimal d'interaction agent ?",
          choices: [
            "Juste le contenu",
            "session_id, msg_id, parent_id, sender, recipient, timestamp, tokens, latency",
            "Le numéro de carte bleue",
            "Rien, on debug à l'œil",
          ],
          answerIndex: 1,
          explanation:
            "Sans ces champs, impossible de reconstruire une session, mesurer un coût, ou identifier la cause d'un échec.",
        },
        {
          question: "Pourquoi versionner les contrats inter-agents ?",
          choices: [
            "Pour le fun",
            "Parce qu'un changement de schéma casse les agents qui consomment — comme une API publique",
            "Pas nécessaire",
            "Juste pour les RH",
          ],
          answerIndex: 1,
          explanation:
            "Multi-agents = mini systèmes distribués. Un agent évolue plus vite que les autres → versionner évite les breaking changes silencieux.",
        },
      ],
      resources: [
        { label: "OpenTelemetry — GenAI semantic conventions", href: "https://opentelemetry.io/docs/specs/semconv/gen-ai/" },
      ],
    },
  ],
};
