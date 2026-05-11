import type { Module } from "../types";

export const module3: Module = {
  slug: "tool-use",
  index: 3,
  title: "Tool Use & Function Calling",
  tagline: "Donner au modèle des super-pouvoirs",
  description:
    "Function calling, parallel tools, error handling, retries, streaming tool use. Le mécanisme qui transforme un chatbot en agent capable d'agir.",
  color: "from-emerald-500 to-teal-500",
  lessons: [
    {
      slug: "function-calling-design",
      moduleSlug: "tool-use",
      index: 1,
      title: "Design des tools : 80% du succès se joue ici",
      subtitle: "Schémas, descriptions, side effects — l'art du tool callable",
      level: "advanced",
      durationMin: 18,
      objectives: [
        "Concevoir un tool que le modèle utilisera correctement",
        "Écrire des descriptions qui réduisent les erreurs de 70%",
        "Choisir entre 1 gros tool ou N petits tools",
        "Gérer les side effects et l'idempotence",
      ],
      vocalScript: `[Intro]
Tout le monde sait écrire un tool. Peu de gens savent en écrire un que le modèle utilise correctement à 95% du temps. Cette leçon te donne les principes qui font la différence.

[Section 1 - schéma]
Un tool, c'est trois choses : un nom, une description, un schéma JSON. Le nom doit être verbe + objet. La description doit dire quand l'utiliser ET quand ne pas l'utiliser. Le schéma doit être minimal : chaque paramètre optionnel est une chance de hallucination.

[Section 2 - granularité]
Le piège classique : un méga-tool "manage_database" avec quinze paramètres. Le modèle se perd. Préfère cinq petits tools focalisés. Mais pas non plus cinquante : à partir de vingt tools, le modèle commence à confondre. Sweet spot : cinq à quinze.

[Section 3 - side effects]
Tout tool qui modifie quelque chose doit être idempotent ou retournable. Le modèle peut retry, le user peut interrompre. Ton tool "send_email" qui envoie deux fois le même mail parce que la première fois a timeout, c'est un incident en prod.

[Conclusion]
Pense tes tools comme des APIs publiques. Documentation claire, idempotence, observabilité. Le modèle est ton meilleur dev junior — donne-lui une bonne SDK.`,
      visuals: [
        {
          title: "Anatomie d'un tool",
          description:
            "Encart JSON : { name: 'verbe_objet', description: '[when to use]\\n[when NOT to use]\\n[examples]', input_schema: {...} }. Annoter chaque champ avec un commentaire de bonne pratique.",
        },
        {
          title: "Granularité optimale",
          description:
            "Courbe en U inversée : qualité d'utilisation vs nombre de tools. Pic entre 5 et 15. Annoter '< 5 = friction, > 20 = confusion'.",
        },
      ],
      content: `## Le tool callable parfait

\`\`\`json
{
  "name": "search_customer_orders",
  "description": "Search orders for a specific customer in the last N days.\\n\\nUse this when:\\n- The user asks about a customer's recent purchases\\n- You need to verify an order before processing a refund\\n\\nDo NOT use this when:\\n- The customer is unknown (use 'find_customer' first)\\n- You need full history (use 'export_customer_history' instead)",
  "input_schema": {
    "type": "object",
    "properties": {
      "customer_id": {
        "type": "string",
        "description": "Internal customer ID, format CUST-XXXXXX"
      },
      "days_back": {
        "type": "integer",
        "description": "How many days to search back from today, max 90",
        "minimum": 1,
        "maximum": 90
      }
    },
    "required": ["customer_id", "days_back"]
  }
}
\`\`\`

Note : la description **dit quand NE PAS utiliser**. C'est le single biggest improvement.

## Les 7 commandements du tool design

1. **Verbe_objet** dans le nom : \`search_orders\`, pas \`orders\` ni \`OrderSearcher\`.
2. **Description = when + when_not + format** des paramètres exotiques.
3. **Minimum de paramètres** — chaque paramètre optionnel est une chance d'erreur.
4. **Type strict** dans le schéma : enums, min/max, regex pattern.
5. **Examples concrets** dans la description si le format n'est pas évident.
6. **Idempotence** quand possible (UUID client-side, dedup serveur).
7. **Erreurs explicites** : retourne \`{"error": "customer_not_found", "suggestion": "use find_customer first"}\`, pas un 500.

## Combien de tools ?

| Nombre | Effet typique |
|---|---|
| 1–3 | Friction, le modèle compense en hallucinant |
| 5–15 | **Sweet spot** |
| 20–50 | Confusion, fautes de routing |
| 50+ | Tu as besoin de **subagents** ou de **tool routing** |

Quand tu dépasses 15, **groupe par domaine** et présente seulement les tools d'un domaine à la fois (gating).

## Side effects et idempotence

\`\`\`python
# ❌ Mauvais
def send_email(to, subject, body):
    smtp.send(to, subject, body)
    return "sent"

# ✅ Bon
def send_email(to, subject, body, idempotency_key):
    if dedup.exists(idempotency_key):
        return {"status": "already_sent", "key": idempotency_key}
    smtp.send(to, subject, body)
    dedup.store(idempotency_key, ttl_hours=24)
    return {"status": "sent", "key": idempotency_key}
\`\`\`

Le modèle **génère** la clé d'idempotence (par ex. hash du contenu) → tu absorbes les retries.

## Pattern : tool result enrichi

Plutôt que \`{"result": "ok"}\`, retourne du contexte exploitable :

\`\`\`json
{
  "result": "ok",
  "next_actions_hint": ["You can now call confirm_payment", "Customer notified"],
  "warnings": ["Stock low on item X"],
  "metadata": {"latency_ms": 230}
}
\`\`\`

Le modèle utilise \`next_actions_hint\` pour planifier la suite. Tu **guides** ses décisions.

## À retenir

- Description = when + when_not + format. Le single biggest lever.
- Sweet spot : 5–15 tools. Au-delà, gate ou subagent.
- Idempotence par défaut sur tout ce qui mute.
- Tool result enrichi pour guider la prochaine étape.`,
      practice: `**Exercice : pipeline de tool design**

Imagine un agent "DevOps assistant". Conçois 6 tools :
1. \`list_pods\` (read)
2. \`describe_pod\` (read)
3. \`fetch_logs\` (read)
4. \`restart_pod\` (write, idempotent)
5. \`scale_deployment\` (write, idempotent)
6. \`apply_manifest\` (write, dangerous)

Pour chacun, écris : nom + description complète (when/when_not) + JSON schema + exemple de tool result enrichi.

**Bonus** : pour \`apply_manifest\`, ajoute un mécanisme de confirmation explicite (champ \`confirm: true\` requis).`,
      quiz: [
        {
          question: "Quelle est la pratique qui améliore le plus la fiabilité d'un tool ?",
          choices: [
            "Mettre une description très longue",
            "Inclure dans la description QUAND utiliser ET QUAND NE PAS utiliser le tool",
            "Utiliser des noms en CamelCase",
            "Mettre tous les paramètres optionnels",
          ],
          answerIndex: 1,
          explanation:
            "Les négations explicites (\"do NOT use this when\") réduisent drastiquement les fautes de routing entre tools.",
        },
        {
          question: "Combien de tools maximum avant de risquer la confusion ?",
          choices: [
            "100",
            "Environ 15–20 ; au-delà, gate par domaine ou délègue à des subagents",
            "3",
            "Aucune limite",
          ],
          answerIndex: 1,
          explanation:
            "Sweet spot 5–15. Entre 20 et 50 tu vois de la confusion ; au-delà, architecture multi-agents.",
        },
        {
          question: "Pourquoi l'idempotence est-elle critique dans les tools ?",
          choices: [
            "C'est une contrainte légale",
            "Parce que le modèle peut retry, et un appel non-idempotent provoque des doubles actions (mails, paiements, etc.)",
            "Pour faire bien sur le CV",
            "Aucune importance en pratique",
          ],
          answerIndex: 1,
          explanation:
            "Retry du modèle + erreurs réseau = situations où le même tool peut être appelé 2 fois. Sans idempotence = incident.",
        },
      ],
      resources: [
        { label: "Anthropic — Tool Use", href: "https://docs.anthropic.com/en/docs/build-with-claude/tool-use" },
        { label: "OpenAI — Function Calling Guide", href: "https://platform.openai.com/docs/guides/function-calling" },
      ],
    },
    {
      slug: "parallel-tools-error-handling",
      moduleSlug: "tool-use",
      index: 2,
      title: "Parallel tools, retries et error handling",
      subtitle: "L'industrialisation du tool use",
      level: "advanced",
      durationMin: 16,
      objectives: [
        "Activer le parallel tool use et mesurer les gains",
        "Concevoir un retry/backoff qui ne casse pas la conversation",
        "Gérer les erreurs réseau, rate-limit, validation",
        "Implémenter un circuit breaker pour les tools instables",
      ],
      vocalScript: `[Intro]
Un tool qui marche en démo et un tool qui tient en prod, c'est deux mondes. Cette leçon couvre la couche industrielle.

[Section 1 - parallel]
Les modèles modernes peuvent émettre plusieurs tool calls dans le même tour. Au lieu de chaîner trois requêtes API, le modèle te dit "appelle ces trois tools en parallèle, je traite les résultats ensemble". Tu divises ta latence par trois. Active-le. Toujours.

[Section 2 - errors]
Un tool plante. Trois options : tu remontes l'erreur au modèle qui retry intelligemment, tu retry toi-même de façon transparente, ou tu fais les deux selon le type d'erreur. Règle : les erreurs transientes (réseau, rate-limit, 5xx) tu retry silencieusement avec backoff. Les erreurs sémantiques (404 customer, validation) tu remontes au modèle qui adaptera son plan.

[Section 3 - circuit breaker]
Quand un tool external est en panne, ne laisse pas l'agent boucler dessus. Un circuit breaker simple : 3 échecs en 30 secondes → off pendant 1 minute. L'agent reçoit "this tool is temporarily unavailable, try alternative X" et adapte. Tu sauves ta facture et la latence user.

[Conclusion]
Les bugs de tool use représentent 60% des incidents prod sur les agents. Investis ici en priorité.`,
      visuals: [
        {
          title: "Sequential vs parallel tools",
          description:
            "Timeline horizontal : Sequential = 3 barres en série (3s). Parallel = 3 barres en parallèle (1s). Annoter '3× speedup'.",
        },
        {
          title: "Politique de retry par type d'erreur",
          description:
            "Tableau : Network/5xx → silent retry exp backoff (3 tentatives). 429 → retry après Retry-After. 4xx validation → remonte au modèle. 404 sémantique → remonte au modèle. Auth → fail fast.",
        },
      ],
      content: `## Parallel tool use

Les API modernes permettent au modèle d'émettre **plusieurs tool_use** dans la même réponse :

\`\`\`json
[
  {"type": "tool_use", "id": "1", "name": "fetch_weather", "input": {"city": "Paris"}},
  {"type": "tool_use", "id": "2", "name": "fetch_traffic", "input": {"city": "Paris"}},
  {"type": "tool_use", "id": "3", "name": "fetch_events", "input": {"city": "Paris"}}
]
\`\`\`

Tu dois les exécuter **vraiment en parallèle** côté serveur :

\`\`\`python
import asyncio

async def execute_tools(tool_uses):
    coros = [run_tool(t.name, t.input) for t in tool_uses]
    results = await asyncio.gather(*coros, return_exceptions=True)
    return [
        {"type": "tool_result", "tool_use_id": t.id, "content": r}
        for t, r in zip(tool_uses, results)
    ]
\`\`\`

Gain typique : **2–4× sur la latence** d'un agent multi-step.

## Retry policy par classe d'erreur

| Erreur | Action | Pourquoi |
|---|---|---|
| Network timeout | Retry silent, backoff exp (1s, 2s, 4s, max 3) | Transient |
| 5xx | Idem | Serveur down/restart |
| 429 rate-limit | Respecte \`Retry-After\` ou backoff | Tu mourras sinon |
| 4xx validation | Remonte au modèle (texte d'erreur clair) | Modèle adapte |
| 404 sémantique | Remonte au modèle | Modèle pivote |
| 401/403 auth | Fail fast, alert | Pas de retry |

\`\`\`python
async def run_tool_safe(name, input):
    for attempt in range(3):
        try:
            return await run_tool(name, input)
        except (TimeoutError, ServerError) as e:
            if attempt == 2:
                return {"error": "transient", "detail": str(e), "retried": 3}
            await asyncio.sleep(2 ** attempt)
        except RateLimitError as e:
            await asyncio.sleep(e.retry_after or 5)
        except ValidationError as e:
            return {"error": "validation", "detail": str(e), "hint": "fix input and retry"}
\`\`\`

## Circuit breaker

\`\`\`python
class CircuitBreaker:
    def __init__(self, threshold=3, window_s=30, cooldown_s=60):
        self.failures = []
        self.opened_at = None
        # ...

    def call(self, fn, *args):
        if self.opened_at and time.time() - self.opened_at < self.cooldown_s:
            return {"error": "circuit_open", "hint": "tool unavailable, use alternative"}
        try:
            result = fn(*args)
            self.failures.clear()
            return result
        except Exception as e:
            self.failures.append(time.time())
            if len(self._recent()) >= self.threshold:
                self.opened_at = time.time()
            raise
\`\`\`

L'agent reçoit le hint et **change de stratégie** au lieu de boucler.

## Tool result format pour les erreurs

Toujours un objet structuré, jamais un string brut :

\`\`\`json
{
  "error": "rate_limited",
  "retry_after_seconds": 12,
  "alternative_tools": ["fetch_cached_weather"],
  "user_message_hint": "Real-time weather temporarily slow, using cached data."
}
\`\`\`

Le \`user_message_hint\` peut être affiché au user pendant que l'agent pivote.

## À retenir

- Parallel tool use = 2–4× speedup, gratuit.
- Politique de retry par classe d'erreur, pas un retry universel.
- Circuit breaker pour éviter les boucles destructrices.
- Tool result toujours structuré, avec hints pour la suite.`,
      practice: `**Exercice : pipeline robuste**

Construis un mini-orchestrateur Python qui :
1. Reçoit une liste de \`tool_uses\` du modèle.
2. Les exécute **en parallèle** (asyncio).
3. Applique la politique de retry par type d'erreur.
4. Intègre un circuit breaker par tool name.
5. Mesure et logge la latence par tool.

**Test** : simule 3 tools (un sain, un qui rate-limit, un qui plante 1 fois sur 2) et vérifie que ton agent ne boucle pas.`,
      quiz: [
        {
          question: "Quel est le gain typique de l'activation du parallel tool use ?",
          choices: [
            "10%",
            "2 à 4× de speedup sur les agents multi-step",
            "Aucun",
            "Variable et imprévisible",
          ],
          answerIndex: 1,
          explanation:
            "Trois tool calls qui auraient pris 3s en série prennent ~1s en parallèle. Sur un agent de 5 steps, l'effet est massif.",
        },
        {
          question: "Comment gérer un retour 4xx de validation d'un tool ?",
          choices: [
            "Retry silencieusement",
            "Crash l'agent",
            "Remonter l'erreur au modèle pour qu'il adapte son input",
            "Ignorer",
          ],
          answerIndex: 1,
          explanation:
            "Les erreurs sémantiques sont des feedback. Le modèle peut corriger son input et réessayer intelligemment.",
        },
        {
          question: "À quoi sert un circuit breaker dans un agent ?",
          choices: [
            "À couper le courant",
            "À empêcher l'agent de boucler indéfiniment sur un tool en panne et lui suggérer une alternative",
            "À chiffrer les communications",
            "À gérer les permissions",
          ],
          answerIndex: 1,
          explanation:
            "Sans CB, un tool down peut faire boucler l'agent → coût + latence + UX dégradée. Avec CB, l'agent pivote.",
        },
      ],
      resources: [
        { label: "Anthropic — Parallel Tool Use", href: "https://docs.anthropic.com/en/docs/build-with-claude/tool-use" },
        { label: "Martin Fowler — Circuit Breaker", href: "https://martinfowler.com/bliki/CircuitBreaker.html" },
      ],
    },
  ],
};
