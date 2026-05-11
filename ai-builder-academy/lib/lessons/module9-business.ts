import type { Module } from "../types";

export const module9: Module = {
  slug: "business-scale",
  index: 9,
  title: "Business, coût et scale",
  tagline: "Construire un produit IA qui survit au million d'users",
  description:
    "Optimisation des coûts, latence, scaling, déploiement, pricing model, business case. Du POC viable au produit profitable.",
  color: "from-yellow-500 to-amber-500",
  lessons: [
    {
      slug: "cost-latency-optimization",
      moduleSlug: "business-scale",
      index: 1,
      title: "Optimiser coût et latence sans sacrifier la qualité",
      subtitle: "Les 7 leviers à appliquer dans l'ordre",
      level: "expert",
      durationMin: 16,
      objectives: [
        "Identifier les 7 leviers d'optimisation",
        "Appliquer dans le bon ordre (ROI décroissant)",
        "Mesurer l'impact de chaque levier",
        "Choisir entre stream, batch, async selon l'UX",
      ],
      vocalScript: `[Intro]
Tu as un agent qui marche. Maintenant, il faut qu'il scale sans ruiner la boîte ni faire fuir les users avec sa lenteur. Cette leçon te donne sept leviers, par ordre de ROI.

[Section 1 - les 7 leviers]
Levier un : prompt caching, premier réflexe, x10 d'économie sur les préfixes stables. Levier deux : routing modèle, Haiku pour 70% des cas, Sonnet pour 25, Opus pour 5. Levier trois : streaming, ne pas changer le coût mais l'UX perçue. Levier quatre : compression du contexte — resume, drop, summarize. Levier cinq : batch API, divise par deux le coût pour les workflows asynchrones. Levier six : structured output minimal, économise output tokens. Levier sept : caching applicatif des réponses pour requêtes identiques.

[Section 2 - ordre]
Applique-les dans l'ordre. Caching d'abord, routing ensuite, le reste après. Mesure après chaque.

[Section 3 - latence vs coût]
Streaming améliore la latence perçue mais pas réelle. Batch API double la latence mais halve le coût. Tu choisis selon ton UX. Pour un chat live, streaming. Pour un nightly job, batch.

[Conclusion]
L'optim n'est pas une question d'ingénierie héroïque. C'est l'application disciplinée de patterns connus. Les sept leviers, dans l'ordre, te divisent typiquement la facture par cinq à dix.`,
      visuals: [
        {
          title: "7 leviers ROI",
          description:
            "Bar chart horizontal classé par ROI : 1. Prompt caching (10×), 2. Model routing (3-5×), 3. Streaming (UX), 4. Context compression (2×), 5. Batch API (2×), 6. Structured output minimal (1.3×), 7. App-level cache (variable).",
        },
        {
          title: "Latence perçue vs réelle",
          description:
            "2 timelines : Sans streaming (waiting 5s puis tout) vs Avec streaming (premier token à 0.5s, fin à 5s). Annotation 'même coût, perception très différente'.",
        },
      ],
      content: `## Les 7 leviers, par ordre de ROI

### 1. Prompt caching (×10 sur les préfixes)
Vu Module 1.2. Premier réflexe sur tout système qui réutilise un prompt long.

### 2. Model routing (×3 à ×5)
Vu Module 1.3. Classe → dispatch.

\`\`\`python
def route(query):
    if simple(query): return haiku.run(query)
    if complex(query): return opus.run(query)
    return sonnet.run(query)
\`\`\`

### 3. Streaming (UX, pas coût)
Affiche les tokens dès qu'ils arrivent. La latence p99 ne change pas, mais le **time to first token** chute. UX gagnante.

\`\`\`python
async for chunk in client.messages.stream(...):
    yield chunk.text
\`\`\`

### 4. Compression de contexte (×2)
Pour les conversations longues :

\`\`\`python
# Garde les 5 derniers messages full + résumé des plus anciens
if len(messages) > 10:
    summary = await summarize(messages[:-5])
    messages = [{"role": "system", "content": summary}] + messages[-5:]
\`\`\`

Variantes : drop les tool_results vieux, résume par fenêtre glissante.

### 5. Batch API (×2 sur le coût, ×2 sur la latence)
Anthropic et OpenAI proposent une **batch API** : tu envoies des milliers de requêtes async, traitées sous 24h, 50% moins cher.

**Pour quoi** : traitements offline (étiquetage, ETL, gen de résumés en masse).

### 6. Structured output minimal
\`\`\`json
// ❌ Trop verbeux
{"reasoning": "...", "step_by_step": [...], "answer": "..."}

// ✅ Minimal pour l'usage
{"answer": "..."}
\`\`\`

Si tu n'utilises pas un champ, ne le demande pas. Chaque token output est facturé 4-5× l'input.

### 7. App-level cache
Cache **applicatif** sur (input_hash → response) avec TTL.

\`\`\`python
def cached_complete(prompt, ttl=3600):
    h = hash(prompt)
    if cached := redis.get(h):
        return cached
    r = llm.complete(prompt)
    redis.setex(h, ttl, r)
    return r
\`\`\`

Pour requêtes répétitives (FAQ, classifications stables, lookups).

## Ordre d'application

1. **Caching** d'abord (simple, énorme).
2. **Routing** ensuite (effort moyen, gain énorme).
3. **Streaming** si UX live.
4. **Compression** si conversations longues.
5. **Batch** si workflows offline.
6. **Output minimal** sur les hot paths.
7. **App-level cache** en dernier (effet variable).

Mesure **après chaque**. Empile les gains.

## Quand choisir batch vs sync vs streaming

| Cas | Choix |
|---|---|
| Chat live, user attend | Streaming |
| Form submit, < 5s acceptable | Sync |
| Bulk processing, pas de user | Batch (×2 moins cher) |
| Long-running task | Async + webhook |

## Pattern : le "fastpath"

Pour les requêtes les plus fréquentes (Pareto), construit un fastpath :

\`\`\`python
async def handle(query):
    # Try fastpath: regex/heuristic/cache
    if fp := fastpath_match(query):
        return fp  # < 50ms, $0
    # Fallback to LLM
    return await llm_path(query)
\`\`\`

Souvent 50% du trafic peut être traité sans LLM.

## À retenir

- 7 leviers, par ordre de ROI : cache, routing, streaming, compression, batch, output minimal, app cache.
- Applique dans l'ordre, mesure entre chaque.
- Streaming pour UX, batch pour coût offline.
- Le fastpath sans LLM = optimisation sous-estimée.`,
      practice: `**Exercice : audit + optim**

Sur ton agent :
1. Mesure baseline : coût/req, latency p50/p99, tokens.
2. Active prompt caching → mesure.
3. Mets en place routing 3 modèles → mesure.
4. Identifie le pareto des requêtes → fastpath les top 5 → mesure.
5. Compresse le contexte sur les sessions > 10 messages → mesure.

Tableau final : levier × métriques × delta.

Cible : **divise la facture par 5** (typique avec ces 4 leviers bien faits).`,
      quiz: [
        {
          question: "Quel est le levier d'optim au plus haut ROI typique ?",
          choices: [
            "Réécrire en C++",
            "Activer le prompt caching sur les préfixes stables",
            "Changer de provider chaque mois",
            "Augmenter le budget marketing",
          ],
          answerIndex: 1,
          explanation:
            "Caching = effort minimal pour ×10 d'économie sur la portion cachée. Aucun autre levier n'a ce ratio.",
        },
        {
          question: "Le streaming améliore quoi exactement ?",
          choices: [
            "Le coût",
            "La latence perçue (time to first token), pas le coût ni la latence totale",
            "La précision",
            "Rien",
          ],
          answerIndex: 1,
          explanation:
            "Streaming = UX. Le user voit du texte arriver en 500ms au lieu d'attendre 5s. Mais total tokens et latency reste le même.",
        },
        {
          question: "Quand utiliser la batch API ?",
          choices: [
            "Pour le chat live",
            "Pour les workflows offline / async — gain ×2 sur le coût, latence acceptable",
            "Jamais",
            "Toujours",
          ],
          answerIndex: 1,
          explanation:
            "Batch = traité sous quelques heures. Idéal pour ETL, étiquetage, batch enrichment. Pas pour le live.",
        },
      ],
      resources: [
        { label: "Anthropic — Batch API", href: "https://docs.anthropic.com/en/docs/build-with-claude/batch-processing" },
        { label: "Anthropic — Prompt Caching", href: "https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching" },
      ],
    },
    {
      slug: "deployment-business",
      moduleSlug: "business-scale",
      index: 2,
      title: "Déploiement, pricing model et business case",
      subtitle: "De ton repo à un produit profitable",
      level: "expert",
      durationMin: 14,
      objectives: [
        "Choisir une stack de déploiement (serverless vs container)",
        "Concevoir un pricing model qui couvre les coûts API",
        "Construire un business case AI feature en 1 page",
        "Anticiper les pièges legal/compliance",
      ],
      vocalScript: `[Intro]
Tu sais construire. Tu sais évaluer. Tu sais sécuriser. Reste à transformer ton agent en produit qui rapporte. Cette dernière leçon te donne le cadre.

[Section 1 - déploiement]
Trois stacks dominantes. Serverless — Vercel, Cloudflare Workers, AWS Lambda — idéal pour latence variable et trafic irrégulier. Container — Fly.io, Railway, ECS — pour processes longs ou besoin de stateful. Edge — Cloudflare AI, Vercel AI — pour latence ultra basse. Choisis selon ton trafic et ton budget DevOps.

[Section 2 - pricing]
Erreur classique : facturer au mois fixe alors que les coûts API sont variables. Trois modèles à connaître. Usage-based — tu factures à la requête ou au token, transparence pour le user, marge stable pour toi. Tiered — packages avec quotas, simple à comprendre, marge moyenne. Hybrid — abo + dépassement, le plus rentable en 2025. Règle d'or : ta marge brute après coût API doit dépasser soixante pour cent, sinon tu n'as pas de business.

[Section 3 - business case]
Un business case AI feature tient sur une page. Problème user, solution, coût construction, coût opérationnel, revenue uplift, payback. Si tu ne peux pas le résumer, tu n'as pas de business case, tu as un POC.

[Conclusion]
La meilleure tech ne sauve pas un mauvais business model. Mais une bonne tech avec un bon model, c'est imbattable. Tu as maintenant les deux. À toi de jouer.`,
      visuals: [
        {
          title: "3 stacks de déploiement",
          description:
            "Tableau : Serverless / Container / Edge. Pour chaque : latence cold-start, coût, complexité, cas d'usage.",
        },
        {
          title: "Business case 1-pager",
          description:
            "Template visuel : Problem | Solution | Build cost | Op cost (coût API/mois) | Revenue uplift | Payback (mois). Avec exemple chiffré.",
        },
      ],
      content: `## Stacks de déploiement

### Serverless (Vercel, CF Workers, Lambda)
**Pour** : trafic irrégulier, faible budget DevOps, équipes front-end.
**Contre** : cold start, timeout (~10-15min max), pas de WebSocket long.

### Container (Fly.io, Railway, ECS, GKE)
**Pour** : process longs, stateful, WebSocket, contrôle fin.
**Contre** : DevOps non-trivial.

### Edge AI (CF AI, Vercel AI Gateway)
**Pour** : latence < 100ms, géo-distribué, modèles edge.
**Contre** : modèles plus limités, coûts spécifiques.

**Mon conseil** : commence en serverless (Vercel ou Workers) → migre quand tu hits un mur.

## Pricing models

### Usage-based
\`\`\`
$0.05 par requête, ou $1 par 100 messages
\`\`\`
**Pour** : transparence, marge stable, segments power-users.
**Contre** : friction d'adoption, prévisibilité difficile pour user.

### Tiered (subscription)
\`\`\`
Free: 50 req/mo
Pro: $20/mo, 1000 req
Enterprise: $200/mo, illimité (fair use)
\`\`\`
**Pour** : simplicité, recurrence stable.
**Contre** : risque marge si quelques heavy users.

### Hybrid (subscription + overage)
\`\`\`
Pro: $20/mo, 1000 req inclues, $0.05 au-delà
\`\`\`
**Le standard 2025** pour produits IA. Adopte ça.

## La règle des 60%

\`\`\`
marge_brute = (revenue - coût_API - coût_infra) / revenue
\`\`\`

Cible : **> 60%**. En dessous, tu finances la croissance avec ton runway. Au-dessus, tu peux investir.

Exemple :
- Plan Pro $20/mo, 1000 req incluses
- Coût API moyen par req : $0.005 → 1000 req = $5
- Coût infra dilué : $1
- Marge brute = ($20 - $5 - $1) / $20 = **70%** ✅

Si tes users dépassent 1500 req sur l'inclusivité, ta marge passe à 50%. Mets de l'overage à $0.05 → tu reprends de la marge.

## Business case en 1 page

\`\`\`
PROBLEM
  Les chargés de support passent 30 min/ticket sur les classifs.
  10 chargés × 50 tickets/jour × 30 min × 2 min de gain × 250 jours
  = 41 666 h économisées/an

SOLUTION
  Agent IA qui pre-classifie + suggère 3 réponses templated.

BUILD COST
  6 sem × 1 dev senior = ~$30 000

OPERATING COST
  500 000 req/an × $0.005 = $2 500 / an

REVENUE / SAVINGS UPLIFT
  41 666 h × €30/h = €1 250 000 économisés/an

PAYBACK
  $30k / €1.25M = < 1 mois

RISKS
  - Adoption (training change mgmt)
  - Hallucinations sur nouveaux types de tickets (mitigation: human review obligatoire sur "low confidence")
\`\`\`

Si ton business case ne tient pas sur 1 page, **simplifie** la feature ou abandonne.

## Pièges legal / compliance

- **RGPD** : lieu de traitement des données, sous-traitance, droit à l'effacement.
- **AI Act (EU)** : obligations selon la classe de risque de ton agent.
- **Data residency** : certains clients exigent EU-only ou US-only.
- **Logging des décisions** : pour les use cases critiques (RH, médical, financier).
- **Output disclaimer** : "Cette réponse est générée par IA, vérifiez les informations critiques."

Faits par défaut, simples, **avant** d'avoir 100 clients.

## Roadmap perso post-formation

1. Choisis 1 problème réel autour de toi.
2. Build POC en 2 semaines avec ce que tu as appris.
3. Mesure (eval set + observability dès le jour 1).
4. Mets en prod auprès de 5 utilisateurs.
5. Itère sur leurs retours.
6. Décide : scale ou pivot.

Répète. Tu as maintenant la boucle d'un AI builder pro.

## À retenir

- Serverless par défaut, container quand tu sais pourquoi.
- Pricing hybrid (sub + overage) = standard 2025.
- Marge brute > 60% non négociable.
- Business case en 1 page ou pas de feature.
- Compliance pas après-coup — fais-le pendant le build.`,
      practice: `**Exercice final : ton 1-pager**

Choisis une feature IA que tu veux construire. Rédige un business case 1-pager :
1. Problem (1 paragraphe)
2. Solution (1 paragraphe)
3. Build cost (estimation honnête)
4. Operating cost (calcul tokens × prix × volume)
5. Revenue / savings uplift (chiffré)
6. Payback period
7. Risks + mitigations

Soumets-le à 2 personnes (mentor, peer, decision maker). Itère.

C'est ton **livrable de fin de formation**.`,
      quiz: [
        {
          question: "Quel pricing model est devenu standard pour les produits IA en 2025 ?",
          choices: [
            "Usage-based pur",
            "Hybrid : subscription avec quota + overage par-dessus",
            "Gratuit, on ferme la boîte ensuite",
            "Une seule transaction lifetime",
          ],
          answerIndex: 1,
          explanation:
            "Subscription = recurrence et prédictibilité. Overage = protection marge sur power users. Le combo gagnant.",
        },
        {
          question: "Quelle marge brute minimale viser ?",
          choices: [
            "20%",
            "60% ou plus — sinon tu finances la croissance avec ton runway",
            "5%",
            "Aucune importance",
          ],
          answerIndex: 1,
          explanation:
            "En dessous de 60%, chaque user supplémentaire t'appauvrit. Au-dessus, tu peux investir dans la croissance.",
        },
        {
          question: "À quel moment penser RGPD / AI Act / compliance ?",
          choices: [
            "Quand le premier client le demande",
            "Pendant le build, par défaut, simple — c'est moins cher que rétro-fitter",
            "Jamais",
            "Quand l'avocat envoie une facture",
          ],
          answerIndex: 1,
          explanation:
            "Compliance baked-in coûte 10× moins que rétro-fittée. Et te débloque les ventes enterprise dès le jour 1.",
        },
      ],
      resources: [
        { label: "EU AI Act résumé", href: "https://artificialintelligenceact.eu/" },
        { label: "Anthropic — Trust Center", href: "https://trust.anthropic.com/" },
      ],
    },
  ],
};
