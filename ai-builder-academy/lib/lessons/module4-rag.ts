import type { Module } from "../types";

export const module4: Module = {
  slug: "rag",
  index: 4,
  title: "RAG avancé : pipelines de production",
  tagline: "Retrieval-Augmented Generation, du jouet au système robuste",
  description:
    "Chunking strategies, embeddings, hybrid search, reranking, evaluation. Construire un pipeline RAG qui répond juste, vite, et sans hallucinations.",
  color: "from-orange-500 to-pink-500",
  lessons: [
    {
      slug: "chunking-strategies",
      moduleSlug: "rag",
      index: 1,
      title: "Chunking : la fondation du RAG",
      subtitle: "80% des bugs RAG viennent d'un mauvais chunking",
      level: "advanced",
      durationMin: 18,
      objectives: [
        "Comprendre l'impact du chunking sur recall et précision",
        "Choisir entre chunking fixe, sémantique, hierarchical, late chunking",
        "Implémenter un chunker robuste avec overlap et metadata",
        "Mesurer la qualité de chunking avant l'embedding",
      ],
      vocalScript: `[Intro]
Quand un RAG renvoie n'importe quoi, neuf fois sur dix le coupable c'est le chunking. Pas l'embedding model, pas le prompt — le chunking. C'est la fondation invisible. Cette leçon te transforme en architecte de chunking.

[Section 1 - pourquoi]
Un chunk, c'est un morceau de document que tu vas embedder et stocker. Sa taille et ses frontières déterminent ce que ton retrieval pourra "voir". Un chunk trop gros : tu ramènes du bruit. Trop petit : tu coupes le contexte au milieu d'une phrase. Trop arbitraire : tu sépares la question de sa réponse.

[Section 2 - stratégies]
Quatre stratégies à connaître. Fixed-size, le plus simple : 500 tokens, 100 d'overlap. Suffit pour 80% des cas. Sémantique : tu coupes aux frontières de paragraphe ou de section. Hierarchical : tu stockes plusieurs niveaux — chunk fin pour le retrieval, parent plus large pour le contexte. Late chunking : technique 2024 où tu embeddes le doc entier puis tu chunks dans l'espace embedding. Niveau expert.

[Section 3 - metadata]
Chaque chunk doit porter sa metadata : source, titre, section, date, type. Cette metadata sert au filtering avant retrieval (date, type) et au reranking après (section, score). Sans metadata, tu cherches une aiguille dans un foin homogène.

[Conclusion]
Règle absolue : avant d'optimiser ton modèle, optimise ton chunking. C'est la stratégie ROI maximum.`,
      visuals: [
        {
          title: "4 stratégies de chunking",
          description:
            "4 schémas côte à côte : Fixed (rectangles égaux), Semantic (rectangles variables suivant titres), Hierarchical (arbre 3 niveaux), Late chunking (vecteur global puis pooling local). Annotations pros/cons.",
        },
        {
          title: "Anatomie d'un chunk",
          description:
            "Encart : { text: '...', embedding: [...], metadata: {source, section, page, date, doc_type, chunk_id, parent_id} }. Mettre 'metadata' en surbrillance.",
        },
        {
          title: "Impact overlap sur recall",
          description:
            "Courbe : recall vs % d'overlap. Pic à ~15-20%. Au-delà, gain marginal et coût stockage explose.",
        },
      ],
      content: `## Pourquoi le chunking domine tout

Le pipeline RAG : Document → **Chunk** → Embed → Store → Retrieve → Rerank → Generate.

Si le chunking est mauvais, tout le reste compense — mal et cher. Investis ici **avant** d'optimiser embeddings ou prompts.

## Les 4 stratégies à connaître

### 1. Fixed-size chunking

\`\`\`python
def chunk_fixed(text, size=500, overlap=100):
    tokens = tokenize(text)
    chunks = []
    for i in range(0, len(tokens), size - overlap):
        chunks.append(detokenize(tokens[i:i+size]))
    return chunks
\`\`\`

**Pour qui** : 80% des cas. Démarre toujours par là.
**Bons defaults** : 400–800 tokens, overlap 10–20%.

### 2. Semantic chunking

Coupe aux frontières naturelles : sections markdown, paragraphes, fins de phrases.

\`\`\`python
def chunk_semantic(markdown):
    sections = re.split(r'\\n(?=#{1,3} )', markdown)
    return [s.strip() for s in sections if s.strip()]
\`\`\`

**Pour qui** : docs structurés (markdown, HTML, légal, API docs).
**Risque** : sections de tailles très inégales → normalize avec un cap (split si > 1500 tok).

### 3. Hierarchical chunking (parent-child)

Tu stockes 2 niveaux :
- **Petits chunks** (200 tok) → utilisés pour le retrieval (précis)
- **Parents** (1500 tok) → injectés dans le prompt (contexte)

\`\`\`python
class HierarchicalIndex:
    def index(self, doc):
        parents = chunk_semantic(doc)
        for p in parents:
            parent_id = store_parent(p)
            children = chunk_fixed(p, size=200, overlap=20)
            for c in children:
                store_child(c, parent_id=parent_id)

    def retrieve(self, query, k=5):
        children = vector_search(query, k=k*3)
        parent_ids = unique([c.parent_id for c in children])[:k]
        return [get_parent(pid) for pid in parent_ids]
\`\`\`

**Effet** : précision du retrieval + richesse du contexte. **Best ROI** sur des bases > 10k docs.

### 4. Late chunking (technique 2024)

Tu embeddes le **document entier** dans un long-context embedding model (ex: Jina v3, Cohere v4), puis tu **pool** les vecteurs par chunk. Avantage : chaque chunk garde la **conscience du contexte global**.

**Pour qui** : docs où le contexte global compte (rapports, contrats, articles longs).

## Metadata : le multiplicateur

\`\`\`python
chunk = {
    "id": "uuid",
    "text": "...",
    "embedding": [...],
    "metadata": {
        "source": "knowledge_base/v2/contracts/2024_q3.pdf",
        "section": "Article 4 — Confidentialité",
        "page": 12,
        "doc_type": "contract",
        "date": "2024-09-15",
        "lang": "fr",
        "parent_id": "abc123",
    },
}
\`\`\`

Tu pourras :
- **Filtrer** avant search : \`where date > 2024-01-01 AND doc_type = 'contract'\`
- **Booster** au reranking : section pertinente = +0.1 score
- **Citer** la source précise dans la réponse

Sans metadata, ton RAG est aveugle.

## Pièges classiques

1. **Chunks trop gros** (> 2000 tok) → noyade d'info, le LLM rate la pépite.
2. **Pas d'overlap** → coupures qui séparent la question de la réponse.
3. **Pas de metadata** → impossible de filtrer/citer.
4. **Chunking unique** pour tous types de docs → un chunker par type (PDF, code, transcript, ticket).

## À retenir

- Chunking = fondation. 80% des bugs RAG y résident.
- Démarre fixed-size 500/100, mesure, puis monte en sophistication si besoin.
- Hierarchical (parent-child) = best ROI dès que la base est sérieuse.
- Metadata systématique. Sans elle, pas de filtering ni citation propre.`,
      practice: `**Exercice pipeline #1 : compare 3 stratégies**

1. Prends 50 documents (PDF, markdown, ou export Notion).
2. Construis 3 indexes : fixed, semantic, hierarchical.
3. Définis 20 questions de test (avec réponses connues).
4. Mesure pour chaque stratégie :
   - **Recall@5** : la réponse est-elle dans le top 5 ?
   - **Precision@5** : combien des 5 sont pertinents ?
   - **Latence** retrieval
   - **Coût** stockage embeddings
5. Choisis la meilleure pour ton cas.

**Bonus** : ajoute la metadata \`section\` et \`date\`, vérifie le gain en filtering.`,
      quiz: [
        {
          question: "Quelle est la première variable à optimiser dans un pipeline RAG ?",
          choices: [
            "Le prompt final",
            "Le chunking — c'est la fondation, 80% des bugs y résident",
            "Le modèle d'embedding",
            "Le LLM générateur",
          ],
          answerIndex: 1,
          explanation:
            "Un mauvais chunking ne se rattrape pas en aval. Embeddings et reranking ne peuvent pas inventer de l'info coupée.",
        },
        {
          question: "Quel overlap typique entre chunks pour un fixed-size 500 tokens ?",
          choices: [
            "0% (pas d'overlap)",
            "10–20% (50–100 tokens) — sweet spot recall vs coût",
            "80%",
            "100%",
          ],
          answerIndex: 1,
          explanation:
            "Un peu d'overlap évite les coupures malheureuses ; trop fait exploser le stockage sans gain.",
        },
        {
          question: "Avantage principal du hierarchical chunking ?",
          choices: [
            "C'est plus simple",
            "Précision du retrieval (petits chunks) ET richesse du contexte injecté (parents)",
            "C'est gratuit",
            "Aucun avantage",
          ],
          answerIndex: 1,
          explanation:
            "Tu cherches sur petit (précis) et tu injectes le grand (contexte) — le best of both worlds.",
        },
      ],
      resources: [
        { label: "LlamaIndex — Chunking strategies", href: "https://docs.llamaindex.ai/en/stable/optimizing/production_rag/" },
        { label: "Late Chunking (Jina AI)", href: "https://jina.ai/news/late-chunking-in-long-context-embedding-models/" },
      ],
    },
    {
      slug: "embeddings-hybrid-search",
      moduleSlug: "rag",
      index: 2,
      title: "Embeddings et hybrid search",
      subtitle: "Vectoriel seul ne suffit pas — ajoute BM25",
      level: "advanced",
      durationMin: 16,
      objectives: [
        "Choisir un modèle d'embedding (closed vs open)",
        "Comprendre pourquoi BM25 reste compétitif",
        "Implémenter hybrid search (vector + lexical) avec RRF",
        "Mesurer le gain réel sur ton dataset",
      ],
      vocalScript: `[Intro]
Vectoriel pur, c'est le piège de débutant. Tu as un beau retrieval sémantique mais tu rates les requêtes qui contiennent des noms propres, des codes produit, des termes rares. La solution : hybrid search. Cette leçon te montre comment.

[Section 1 - embeddings]
Un embedding c'est un vecteur, typiquement 768 ou 1536 dimensions, qui représente le sens d'un texte. Deux textes similaires → vecteurs proches. Modèles à connaître : OpenAI text-embedding-3, Cohere embed-v4, Voyage AI, Jina v3. Tous bons. Le choix se fait sur trois critères : qualité sur ton domaine, coût, taille du vecteur.

[Section 2 - BM25]
BM25, c'est un algorithme statistique des années 90 basé sur la fréquence de termes. Vieux, simple, et incroyablement compétitif. Là où le vectoriel rate les requêtes type "ERR-4042" ou "Schmidt", BM25 trouve. C'est complémentaire, pas concurrent.

[Section 3 - RRF]
Reciprocal Rank Fusion, ou RRF : tu lances la requête sur les deux moteurs en parallèle, tu combines les rankings avec une formule simple — un sur k plus le rang. Pas besoin de scores normalisés. C'est la méthode standard pour fusionner.

[Conclusion]
Vectoriel + BM25 + RRF : c'est le baseline minimum d'un RAG sérieux. Personne ne fait du pur vectoriel en prod.`,
      visuals: [
        {
          title: "Vector vs BM25 vs Hybrid",
          description:
            "Tableau 3 colonnes × 3 lignes : Forces / Faiblesses / Cas idéal. Vector excelle sémantique, BM25 sur termes rares/exacts, Hybrid combine.",
        },
        {
          title: "Reciprocal Rank Fusion",
          description:
            "Schéma : Query → [Vector results: doc A=1, B=2, C=3] + [BM25 results: doc B=1, D=2, A=3] → RRF formula 1/(k+rank) → fused: B, A, D, C.",
        },
      ],
      content: `## Modèles d'embedding (2025)

| Modèle | Dim | Force | Coût |
|---|---|---|---|
| OpenAI text-embedding-3-large | 3072 | Polyvalent, anglais excellent | $0.13/M |
| Cohere embed-v4 | 1024 | Multilingue fort, reranking pair | $0.10/M |
| Voyage AI voyage-3 | 1024 | Top sur retrieval bench | $0.06/M |
| Jina v3 | 1024 | Open weights, late chunking | self-host |
| BGE-M3 (open) | 1024 | Multilingue + multitask | self-host |

**Critères de choix** :
1. **Domaine** : teste sur **tes** docs, pas le MTEB général.
2. **Multilingue ?** Cohere et BGE excellent ; OpenAI bon mais pas top.
3. **Coût + dim** : 1024 dims est le sweet spot. 3072 = 3× le stockage pour ~5% de gain.

## Pourquoi BM25 ne meurt pas

Vector search rate :
- Codes/IDs : "ERR-4042", "SKU-9981"
- Noms propres rares : "Iulianna Vergniaud"
- Acronymes : "GDPR", "K8s"
- Mots-clés exacts : "EXACTLY this phrase"

BM25 excelle là-dessus. Algorithme :

\`\`\`
score(D, Q) = Σ IDF(qi) × (tf(qi, D) × (k+1)) / (tf(qi, D) + k × (1 - b + b × |D|/avgdl))
\`\`\`

Bibliothèques : \`rank_bm25\` (Python), Elasticsearch BM25, Tantivy, Lucene.

## Hybrid search avec RRF

\`\`\`python
def reciprocal_rank_fusion(rankings, k=60):
    """rankings: list of [doc_id1, doc_id2, ...] from each retriever"""
    scores = {}
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            scores[doc_id] = scores.get(doc_id, 0) + 1 / (k + rank)
    return sorted(scores.items(), key=lambda x: -x[1])

def hybrid_search(query, k=10):
    vec_results = vector_search(query, k=k*2)
    bm25_results = bm25_search(query, k=k*2)
    fused = reciprocal_rank_fusion([vec_results, bm25_results])
    return fused[:k]
\`\`\`

Pas besoin de normaliser les scores. \`k=60\` est le default consacré.

**Gain typique vs vector seul** : +10 à +25% sur recall@10. Énorme.

## Patterns avancés

- **Query expansion** : reformule la query avec un LLM (3 variantes), search sur chacune, RRF.
- **Multi-query embeddings** : embeddings différents (asymmetric retrieval) — un pour query, un pour document.
- **Pre-filtering** : applique les filtres metadata avant search pour éviter de chercher dans tout l'index.

## Stack recommandée

| Composant | Choix éprouvé |
|---|---|
| Vector store | Qdrant, Weaviate, pgvector (si Postgres déjà) |
| Lexical | Elasticsearch, OpenSearch, Tantivy |
| Tout-en-un | Vespa (vector + BM25 natif), Weaviate (BM25 intégré) |

Si tu débutes : **Qdrant + rank_bm25** locaux, ou **Weaviate** managed.

## À retenir

- Pur vectoriel = perte sur termes rares et noms propres.
- BM25 reste compétitif après 30 ans, complémentaire au vectoriel.
- Hybrid search avec RRF = baseline minimum, +10–25% recall.
- Choisis ton embedding sur **tes** données, pas sur les leaderboards.`,
      practice: `**Exercice pipeline #2 : hybrid search bench**

Reprends ton dataset de l'exercice #1 :
1. Implémente \`vector_search\` (avec OpenAI ou local).
2. Implémente \`bm25_search\` avec \`rank_bm25\` (\`pip install rank_bm25\`).
3. Combine avec RRF (k=60).
4. Évalue les 3 approches (vector, bm25, hybrid) sur tes 20 questions.
5. Trace recall@5 et @10 pour chacune.

**Bonus** : identifie 3 questions où BM25 bat le vectoriel et 3 où c'est l'inverse. Comprends pourquoi.`,
      quiz: [
        {
          question: "Pourquoi BM25 reste utile en 2025 malgré les embeddings sémantiques ?",
          choices: [
            "C'est plus rapide uniquement",
            "Il excelle sur les termes rares, codes, noms propres et matches exacts — là où le vectoriel rate",
            "Pour la rétro-compatibilité",
            "Aucune raison vraie",
          ],
          answerIndex: 1,
          explanation:
            "Vectoriel et lexical sont complémentaires. L'un cherche le sens, l'autre l'exactitude. Hybrid = les deux.",
        },
        {
          question: "Pourquoi RRF (Reciprocal Rank Fusion) plutôt qu'une moyenne pondérée des scores ?",
          choices: [
            "RRF est plus complexe",
            "RRF n'a pas besoin de normaliser des scores hétérogènes (un score BM25 et un score cosine ne se comparent pas)",
            "C'est imposé par les vector DB",
            "Pour faire compliqué",
          ],
          answerIndex: 1,
          explanation:
            "Les scores BM25 (non bornés) et cosine (0 à 1) ne sont pas comparables. RRF utilise les rangs, pas les scores.",
        },
        {
          question: "Quelle est la dimension d'embedding 'sweet spot' en pratique ?",
          choices: [
            "256",
            "1024 — bon compromis qualité / coût stockage",
            "8192",
            "Toujours 3072",
          ],
          answerIndex: 1,
          explanation:
            "1024 dims donne ~95% de la qualité de 3072 pour 1/3 du stockage. Choix par défaut en production.",
        },
      ],
      resources: [
        { label: "MTEB Leaderboard (HuggingFace)", href: "https://huggingface.co/spaces/mteb/leaderboard" },
        { label: "Reciprocal Rank Fusion paper", href: "https://plg.uwaterloo.ca/~gvcormac/cormacksigir09-rrf.pdf" },
      ],
    },
    {
      slug: "reranking-evaluation",
      moduleSlug: "rag",
      index: 3,
      title: "Reranking, evaluation et mini-projet RAG complet",
      subtitle: "Le pipeline bout-en-bout que tu déploieras en prod",
      level: "expert",
      durationMin: 22,
      objectives: [
        "Ajouter un reranker pour passer de recall@20 à precision@5",
        "Construire un eval set RAG (question, ground truth, sources)",
        "Mesurer faithfulness, answer relevance, context precision",
        "Assembler le pipeline complet : query → retrieve → rerank → generate → cite",
      ],
      vocalScript: `[Intro]
Tu as un bon chunking, un hybrid search qui ramène vingt résultats pertinents. Mais ton LLM ne peut pas en avaler vingt — il faut les filtrer aux cinq meilleurs. C'est le job du reranker. Et surtout, tu dois mesurer. Cette leçon ferme la boucle.

[Section 1 - reranker]
Un reranker prend ta query et tes vingt candidats, et les re-score un par un avec un modèle dédié, plus lourd mais plus précis. Cohere rerank, BGE reranker, Voyage rerank. Effet typique : ton recall@20 devient un precision@5 qui passe de soixante-dix à quatre-vingt-dix pour cent. C'est gigantesque.

[Section 2 - eval]
Sans eval, tu navigues à l'aveugle. Construis un dataset de cinquante questions avec leurs réponses attendues et leurs sources. Mesure trois métriques : faithfulness — la réponse est-elle ancrée dans les sources ? answer relevance — répond-elle vraiment à la question ? context precision — les chunks ramenés sont-ils pertinents ? Bibliothèques : RAGAS, Promptfoo, ou custom.

[Section 3 - pipeline complet]
Le pipeline final, en cinq étapes : préprocessing de la query — éventuelle reformulation, hybrid retrieval, reranking, generation avec citations forcées, post-process pour vérifier les citations. Plus un cache à chaque niveau. C'est le standard production.

[Conclusion]
À ce stade tu sais construire un RAG qui tient. Mais surtout, tu sais le mesurer. C'est ce qui te démarque des quatre-vingt-quinze pour cent qui shippent à l'aveugle.`,
      visuals: [
        {
          title: "Pipeline RAG complet",
          description:
            "Schéma horizontal en 6 boîtes : Query → [Preprocess] → [Hybrid Retrieve top 20] → [Rerank top 5] → [LLM generate] → [Citation check] → Answer. Caches en pointillés sous chaque étape.",
        },
        {
          title: "Métriques RAG",
          description:
            "Triangle : Faithfulness (réponse ancrée?) / Answer relevance (répond à la Q?) / Context precision (bons chunks?). Au centre : 'RAG quality'.",
        },
        {
          title: "Effet du reranking",
          description:
            "Barres : recall@20 = 92%, precision@5 sans rerank = 70%, precision@5 avec rerank = 89%. Annotation '+19 points'.",
        },
      ],
      content: `## Le reranker : multiplier la précision

Tu as ramené 20 candidats avec hybrid search. Tu n'en garderas que 5 dans le prompt. Comment choisir ?

### Cross-encoder reranking

Un cross-encoder prend **(query, document)** comme un seul input et calcule un score de pertinence. Plus lent qu'un bi-encoder mais beaucoup plus précis.

\`\`\`python
import cohere
co = cohere.Client(api_key=...)

def rerank(query, candidates, top_n=5):
    response = co.rerank(
        model="rerank-v3.5",
        query=query,
        documents=[c.text for c in candidates],
        top_n=top_n,
    )
    return [candidates[r.index] for r in response.results]
\`\`\`

**Modèles à connaître** :
- Cohere rerank-v3.5 (cloud)
- BGE-reranker-v2-m3 (open, multilingue)
- Voyage rerank-2

**Coût** : ~$0.002 par recherche de 20 docs. **Gain** : +15–25 points de precision@5.

## Évaluer un RAG : 3 métriques + 1 dataset

### Le dataset

\`\`\`json
[
  {
    "question": "Quelle est la durée de préavis pour un CDI cadre ?",
    "ground_truth": "3 mois en France selon la convention collective applicable",
    "expected_sources": ["doc_42_p3", "doc_42_p4"],
    "tags": ["RH", "FR"]
  }
]
\`\`\`

50–200 questions, écrites par un expert métier, **pas synthétiques**.

### Les 3 métriques (RAGAS framework)

1. **Faithfulness** : la réponse est-elle ancrée dans les chunks fournis ? (LLM-as-judge)
2. **Answer relevance** : la réponse répond-elle à la question posée ? (LLM-as-judge)
3. **Context precision** : parmi les chunks ramenés, combien sont vraiment pertinents ? (overlap avec \`expected_sources\` ou LLM-as-judge)

\`\`\`python
from ragas import evaluate
from ragas.metrics import faithfulness, answer_relevancy, context_precision

results = evaluate(
    dataset=eval_dataset,
    metrics=[faithfulness, answer_relevancy, context_precision],
)
# → scores 0..1 par métrique, agrégés
\`\`\`

**Cible production** : > 0.85 sur les trois.

## Le pipeline complet

\`\`\`python
async def rag_pipeline(query: str, user_filters: dict = None):
    # 1. Preprocess : reformulation si question ambiguë
    refined = await maybe_rewrite(query)

    # 2. Hybrid retrieval (top 20)
    candidates = await hybrid_search(refined, k=20, filters=user_filters)

    # 3. Rerank (top 5)
    top5 = await rerank(refined, candidates, top_n=5)

    # 4. Build context with citations
    context = "\\n\\n".join(
        f"<source id='{c.id}' title='{c.metadata.title}'>{c.text}</source>"
        for c in top5
    )

    # 5. Generate with forced citations
    answer = await llm.complete(
        system=RAG_SYSTEM_PROMPT,  # demande des citations [src:ID]
        messages=[{"role": "user", "content": f"<context>{context}</context>\\n\\n{query}"}],
    )

    # 6. Verify citations (optional but recommended)
    answer = verify_and_link_citations(answer, top5)

    return {"answer": answer, "sources": top5}
\`\`\`

System prompt clé :

\`\`\`
You answer questions using ONLY the provided <source> blocks.
- If the answer isn't in the sources, say "Je ne sais pas, sources insuffisantes."
- Cite each fact with [src:ID] inline.
- Never invent. Never use prior knowledge.
\`\`\`

## Le must-have : la fallback "je ne sais pas"

90% des RAG hallucinent parce qu'on ne leur donne pas la **permission de ne pas savoir**. Force-la dans le prompt. C'est le single biggest fix anti-hallucination.

## À retenir

- Reranking = +15–25 points de precision pour ~$0.002/query. Toujours.
- Eval set humain de 50–200 questions = condition non négociable.
- 3 métriques RAGAS : faithfulness, answer relevance, context precision.
- Pipeline complet : preprocess → hybrid → rerank → generate (cited) → verify.
- Permission de dire "je ne sais pas" = anti-hallucination #1.`,
      practice: `**Mini-projet pipeline RAG complet**

But : un système RAG bout-en-bout sur **ton** corpus.

**Étapes** :
1. **Ingestion** : 100+ documents (Notion export, PDF, docs internes…).
2. **Chunking** hierarchical avec metadata (\`source\`, \`section\`, \`date\`).
3. **Indexing** : Qdrant + BM25 (rank_bm25 ou Elasticsearch).
4. **Pipeline** :
   - Hybrid search top 20
   - Rerank top 5 (Cohere ou BGE)
   - LLM generate avec citations \`[src:id]\`
   - Citation verification
5. **Eval** : 30 questions/réponses construites manuellement.
6. **Mesure** : faithfulness, answer relevance, context precision avec RAGAS.
7. **Itération** : identifie la métrique la plus faible, optimise un seul paramètre, remesure.

**Livrables** :
- Code (jupyter ou script)
- Tableau de scores avant/après chaque optimisation
- Note d'1 page : "Si je devais déployer demain, voici ce qui manque."

**Étoile bonus** : ajoute le \`prompt caching\` sur le system prompt et mesure l'économie.`,
      quiz: [
        {
          question: "Quel est l'effet typique d'un reranker sur un pipeline RAG ?",
          choices: [
            "Aucun effet mesurable",
            "+15 à +25 points de precision@5 pour un coût marginal",
            "Réduit la précision",
            "Double la latence sans gain",
          ],
          answerIndex: 1,
          explanation:
            "Le cross-encoder évalue chaque (query, doc) en profondeur. C'est le boost qualité le plus rentable du pipeline RAG.",
        },
        {
          question: "Quelle est la cause #1 d'hallucinations dans un RAG ?",
          choices: [
            "Le modèle est mauvais",
            "Le modèle n'a pas la permission explicite de dire 'je ne sais pas, sources insuffisantes'",
            "Trop de chunks",
            "Pas assez de tokens",
          ],
          answerIndex: 1,
          explanation:
            "Sans 'permission de ne pas savoir', le modèle invente pour satisfaire la question. Force la fallback dans le system prompt.",
        },
        {
          question: "Que mesure la métrique 'faithfulness' ?",
          choices: [
            "La vitesse de réponse",
            "Si la réponse est ancrée dans les chunks fournis (pas inventée)",
            "Si l'utilisateur est satisfait",
            "Le coût en tokens",
          ],
          answerIndex: 1,
          explanation:
            "Faithfulness = l'agent ne dit que ce que les sources permettent. Mesurée typiquement par un LLM-as-judge.",
        },
      ],
      resources: [
        { label: "RAGAS — Evaluation framework", href: "https://docs.ragas.io/" },
        { label: "Cohere Rerank docs", href: "https://docs.cohere.com/docs/rerank-overview" },
        { label: "Anthropic — Contextual Retrieval", href: "https://www.anthropic.com/news/contextual-retrieval" },
      ],
    },
  ],
};
