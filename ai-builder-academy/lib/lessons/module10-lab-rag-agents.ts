import type { Module } from "../types";

export const module10: Module = {
  slug: "lab-rag-agents",
  index: 10,
  title: "Lab pratique — RAG & Agents",
  tagline: "10 exercices guidés pour combler les lacunes",
  description:
    "Module bonus 100% pratique. 5 exercices RAG production-grade (chunking, hybrid, reranking, contextual retrieval, eval RAGAS) et 5 exercices agents avancés (memory, checkpointing, self-recovery, HITL, debug). Chaque exercice : objectif clair, étapes pas-à-pas, code starter, corrigé type, critères d'évaluation.",
  color: "from-pink-500 to-orange-500",
  lessons: [
    {
      slug: "lab-rag-01-chunking",
      moduleSlug: "lab-rag-agents",
      index: 1,
      title: "RAG-01 — Chunking lab",
      subtitle: "Compare 3 stratégies sur le même corpus, mesure le recall",
      level: "advanced",
      durationMin: 25,
      objectives: [
        "Implémenter 3 chunkers : fixed-size, semantic, hierarchical",
        "Construire un eval set de 20 questions avec ground truth",
        "Mesurer recall@5 et precision@5 pour chaque stratégie",
        "Choisir la meilleure stratégie selon ton corpus",
      ],
      vocalScript: `[Intro]
Premier exercice. Tu vas construire trois chunkers, les comparer sur le même corpus, mesurer, et choisir. Tu vas voir, c'est ce qui sépare un RAG amateur d'un RAG pro : la rigueur de la mesure.

[Étape 1 - corpus]
Étape un : prends vingt à cinquante documents que tu utilises vraiment — exports Notion, PDFs internes, articles de blog. Pas des données synthétiques, ça fausse tout. Stocke-les dans un dossier corpus.

[Étape 2 - chunkers]
Étape deux : implémente trois chunkers. Fixed-size cinq cents tokens overlap cent. Semantic qui coupe aux headers markdown. Hierarchical, deux niveaux, chunks de deux cents tokens avec parents de mille cinq cents. Code minimal, mais propre.

[Étape 3 - eval]
Étape trois : écris vingt questions sur ton corpus avec leurs réponses attendues et au moins un chunk source par question. Cette annotation manuelle est ce qui rendra ton eval crédible.

[Étape 4 - mesure]
Étape quatre : pour chaque chunker, embed tous les chunks, retrieve top cinq sur chaque question, calcule recall — la source attendue est-elle dans le top cinq — et précision — combien des cinq sont pertinents. Trace les chiffres dans un tableau.

[Conclusion]
À la fin tu auras une réponse factuelle : sur mon corpus, quel chunker est le meilleur. C'est la base de tout ton pipeline RAG.`,
      visuals: [
        {
          title: "Architecture du lab",
          description:
            "Pipeline : corpus/ (20 docs) → 3 chunkers en parallèle → 3 indexes Qdrant → eval loop sur 20 questions → tableau de résultats.",
          ascii: `corpus/ ──┬─► fixed_chunker ───► index_fixed ───┐
            ├─► semantic_chunker ─► index_semantic ┼─► eval (20Q) ─► table
            └─► hierarchical ─────► index_hierarch ┘`,
        },
        {
          title: "Format du eval set",
          description:
            "JSON par question : { question, expected_answer, expected_source_ids: [...], tags: [...] }. 20 lignes minimum, écrites à la main.",
        },
      ],
      content: `## Setup

\`\`\`bash
pip install qdrant-client openai sentence-transformers tiktoken
\`\`\`

Lance Qdrant local :
\`\`\`bash
docker run -p 6333:6333 qdrant/qdrant
\`\`\`

## Étape 1 — Corpus

Place 20-50 documents dans \`corpus/\`. Markdown ou texte simple pour démarrer.

## Étape 2 — Les 3 chunkers

\`\`\`python
# chunkers.py
import re, tiktoken

enc = tiktoken.get_encoding("cl100k_base")

def chunk_fixed(text: str, size=500, overlap=100):
    toks = enc.encode(text)
    out = []
    for i in range(0, len(toks), size - overlap):
        out.append(enc.decode(toks[i:i+size]))
    return out

def chunk_semantic(md: str):
    sections = re.split(r'(?=^#{1,3} )', md, flags=re.M)
    chunks = []
    for s in sections:
        s = s.strip()
        if not s: continue
        if len(enc.encode(s)) > 1500:
            chunks.extend(chunk_fixed(s, 800, 100))
        else:
            chunks.append(s)
    return chunks

def chunk_hierarchical(md: str):
    parents = chunk_semantic(md)
    items = []
    for pi, p in enumerate(parents):
        for ci, c in enumerate(chunk_fixed(p, size=200, overlap=20)):
            items.append({"text": c, "parent_id": pi, "parent_text": p})
    return items
\`\`\`

## Étape 3 — Eval set (20 questions à la main)

\`\`\`json
[
  {
    "id": "Q01",
    "question": "Quelle est la durée de préavis pour un CDI cadre en France ?",
    "expected_keywords": ["3 mois", "trois mois", "préavis"],
    "expected_source_doc": "convention_collective.md"
  }
]
\`\`\`

## Étape 4 — Eval loop

\`\`\`python
def evaluate(retriever, eval_set, k=5):
    recall_hits = 0
    precision_sum = 0
    for q in eval_set:
        results = retriever.search(q["question"], top_k=k)
        source_docs = {r.metadata["source_doc"] for r in results}
        # recall = la source attendue est dans le top k ?
        if q["expected_source_doc"] in source_docs:
            recall_hits += 1
        # precision = combien des k sont du même doc que la source attendue ?
        prec = sum(1 for r in results if r.metadata["source_doc"] == q["expected_source_doc"]) / k
        precision_sum += prec
    return {
        "recall@5": recall_hits / len(eval_set),
        "precision@5": precision_sum / len(eval_set),
    }
\`\`\`

## Tableau attendu

| Stratégie | Recall@5 | Precision@5 | Storage (MB) |
|---|---|---|---|
| Fixed 500/100 | ? | ? | ? |
| Semantic | ? | ? | ? |
| Hierarchical 200/20 | ? | ? | ? |

## Pièges à éviter

- **Eval set généré par LLM** : trop facile, gonfle artificiellement le recall. Écris à la main.
- **Toujours embedder avec le même modèle** : sinon tu compares 2 choses à la fois.
- **Ne pas randomiser** l'ordre des chunks à l'insertion : peut influencer certains retrievers.

## Critères de réussite

- ✅ 3 chunkers fonctionnels
- ✅ 20 questions annotées à la main
- ✅ Tableau de résultats reproductible
- ✅ Décision motivée par les chiffres`,
      practice: `**Livrable attendu** :

1. Repo (ou notebook) avec les 3 chunkers en code clair.
2. Eval set JSON committé (sans réponses leaked dans le code).
3. Script qui lance l'eval et produit le tableau.
4. Markdown de 1 page : "Sur mon corpus, je choisis [stratégie] parce que [chiffres]."

**Bonus** :
- Ajoute la metadata \`section\` aux chunks et compare hierarchical avec/sans metadata.
- Mesure aussi le temps d'indexation et le storage.`,
      quiz: [
        {
          question: "Pourquoi écrire l'eval set à la main et pas le générer avec un LLM ?",
          choices: [
            "Pour gagner du temps",
            "Un eval set LLM-generated tend à être trop proche du texte source → recall artificiellement gonflé",
            "Le LLM ne sait pas écrire",
            "Aucune différence",
          ],
          answerIndex: 1,
          explanation:
            "Les questions LLM-generated sur un texte ressemblent trop au texte. Les questions humaines reflètent les vrais usages.",
        },
        {
          question: "Quelle métrique mesure 'combien des chunks ramenés sont pertinents' ?",
          choices: ["Recall", "Precision", "F1", "Latency"],
          answerIndex: 1,
          explanation:
            "Recall = source attendue trouvée ? Precision = parmi les k ramenés, combien sont du bon doc/section.",
        },
        {
          question: "Quel chunker démarrer en premier sur un corpus inconnu ?",
          choices: [
            "Late chunking direct",
            "Fixed-size 500/100 — baseline rapide, mesure, puis itère",
            "Hierarchical avec 5 niveaux",
            "Aucun, juste embed le doc entier",
          ],
          answerIndex: 1,
          explanation:
            "Fixed-size est le baseline incontournable. Tu mesures, puis tu décides si la sophistication vaut le coup.",
        },
      ],
      resources: [
        { label: "tiktoken — tokenizer OpenAI/Anthropic-compatible", href: "https://github.com/openai/tiktoken" },
        { label: "Qdrant — quick start", href: "https://qdrant.tech/documentation/quickstart/" },
      ],
    },
    {
      slug: "lab-rag-02-hybrid-search",
      moduleSlug: "lab-rag-agents",
      index: 2,
      title: "RAG-02 — Hybrid search (vector + BM25 + RRF)",
      subtitle: "Passe de pur vectoriel à hybrid, mesure le gain réel",
      level: "advanced",
      durationMin: 25,
      objectives: [
        "Implémenter vector_search avec un embedding model",
        "Implémenter bm25_search avec rank_bm25",
        "Combiner avec Reciprocal Rank Fusion (k=60)",
        "Mesurer le gain hybrid vs vector seul",
      ],
      vocalScript: `[Intro]
Deuxième exo. Tu vas brancher BM25 à côté de ton vectoriel et fusionner avec RRF. Spoiler : tu vas observer un gain de dix à vingt points de recall, et tu sauras pourquoi.

[Étape 1 - install]
Étape un : installe rank-bm25, c'est cinq cents kilo-octets. Tu n'as pas besoin d'Elasticsearch pour ce lab.

[Étape 2 - index BM25]
Étape deux : pour BM25 tu tokenises chaque chunk en mots — split simple, lowercase, retire la ponctuation. Tu construis l'index une fois en mémoire. C'est tout.

[Étape 3 - RRF]
Étape trois : la magie. Tu lances vector_search top vingt, bm25_search top vingt, et tu fusionnes avec RRF, k égal soixante. Pas besoin de normaliser les scores — RRF utilise les rangs.

[Étape 4 - identifie le gain]
Étape quatre : trouve trois questions où BM25 bat le vectoriel et trois où c'est l'inverse. C'est ce diagnostic qui fait de toi un pro, pas juste l'application aveugle de RRF.

[Conclusion]
À la fin tu auras intériorisé pourquoi le hybrid est devenu un baseline obligatoire.`,
      visuals: [
        {
          title: "Pipeline hybrid",
          description:
            "Query → split en parallèle → [vector_search top20] + [bm25_search top20] → RRF(k=60) → top10 finaux. Mesure recall@10 à la fin.",
        },
        {
          title: "Quand BM25 gagne",
          description:
            "Tableau : Codes/IDs (ERR-4042) → BM25 win. Synonymes/sémantique (auto / véhicule) → Vector win. Noms propres rares → BM25 win. Hybrid prend les deux.",
        },
      ],
      content: `## Étape 1 — Setup BM25

\`\`\`bash
pip install rank_bm25
\`\`\`

\`\`\`python
import re
from rank_bm25 import BM25Okapi

def tokenize(text: str):
    return re.findall(r"\\w+", text.lower())

class BM25Index:
    def __init__(self, chunks):
        self.chunks = chunks
        self.bm25 = BM25Okapi([tokenize(c["text"]) for c in chunks])

    def search(self, query, top_k=20):
        scores = self.bm25.get_scores(tokenize(query))
        idx = scores.argsort()[::-1][:top_k]
        return [self.chunks[i] for i in idx]
\`\`\`

## Étape 2 — Vector search (rappel)

\`\`\`python
class VectorIndex:
    def __init__(self, chunks, embed_model):
        self.chunks = chunks
        self.vectors = embed_model.embed([c["text"] for c in chunks])
        # store in Qdrant or in-memory faiss

    def search(self, query, top_k=20):
        qv = self.embed_model.embed([query])[0]
        # cosine similarity ranking
        ...
\`\`\`

## Étape 3 — Reciprocal Rank Fusion

\`\`\`python
def rrf(rankings, k=60):
    """rankings: list of lists of doc_id ordered by relevance"""
    scores = {}
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            scores[doc_id] = scores.get(doc_id, 0) + 1.0 / (k + rank)
    return sorted(scores, key=lambda x: -scores[x])

def hybrid_search(query, k=10):
    vec = vec_index.search(query, top_k=20)
    bm25 = bm25_index.search(query, top_k=20)
    vec_ids = [c["id"] for c in vec]
    bm25_ids = [c["id"] for c in bm25]
    fused_ids = rrf([vec_ids, bm25_ids])[:k]
    id_to_chunk = {c["id"]: c for c in (vec + bm25)}
    return [id_to_chunk[i] for i in fused_ids]
\`\`\`

## Étape 4 — Mesure

Reprends l'eval set de RAG-01. Calcule recall@5 et @10 pour :
1. Vector seul
2. BM25 seul
3. Hybrid RRF

Attendu : hybrid > vector et hybrid > bm25, sur la plupart des questions.

## Étape 5 — Diagnostic

Pour chaque question où hybrid > vector, identifie : est-ce que BM25 a trouvé un chunk que vector avait raté ? Pourquoi (mot rare, code, nom propre) ?

Idem pour vector > bm25 : reformulation sémantique, synonyme.

## Pièges à éviter

- **Stemming agressif** sur BM25 → casse les codes (ERR-4042 → ERR-4042 OK, mais "running" → "run" peut perdre des matches).
- **k trop bas dans RRF** → favorise un seul retriever ; reste à k=60.
- **Comparer top_k différents** entre vector et bm25 → biaise RRF. Garde le même.

## Critères de réussite

- ✅ Hybrid bat vector d'au moins 5 points de recall@5
- ✅ Tu peux nommer 3 questions où BM25 a sauvé la mise
- ✅ Tu peux nommer 3 questions où vector a sauvé la mise`,
      practice: `**Livrable** :

1. Module \`retrieval.py\` exposant \`vector_search\`, \`bm25_search\`, \`hybrid_search\`.
2. Script eval qui produit un tableau recall@5/@10 pour les 3 modes.
3. Note 1 page : "BM25 m'a aidé sur ces 3 cas, vector sur ces 3 cas, hybrid bat les deux."

**Bonus** : essaie \`k=10, 30, 60, 100\` dans RRF, montre la sensibilité.`,
      quiz: [
        {
          question: "Pourquoi RRF n'a pas besoin de normaliser les scores ?",
          choices: [
            "Magie",
            "Parce qu'il fusionne sur les rangs (1, 2, 3...) et non sur les scores bruts",
            "Parce que les scores sont déjà normalisés",
            "Parce que la moyenne suffit",
          ],
          answerIndex: 1,
          explanation:
            "Un rang 1 vaut 1/61 dans RRF, peu importe que le score sous-jacent soit un cosine 0.92 ou un BM25 14.3.",
        },
        {
          question: "Sur quelle classe de requête BM25 surpasse-t-il typiquement le vectoriel ?",
          choices: [
            "Reformulations sémantiques",
            "Codes, IDs, acronymes, noms propres rares",
            "Très longs paragraphes",
            "Aucune",
          ],
          answerIndex: 1,
          explanation:
            "BM25 trouve des matches lexicaux exacts là où le vectoriel cherche du sens — donc gagnant sur l'exactitude littérale.",
        },
        {
          question: "Quelle valeur de k recommandée dans RRF ?",
          choices: ["1", "60 (valeur consacrée)", "10000", "Aléatoire"],
          answerIndex: 1,
          explanation:
            "k=60 est le default du papier original et reste très robuste en pratique.",
        },
      ],
      resources: [
        { label: "rank_bm25 — implementation Python", href: "https://github.com/dorianbrown/rank_bm25" },
        { label: "RRF paper (Cormack et al.)", href: "https://plg.uwaterloo.ca/~gvcormac/cormacksigir09-rrf.pdf" },
      ],
    },
    {
      slug: "lab-rag-03-reranking",
      moduleSlug: "lab-rag-agents",
      index: 3,
      title: "RAG-03 — Reranking avec cross-encoder",
      subtitle: "+15 à +25 points de precision pour quelques millisecondes",
      level: "advanced",
      durationMin: 20,
      objectives: [
        "Ajouter un reranker (Cohere ou BGE local)",
        "Mesurer le gain précis sur ton eval set",
        "Optimiser le tradeoff top_n du retriever vs top_n du reranker",
        "Implémenter un fallback si le reranker timeout",
      ],
      vocalScript: `[Intro]
Tu as un hybrid search qui te ramène vingt candidats. Tu n'en garderas que cinq dans le prompt. Le reranker, c'est ce qui choisit les bons cinq. Cet exo te fait gagner souvent vingt points de precision en une heure de boulot.

[Étape 1 - choisir]
Étape un : choisis ton reranker. Cohere rerank-v3.5 cloud, simple, payant. Ou BGE-reranker-v2-m3 local, gratuit, multilingue, demande un GPU honnête. Pour ce lab, Cohere par défaut.

[Étape 2 - intégrer]
Étape deux : tu prends les vingt candidats de l'hybrid, tu envoies au reranker avec la query, tu récupères les cinq meilleurs réordonnés. Trois lignes de code.

[Étape 3 - mesure]
Étape trois : mesure precision@5 avec et sans reranker sur ton eval set. Si ton recall@20 était à quatre-vingt-quinze pour cent, tu devrais voir precision@5 passer de soixante-dix à quatre-vingt-cinq, voire quatre-vingt-quinze.

[Étape 4 - fallback]
Étape quatre : le reranker peut timeout. Implémente un fallback qui retombe sur les cinq premiers de l'hybrid si le reranker rate. Toujours.

[Conclusion]
À la fin de cet exo, tu as un pipeline qui rivalise avec ce qui se fait de mieux en industrie.`,
      visuals: [
        {
          title: "Avec/sans reranker",
          description:
            "2 pipelines : (a) hybrid top 5 → prompt. (b) hybrid top 20 → reranker → top 5 → prompt. Annoter precision@5 70% vs 89%.",
        },
        {
          title: "Tradeoff top_n",
          description:
            "Courbe : precision@5 final en fonction de top_n entrée du reranker (5, 10, 20, 50, 100). Plateau vers 20-30.",
        },
      ],
      content: `## Étape 1 — Cohere (option simple)

\`\`\`bash
pip install cohere
\`\`\`

\`\`\`python
import os, cohere
co = cohere.Client(api_key=os.environ["COHERE_API_KEY"])

def rerank_cohere(query, candidates, top_n=5):
    res = co.rerank(
        model="rerank-v3.5",
        query=query,
        documents=[c["text"] for c in candidates],
        top_n=top_n,
    )
    return [candidates[r.index] for r in res.results]
\`\`\`

## Étape 1bis — BGE local (option gratuite)

\`\`\`bash
pip install sentence-transformers FlagEmbedding
\`\`\`

\`\`\`python
from FlagEmbedding import FlagReranker
reranker = FlagReranker("BAAI/bge-reranker-v2-m3", use_fp16=True)

def rerank_bge(query, candidates, top_n=5):
    pairs = [[query, c["text"]] for c in candidates]
    scores = reranker.compute_score(pairs, normalize=True)
    ranked = sorted(zip(scores, candidates), key=lambda x: -x[0])
    return [c for _, c in ranked[:top_n]]
\`\`\`

## Étape 2 — Pipeline complet

\`\`\`python
def retrieve_and_rerank(query, k_final=5):
    candidates = hybrid_search(query, k=20)
    try:
        return rerank_cohere(query, candidates, top_n=k_final)
    except Exception as e:
        log("rerank_failed", error=str(e))
        return candidates[:k_final]  # fallback
\`\`\`

## Étape 3 — Mesure

Reprends ton eval set. Calcule precision@5 et faithfulness sur l'output final pour :
- Hybrid top 5 (baseline)
- Hybrid top 20 → rerank top 5

Tu devrais voir un gain de **+10 à +25 points** sur precision@5.

## Étape 4 — Sensibilité top_n

\`\`\`python
for n_in in [5, 10, 20, 50]:
    candidates = hybrid_search(query, k=n_in)
    final = rerank_cohere(query, candidates, top_n=5)
    measure(final)
\`\`\`

Trace la courbe. Plateau typique vers n_in=20-30. Au-delà, gain marginal pour coût/latence linéaires.

## Pièges à éviter

- **top_n du reranker > top_n du retriever** → tu reçois moins que demandé, silencieux.
- **Pas de timeout sur Cohere** → le reranker fait latence p99.
- **Reranker sans fallback** → ton RAG tombe si Cohere a un incident.
- **Tester sur 5 questions** → bruit. Minimum 20.

## Critères de réussite

- ✅ Precision@5 améliorée d'au moins 10 points absolus
- ✅ Latence reranker < 500ms p99
- ✅ Fallback testé (kill Cohere et vérifie que le pipeline continue)`,
      practice: `**Livrable** :

1. Pipeline \`retrieve_and_rerank\` avec fallback.
2. Tableau precision@5 hybrid vs hybrid+rerank.
3. Courbe sensibilité top_n entrée reranker.
4. Test d'incident : kill l'API du reranker, vérifie le fallback.

**Bonus** : ajoute un cache (query_hash → reranked_results, TTL 1h) pour les requêtes fréquentes.`,
      quiz: [
        {
          question: "Quel gain typique d'un reranker bien intégré ?",
          choices: [
            "Aucun",
            "+10 à +25 points de precision@5",
            "Réduit la précision",
            "Multiplie la latence par 10",
          ],
          answerIndex: 1,
          explanation:
            "Le cross-encoder évalue (query, doc) ensemble — beaucoup plus précis qu'un bi-encoder qui les embedde séparément.",
        },
        {
          question: "Pourquoi un fallback est-il indispensable sur le reranker ?",
          choices: [
            "Pas indispensable",
            "Si le service tombe, ton RAG tombe entièrement. Fallback = continue avec top 5 hybrid.",
            "Pour le SEO",
            "Pour les tests unitaires",
          ],
          answerIndex: 1,
          explanation:
            "Tout service externe peut tomber. Le fallback dégradé est mieux qu'une page d'erreur.",
        },
        {
          question: "À partir de quel top_n entrée le gain plafonne typiquement ?",
          choices: [
            "5",
            "20-30 (la courbe précision plafonne, latence croît linéairement)",
            "200",
            "Aucun plateau",
          ],
          answerIndex: 1,
          explanation:
            "Au-delà de 20-30 candidats, le reranker voit du bruit pour un gain marginal. Coût/latence non rentables.",
        },
      ],
      resources: [
        { label: "Cohere Rerank docs", href: "https://docs.cohere.com/docs/rerank-overview" },
        { label: "BGE-reranker-v2 (BAAI)", href: "https://huggingface.co/BAAI/bge-reranker-v2-m3" },
      ],
    },
    {
      slug: "lab-rag-04-contextual-retrieval",
      moduleSlug: "lab-rag-agents",
      index: 4,
      title: "RAG-04 — Contextual retrieval",
      subtitle: "La technique Anthropic qui réduit l'échec de retrieval de 49%",
      level: "expert",
      durationMin: 22,
      objectives: [
        "Comprendre pourquoi un chunk isolé perd son contexte",
        "Préfixer chaque chunk avec un contexte généré par LLM",
        "Combiner avec hybrid + reranking (stack complète)",
        "Mesurer le gain sur ton eval set",
      ],
      vocalScript: `[Intro]
Anthropic a publié en septembre vingt-vingt-quatre une technique simple et puissante : contextual retrieval. L'idée — préfixer chaque chunk avec un résumé contextuel de cinquante à cent tokens — réduit le taux d'échec retrieval de quarante-neuf pour cent. Cet exo te le fait implémenter.

[Étape 1 - le problème]
Étape un : pourquoi ? Un chunk pris isolément perd son contexte. Le chunk dit "le revenu a baissé de trois pour cent au deuxième trimestre" — mais le revenu de quoi, en quelle année ? Le LLM va galérer. Avec un préfixe "Rapport annuel Acme Corp 2024, section finance, deuxième trimestre", la requête "revenus 2024 d'Acme" matche enfin.

[Étape 2 - generate context]
Étape deux : pour chaque chunk, tu envoies au LLM le document entier plus le chunk, et tu demandes un résumé contextuel court — cinquante à cent tokens. Tu préfixes ce résumé au texte du chunk avant embedding. Le prompt caching rend ça abordable — tu paies le doc entier une fois par document, pas par chunk.

[Étape 3 - combine]
Étape trois : combine avec ton hybrid plus reranking. Anthropic a mesuré que la combinaison contextual plus BM25 plus rerank donne moins six-sept pour cent d'échec retrieval — performance state-of-the-art.

[Conclusion]
Cet exo te fait monter au niveau d'un RAG top mondial 2025.`,
      visuals: [
        {
          title: "Chunk avant/après contextualisation",
          description:
            "Avant : 'Les revenus ont baissé de 3% au Q2.' Après : '[Acme Corp annual report 2024, finance section, Q2] Les revenus ont baissé de 3% au Q2.' Annoter 'retrieval beaucoup plus précis'.",
        },
        {
          title: "Stack complète Anthropic",
          description:
            "Pipeline : Contextual chunks → hybrid (vector + BM25) → reranker → top 5 → LLM. Annotations gains cumulés : -35% baseline, -49% +context, -67% +rerank.",
        },
      ],
      content: `## Le problème en 1 image

\`\`\`
Chunk brut : "Le revenu a baissé de 3% au Q2."
Requête   : "Revenus Acme 2024"
Match ?   : Faible (ambigu).
\`\`\`

\`\`\`
Chunk contextualisé : "[Acme Corp annual report 2024, finance Q2] Le revenu a baissé de 3% au Q2."
Requête             : "Revenus Acme 2024"
Match ?             : Excellent.
\`\`\`

## Étape 1 — Génération du contexte

\`\`\`python
CONTEXT_PROMPT = """
<document>
{full_doc}
</document>

Here is the chunk we want to situate within the whole document:
<chunk>
{chunk_text}
</chunk>

Please give a short succinct context to situate this chunk within the overall
document for the purposes of improving search retrieval of the chunk.
Answer only with the succinct context (50-100 tokens) and nothing else.
"""

async def generate_context(full_doc: str, chunk_text: str) -> str:
    response = await llm.complete(
        system="You contextualize document chunks for retrieval.",
        messages=[{"role": "user", "content": CONTEXT_PROMPT.format(
            full_doc=full_doc, chunk_text=chunk_text
        )}],
        max_tokens=150,
        # IMPORTANT: prompt cache the full_doc
        cache_control_on_full_doc=True,
    )
    return response.text.strip()
\`\`\`

## Étape 2 — Pipeline d'indexation

\`\`\`python
async def index_with_context(doc_path: str):
    full_doc = read(doc_path)
    chunks = chunk_semantic(full_doc)
    for chunk in chunks:
        ctx = await generate_context(full_doc, chunk)
        contextualized_text = f"{ctx}\\n\\n{chunk}"
        embedding = embed(contextualized_text)
        store(text=contextualized_text, embedding=embedding, metadata={"source": doc_path})
\`\`\`

**Coût avec prompt caching** : ~$1.02 par million de tokens de document (vs ~$15 sans cache).

## Étape 3 — Stack complète

Combine contextual + hybrid + reranker :

\`\`\`python
def full_pipeline(query, k=5):
    # contextualized chunks already indexed
    candidates = hybrid_search(query, k=150)  # large pool
    final = rerank(query, candidates, top_n=k)
    return final
\`\`\`

## Mesure

| Stack | Failure rate retrieval (top 5) |
|---|---|
| Baseline (vector only) | -- |
| + Contextual | ~ -35% |
| + Hybrid BM25 | ~ -49% |
| + Reranker | ~ -67% |

(Chiffres Anthropic, ordres de grandeur sur leur eval set.)

## Pièges à éviter

- **Pas de prompt caching** → coût indexation explose.
- **Contexte trop long** (> 100 tok) → dilue l'embedding du chunk réel.
- **Re-générer le contexte à chaque ré-indexation** → cache les contextes en local aussi.
- **Ne pas le faire sur les docs courts** (< 500 tok) → coût > bénéfice.

## Critères de réussite

- ✅ Indexation contextualisée fonctionne sur 20+ docs
- ✅ Prompt caching activé et mesuré
- ✅ Gain mesurable sur eval set vs baseline
- ✅ Coût d'indexation acceptable (< $10 pour 100 docs)`,
      practice: `**Livrable** :

1. Pipeline indexation contextualisée avec prompt caching.
2. Comparaison eval set : baseline vs contextual vs contextual+hybrid+rerank.
3. Calcul du coût d'indexation pour 100 docs avec cache vs sans cache.

**Bonus** : essaie de générer le contexte avec Haiku (cheap) vs Sonnet, mesure si le gain qualité justifie le surcoût.`,
      quiz: [
        {
          question: "Pourquoi contextualiser les chunks améliore-t-il le retrieval ?",
          choices: [
            "Plus de tokens = mieux",
            "Un chunk isolé perd son contexte (qui, quand, où) ; le préfixer restore les ancres sémantiques pour matcher les queries",
            "Magie noire",
            "Aucun effet réel",
          ],
          answerIndex: 1,
          explanation:
            "Le contexte ajoute les ancres manquantes (entité, période, section) qui permettent au retrieval de matcher des queries qui mentionnent ces ancres.",
        },
        {
          question: "Pourquoi le prompt caching est crucial ici ?",
          choices: [
            "Pas crucial",
            "Sans cache, tu paies plein tarif le doc entier pour CHAQUE chunk indexé — coût x100",
            "Pour aller plus vite",
            "Aucun rapport",
          ],
          answerIndex: 1,
          explanation:
            "Avec cache, le doc full est payé 1× par document. Sans cache, 1× par chunk = explosion linéaire avec le nombre de chunks.",
        },
        {
          question: "Le contexte généré devrait peser combien de tokens ?",
          choices: [
            "10 tokens",
            "50-100 tokens — assez pour situer, pas trop pour ne pas diluer le chunk",
            "1000 tokens",
            "Aucune importance",
          ],
          answerIndex: 1,
          explanation:
            "Trop court : pas d'info utile. Trop long : dilue l'embedding du chunk réel et coûte cher.",
        },
      ],
      resources: [
        { label: "Anthropic — Contextual Retrieval", href: "https://www.anthropic.com/news/contextual-retrieval" },
      ],
    },
    {
      slug: "lab-rag-05-eval-ragas",
      moduleSlug: "lab-rag-agents",
      index: 5,
      title: "RAG-05 — Eval RAGAS et boucle d'amélioration",
      subtitle: "Faithfulness, answer relevance, context precision — la triade qui ferme la boucle",
      level: "expert",
      durationMin: 25,
      objectives: [
        "Installer RAGAS et lancer l'eval sur ton pipeline",
        "Interpréter faithfulness / answer relevance / context precision",
        "Identifier la métrique faible et l'améliorer en 1 itération",
        "Mettre l'eval en CI pour bloquer les régressions",
      ],
      vocalScript: `[Intro]
Le dernier exo RAG. Tu vas mesurer ton pipeline avec RAGAS — la bibliothèque standard 2025 — et faire une vraie itération basée sur les chiffres. C'est la signature d'un RAG ingénieur.

[Étape 1 - install]
Étape un : pip install ragas. Tu auras besoin d'une clé OpenAI ou Anthropic — RAGAS utilise un LLM-as-judge pour scorer.

[Étape 2 - format]
Étape deux : RAGAS attend un dataset HuggingFace avec quatre colonnes — question, answer (la réponse de ton pipeline), contexts (les chunks retrievés), ground_truths (la vérité). Tu construis ça depuis ton eval set.

[Étape 3 - run]
Étape trois : tu lances faithfulness, answer_relevancy, context_precision, context_recall. Quatre métriques entre zéro et un. Cible production : zéro virgule quatre-vingt-cinq et plus partout.

[Étape 4 - itère]
Étape quatre : identifie la métrique la plus faible. Si faithfulness est basse, ton LLM hallucine — renforce le prompt anti-hallucination. Si context precision est basse, ton retrieval est bruyant — relance RAG-zéro-trois sur le reranker. Itère, mesure, gagne.

[Étape 5 - CI]
Étape cinq : mets l'eval en GitHub Actions. À chaque PR qui touche un prompt ou un retriever, l'eval tourne. Si une métrique chute de plus de cinq pour cent, le merge est bloqué.

[Conclusion]
À la fin tu as ce que quatre-vingt-quinze pour cent des équipes RAG n'ont pas : une boucle qualité automatisée.`,
      visuals: [
        {
          title: "Les 4 métriques RAGAS",
          description:
            "Tableau : faithfulness (réponse ancrée dans contexts ?), answer_relevancy (répond à la Q ?), context_precision (chunks pertinents ?), context_recall (chunks couvrent la ground truth ?).",
        },
        {
          title: "Boucle d'amélioration",
          description:
            "Cycle : RAGAS run → identifier métrique faible → fix ciblé (prompt si faithfulness, retrieval si context) → re-run → compare.",
        },
      ],
      content: `## Étape 1 — Setup

\`\`\`bash
pip install ragas datasets
export OPENAI_API_KEY=...
\`\`\`

## Étape 2 — Format dataset

\`\`\`python
from datasets import Dataset

def build_eval_dataset(eval_set, pipeline):
    rows = []
    for q in eval_set:
        result = pipeline.run(q["question"])
        rows.append({
            "question": q["question"],
            "answer": result.answer,
            "contexts": [c.text for c in result.contexts],
            "ground_truth": q["expected_answer"],
        })
    return Dataset.from_list(rows)
\`\`\`

## Étape 3 — Run RAGAS

\`\`\`python
from ragas import evaluate
from ragas.metrics import (
    faithfulness, answer_relevancy,
    context_precision, context_recall,
)

ds = build_eval_dataset(eval_set, my_pipeline)
result = evaluate(
    ds,
    metrics=[faithfulness, answer_relevancy, context_precision, context_recall],
)
print(result)
\`\`\`

Output typique :

\`\`\`
{
  "faithfulness": 0.82,
  "answer_relevancy": 0.91,
  "context_precision": 0.74,    # ← maillon faible
  "context_recall": 0.88,
}
\`\`\`

## Étape 4 — Itération ciblée

| Métrique faible | Diagnostic probable | Fix |
|---|---|---|
| faithfulness < 0.85 | LLM invente, ignore le contexte | Renforce le prompt (force citations, "say I don't know") |
| answer_relevancy < 0.85 | Réponse off-topic | Améliore l'instruction de réponse, vérifie le rewrite query |
| context_precision < 0.85 | Trop de chunks non pertinents | Améliore reranker, augmente top_k retrieval/rerank ratio |
| context_recall < 0.85 | Chunks manquent l'info | Améliore chunking, contextual retrieval, hybrid |

Fais **UN** changement à la fois. Re-run. Compare.

## Étape 5 — CI

\`\`\`yaml
# .github/workflows/rag-eval.yml
name: RAG eval

on:
  pull_request:
    paths: ["prompts/**", "retrieval/**", "pipeline/**"]

jobs:
  eval:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -r requirements.txt
      - run: python eval/run.py --baseline main --candidate HEAD
        env:
          OPENAI_API_KEY: \${{ secrets.OPENAI_API_KEY }}
      - run: |
          python eval/check_regression.py --threshold 0.05
\`\`\`

## Pièges à éviter

- **Mesurer une seule métrique** → tu ignores les régressions ailleurs.
- **Eval set < 30 questions** → variance trop forte.
- **Re-run sans seed** → résultats non comparables. Fixe la seed du LLM judge.
- **Pas de baseline** → tu ne sais pas si tu progresses ou si tu régresses.
- **Itérer 5 choses en parallèle** → tu ne sais pas ce qui a aidé.

## Critères de réussite

- ✅ 4 métriques RAGAS mesurées, log historique
- ✅ Maillon faible identifié et amélioré (+5 points min)
- ✅ Eval en CI qui bloque les régressions
- ✅ Tu peux dire : "depuis Q1, faithfulness est passé de 0.80 à 0.91"`,
      practice: `**Livrable** :

1. Eval RAGAS qui tourne en local et en CI.
2. Rapport markdown : scores actuels, scores cible, plan d'amélioration.
3. Au moins une itération complète : mesure → diagnostic → fix → re-mesure → gain.

**Bonus** : ajoute une métrique custom — par exemple "average citation count per answer" — et trace-la dans le temps.`,
      quiz: [
        {
          question: "Si faithfulness est élevée mais context_precision faible, que se passe-t-il ?",
          choices: [
            "Tout va bien",
            "Le LLM répond correctement mais ramène beaucoup de chunks non pertinents (gaspillage tokens + dilution)",
            "C'est impossible",
            "Le retriever ne marche pas",
          ],
          answerIndex: 1,
          explanation:
            "Le LLM compense un retrieval bruyant — coût plus élevé, latence plus élevée, et fragilité quand le top n change.",
        },
        {
          question: "Pourquoi faire UN seul changement à la fois entre les runs ?",
          choices: [
            "Pas obligatoire",
            "Sinon tu ne sais pas quelle modif a causé le delta — méthode scientifique de base",
            "Pour aller plus lentement",
            "Aucune raison",
          ],
          answerIndex: 1,
          explanation:
            "Itération scientifique : un changement, une mesure, une attribution. Multiple changes = bruit, pas d'apprentissage.",
        },
        {
          question: "Quel est le rôle de l'eval en CI ?",
          choices: [
            "Décoration",
            "Bloquer les régressions silencieuses sur chaque PR qui touche le pipeline",
            "Faire perdre du temps",
            "Pas utile",
          ],
          answerIndex: 1,
          explanation:
            "Sans CI eval, tu shippes des régressions invisibles. La CI = circuit breaker qualité automatique.",
        },
      ],
      resources: [
        { label: "RAGAS — docs officielles", href: "https://docs.ragas.io/" },
      ],
    },
    {
      slug: "lab-agt-01-memory-layers",
      moduleSlug: "lab-rag-agents",
      index: 6,
      title: "AGT-01 — Memory layers (working / short / long)",
      subtitle: "Donner à ton agent une mémoire utile sans exploser le contexte",
      level: "expert",
      durationMin: 22,
      objectives: [
        "Distinguer 3 couches de mémoire et leur cycle de vie",
        "Implémenter working memory avec compression automatique",
        "Implémenter short-term memory (résumés de session)",
        "Implémenter long-term memory (RAG sur conversations passées)",
      ],
      vocalScript: `[Intro]
Tes agents jusqu'ici sont amnésiques. Chaque session ils repartent de zéro. Cet exo te fait construire trois couches de mémoire qui transforment ton agent en assistant qui se souvient.

[Étape 1 - working]
Étape un : working memory. C'est l'historique de la conversation courante. Tu le tronques intelligemment — garde les cinq derniers messages full, résume les plus anciens. Code en quinze lignes.

[Étape 2 - short-term]
Étape deux : short-term memory. Quand une session se termine, tu génères un résumé d'une centaine de tokens — quoi a été décidé, quoi reste à faire, quels faits importants. Tu le stockes par user.

[Étape 3 - long-term]
Étape trois : long-term memory. Tu indexes les résumés de session passées dans un vector store. Quand une nouvelle session démarre, tu retrieves les trois résumés les plus pertinents pour le contexte.

[Étape 4 - intégration]
Étape quatre : tu assembles. System prompt + long-term snippets retrieved + short-term summary du user + working memory courante. L'agent se souvient.

[Conclusion]
À la fin tu auras un agent qui a une histoire avec chaque user. C'est ce qui transforme un chatbot en assistant.`,
      visuals: [
        {
          title: "3 couches de mémoire",
          description:
            "Pyramide : working (turns courants, full text), short-term (summary de session, ~100 tok), long-term (vector store des summaries passés). TTL : minutes / jours / mois.",
        },
        {
          title: "Assemblage du prompt",
          description:
            "Composition : [system] + [long-term retrieved (top 3 past summaries)] + [short-term (this session summary)] + [working (last 5 msgs full)] → LLM.",
        },
      ],
      content: `## Étape 1 — Working memory avec compression

\`\`\`python
class WorkingMemory:
    def __init__(self, keep_full=5):
        self.messages = []
        self.summary = ""
        self.keep_full = keep_full

    async def add(self, role, content):
        self.messages.append({"role": role, "content": content})
        if len(self.messages) > self.keep_full * 2:
            # Compress older half
            to_compress = self.messages[:-self.keep_full]
            self.summary = await summarize(self.summary, to_compress)
            self.messages = self.messages[-self.keep_full:]

    def to_prompt_messages(self):
        msgs = []
        if self.summary:
            msgs.append({"role": "system", "content": f"Earlier in this conversation: {self.summary}"})
        msgs.extend(self.messages)
        return msgs
\`\`\`

## Étape 2 — Short-term (session summary)

\`\`\`python
SESSION_SUMMARY_PROMPT = """
Summarize this conversation for future reference. Include:
- User's main goal
- Decisions made
- Open items / next steps
- Key facts the user mentioned about themselves or their context

Limit: 150 tokens. Be specific, no fluff.
"""

async def end_session(user_id, working_memory):
    summary = await llm.complete(
        system=SESSION_SUMMARY_PROMPT,
        messages=working_memory.to_prompt_messages(),
    )
    db.upsert(f"session_summary:{user_id}:{now()}", summary)
    # also index in vector store for long-term
    await vector_store.add(
        text=summary.text,
        metadata={"user_id": user_id, "ts": now()}
    )
\`\`\`

## Étape 3 — Long-term (RAG sur passé)

\`\`\`python
async def long_term_context(user_id, current_user_msg, k=3):
    candidates = await vector_store.search(
        query=current_user_msg,
        filter={"user_id": user_id},
        k=k,
    )
    return "\\n".join(f"- ({c.metadata.ts}) {c.text}" for c in candidates)
\`\`\`

## Étape 4 — Assemblage

\`\`\`python
async def build_prompt(user_id, user_msg, working_mem):
    long_term = await long_term_context(user_id, user_msg)
    latest_short = db.get(f"session_summary:{user_id}:latest") or ""
    system = f"""
You're a helpful assistant.

<long_term_context>
Past relevant sessions with this user:
{long_term}
</long_term_context>

<latest_session_summary>
{latest_short}
</latest_session_summary>
"""
    return system, working_mem.to_prompt_messages()
\`\`\`

## Pièges à éviter

- **Inclure trop de long-term** → le contexte explose, le LLM se perd.
- **Stocker tout en clair** → respect des PII, encryption au repos.
- **Pas de TTL** sur le long-term → mémoire qui pourrit (faits obsolètes).
- **Résumer avec un modèle trop petit** → résumés bancals.

## Critères de réussite

- ✅ Working memory compresse au-delà de 10 messages, sans crasher
- ✅ Short-term summary généré à la fin de chaque session
- ✅ Long-term RAG retrieves 3 sessions passées pertinentes
- ✅ Sur une 3e session, l'agent se souvient d'une info de la 1ère session`,
      practice: `**Livrable** :

1. Module \`memory.py\` avec les 3 classes : WorkingMemory, ShortTerm, LongTerm.
2. Test bout-en-bout : 3 sessions consécutives avec un même user, vérifie que la 3e session "se souvient" d'un fait de la 1ère.
3. Mesure : combien de tokens économisés grâce à la compression vs garder full history ?

**Bonus** : ajoute un TTL et une "facts table" — quand l'agent apprend un fait stable (nom du chien, préférences), il l'écrit dans une mini-DB structurée séparée du résumé.`,
      quiz: [
        {
          question: "Pourquoi 3 couches plutôt qu'une grosse mémoire ?",
          choices: [
            "Pour faire compliqué",
            "Cycles de vie différents (turn / session / mois) + coût (full text / summary / vector retrieve)",
            "Aucune raison",
            "Imposé par les SDK",
          ],
          answerIndex: 1,
          explanation:
            "Chaque couche optimise un trade-off différent. Mélanger = soit tu paies trop (full history forever), soit tu perds (résumé brutal).",
        },
        {
          question: "Quand déclencher la compression du working memory ?",
          choices: [
            "Jamais",
            "Quand on dépasse N messages (typiquement 10-20) : on garde les derniers full + résumé des plus anciens",
            "À chaque turn",
            "À l'initialisation",
          ],
          answerIndex: 1,
          explanation:
            "Compression au-delà d'un seuil = garde le récent en clair (précis), résume le vieux (économique).",
        },
        {
          question: "Pourquoi un TTL sur la long-term memory ?",
          choices: [
            "Pas utile",
            "Les faits vieillissent et deviennent obsolètes ou faux — purger évite que l'agent réponde avec du stale",
            "Pour économiser du disque",
            "Pour l'esthétique",
          ],
          answerIndex: 1,
          explanation:
            "Une préférence d'il y a 2 ans peut être périmée. TTL ou requalification périodique évite l'agent qui agit sur des infos obsolètes.",
        },
      ],
      resources: [
        { label: "MemGPT (Letta) — long-term memory for agents", href: "https://github.com/letta-ai/letta" },
      ],
    },
    {
      slug: "lab-agt-02-checkpointing",
      moduleSlug: "lab-rag-agents",
      index: 7,
      title: "AGT-02 — Checkpointing et reprise",
      subtitle: "Ton agent crashe au step 47/100. Tu reprends. Tu ne recommences pas.",
      level: "expert",
      durationMin: 18,
      objectives: [
        "Sérialiser l'état complet d'un agent (messages + tools state)",
        "Implémenter save_checkpoint à chaque step",
        "Implémenter resume_from_checkpoint",
        "Tester la résilience en killant le process en plein run",
      ],
      vocalScript: `[Intro]
Ton agent tourne quarante-cinq minutes. Au step quarante-sept sur cent, ton process crashe — OOM, network, hostile, peu importe. Sans checkpoint, tu repars de zéro. Avec, tu reprends. Cet exo te fait construire le filet de sécurité.

[Étape 1 - state]
Étape un : identifie l'état à sérialiser. Au minimum : la liste de messages, le step counter, les tokens consommés, l'éventuel plan en cours. En option : les résultats de tools déjà exécutés — utile si rejouer coûte cher.

[Étape 2 - save]
Étape deux : à chaque step de la boucle, après l'exécution des tools, tu écris l'état dans un fichier JSON ou une row Postgres. Atomique — utilise rename pour éviter les fichiers corrompus.

[Étape 3 - resume]
Étape trois : un endpoint resume_from prend un checkpoint id, charge l'état, et reprend la boucle là où elle s'est arrêtée. Tu passes en argument les tools — ne les sérialise pas, ils ne sont pas portables.

[Étape 4 - test]
Étape quatre : test brutal. Tu lances un agent qui doit faire vingt steps. Tu kill le process au step dix. Tu resumes. Tu vérifies que les dix derniers steps s'exécutent et que le résultat final est identique à un run non interrompu.

[Conclusion]
À la fin tu as un agent prod-grade qui survit aux pannes. La majorité des frameworks ne le font pas par défaut.`,
      visuals: [
        {
          title: "Checkpoint cycle",
          description:
            "Loop : LLM call → tool exec → save_checkpoint(state) → next step. Si crash → load_checkpoint → resume from same step.",
        },
        {
          title: "Format d'un checkpoint",
          description:
            "JSON : { checkpoint_id, agent_id, step, messages, tokens_used, plan, tool_call_dedup_keys, ts }. Stocké en JSONL append-only.",
        },
      ],
      content: `## Étape 1 — Définir l'état

\`\`\`python
from dataclasses import dataclass, asdict, field
from typing import Any

@dataclass
class AgentState:
    agent_id: str
    step: int = 0
    messages: list = field(default_factory=list)
    tokens_used: int = 0
    plan: dict | None = None
    tool_results_cache: dict = field(default_factory=dict)  # tool_use_id -> result

    def to_json(self):
        return asdict(self)

    @classmethod
    def from_json(cls, data):
        return cls(**data)
\`\`\`

## Étape 2 — Save atomique

\`\`\`python
import os, json, tempfile

def save_checkpoint(state: AgentState, dir="./checkpoints"):
    os.makedirs(dir, exist_ok=True)
    path = f"{dir}/{state.agent_id}.json"
    # Écriture atomique : tmp file + rename
    with tempfile.NamedTemporaryFile("w", dir=dir, delete=False) as f:
        json.dump(state.to_json(), f, ensure_ascii=False)
        tmp = f.name
    os.replace(tmp, path)
\`\`\`

## Étape 3 — Boucle agent avec checkpoint

\`\`\`python
async def run_agent_resumable(state: AgentState, tools, max_steps=100):
    while state.step < max_steps:
        response = await llm.complete(messages=state.messages, tools=tools)
        state.tokens_used += response.usage.total_tokens
        state.messages.append({"role": "assistant", "content": response.content})

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            save_checkpoint(state)
            return state  # done

        # Exécuter, en utilisant le cache si on a déjà fait ce tool_use_id
        tool_results = []
        for tu in tool_uses:
            if tu.id in state.tool_results_cache:
                tr = state.tool_results_cache[tu.id]
            else:
                tr = await execute_tool(tu.name, tu.input)
                state.tool_results_cache[tu.id] = tr
            tool_results.append({"type": "tool_result", "tool_use_id": tu.id, "content": tr})

        state.messages.append({"role": "user", "content": tool_results})
        state.step += 1
        save_checkpoint(state)  # save AFTER state update
    return state
\`\`\`

## Étape 4 — Resume

\`\`\`python
def load_checkpoint(agent_id, dir="./checkpoints") -> AgentState:
    with open(f"{dir}/{agent_id}.json") as f:
        return AgentState.from_json(json.load(f))

# Usage :
state = load_checkpoint("agent_abc")  # state already at step 10
result = await run_agent_resumable(state, tools)
\`\`\`

## Étape 5 — Test brutal

\`\`\`python
async def test_resume():
    # 1. Lance un agent qui doit faire 20 steps
    state = AgentState(agent_id="test")
    task1 = asyncio.create_task(run_agent_resumable(state, tools, max_steps=20))
    await asyncio.sleep(5)
    task1.cancel()  # simulate crash

    # 2. Reload + resume
    state2 = load_checkpoint("test")
    print(f"Resumed at step {state2.step}")
    final = await run_agent_resumable(state2, tools, max_steps=20)
    assert final.step == 20
\`\`\`

## Pièges à éviter

- **Écriture non atomique** → fichier corrompu si crash en plein write.
- **Cache de tool_results sans dedup_key** → tools idempotents oui, mais identifie par tool_use_id.
- **Sérialiser les tools** → ne le fais pas, ils ne sont pas portables. Passe en argument au resume.
- **Pas de validation de schéma** au load → si tu changes AgentState, vieux checkpoints cassent silencieusement.

## Critères de réussite

- ✅ Save atomique vérifié (cat checkpoint pendant un run = toujours valide)
- ✅ Resume après kill -9 reprend au bon step
- ✅ Tool results déjà exécutés sont re-utilisés depuis le cache
- ✅ Versionner le schéma (champ \`schema_version\`)`,
      practice: `**Livrable** :

1. Module \`checkpoint.py\` avec save/load atomiques.
2. Boucle agent qui sauve à chaque step.
3. Test \`test_resume.py\` qui kill + resume et vérifie l'idempotence.

**Bonus** : stockage en Postgres (table \`agent_checkpoints\`) au lieu de JSON file, avec lock optimiste pour éviter double-run.`,
      quiz: [
        {
          question: "Pourquoi l'écriture atomique du checkpoint ?",
          choices: [
            "Pour la performance",
            "Pour éviter qu'un crash en plein write produise un fichier corrompu illisible au reload",
            "Aucune raison",
            "Pour le SEO",
          ],
          answerIndex: 1,
          explanation:
            "Sans atomic write, un crash mid-write = checkpoint cassé. tmp file + os.replace garantit qu'on n'observe que des états complets.",
        },
        {
          question: "Pourquoi sérialiser les tool_results dans le checkpoint ?",
          choices: [
            "Inutile",
            "Pour éviter de ré-exécuter des tools coûteux/non-idempotents lors du resume",
            "Pour le debug uniquement",
            "Aucune raison",
          ],
          answerIndex: 1,
          explanation:
            "Sans cache, un resume re-appelle les tools déjà passés — gaspillage si gros tools, danger si non-idempotents.",
        },
        {
          question: "Comment versionner un checkpoint pour ne pas casser après une refacto ?",
          choices: [
            "Espérer que rien ne change",
            "Ajouter un champ schema_version et écrire des migrations à la lecture",
            "Garder un seul format pour toujours",
            "Impossible",
          ],
          answerIndex: 1,
          explanation:
            "Comme les migrations DB : version explicite + fonction de migration permet d'évoluer sans casser le passé.",
        },
      ],
      resources: [
        { label: "LangGraph — checkpointing", href: "https://langchain-ai.github.io/langgraph/concepts/persistence/" },
      ],
    },
    {
      slug: "lab-agt-03-self-recovery",
      moduleSlug: "lab-rag-agents",
      index: 8,
      title: "AGT-03 — Self-recovery (l'agent qui se corrige)",
      subtitle: "Détecter ses propres erreurs et replanifier",
      level: "expert",
      durationMin: 20,
      objectives: [
        "Détecter automatiquement un échec (tool error, output invalide, plan dead-end)",
        "Implémenter une étape critique 'self-reflection'",
        "Replanifier ou retry avec leçon apprise",
        "Éviter les boucles infinies de retry",
      ],
      vocalScript: `[Intro]
Le plus gros écart entre amateur et pro sur les agents : la self-recovery. Un agent amateur plante et reste planté. Un agent pro détecte qu'il a échoué, comprend pourquoi, et adapte. Cet exo te fait construire ce muscle.

[Étape 1 - signaux]
Étape un : identifie les signaux d'échec. Tool qui retourne une erreur. Output qui rate une validation — JSON invalide, format manqué. Plan qui semble bloqué — tu fais le même tool call cinq fois sans progression. Stagnation détectée par token count qui croît sans new info.

[Étape 2 - reflect]
Étape deux : tu intercales un step de réflexion. Quand un signal de failure est levé, tu demandes au LLM : "tu viens d'échouer sur X — voici les détails — qu'est-ce qui n'a pas marché et que devrais-tu faire différemment ?" Tu stockes la réponse comme une leçon.

[Étape 3 - retry avec leçon]
Étape trois : tu retries le step, mais avec la leçon injectée dans le prompt. C'est ce qui distingue un retry intelligent d'un retry idiot.

[Étape 4 - garde-fou]
Étape quatre : max retries par signal de failure — typiquement trois. Au-delà, escalade vers l'humain ou abandonne proprement. Sinon, boucle infinie garantie.

[Conclusion]
À la fin tu auras un agent qui apprend en cours de mission. Pas du fine-tuning, du in-context recovery. Très puissant.`,
      visuals: [
        {
          title: "Boucle self-recovery",
          description:
            "Step normal → exec → check signals (tool err, invalid output, stagnation) → si failure : reflect → store lesson → retry with lesson. Compteur retries max 3.",
        },
        {
          title: "Détection stagnation",
          description:
            "Heuristique : N derniers tool_calls identiques OU token count croît > 50% sans nouveau pattern. → trigger reflect.",
        },
      ],
      content: `## Étape 1 — Détecteurs d'échec

\`\`\`python
class FailureDetector:
    def __init__(self, stagnation_window=4):
        self.recent_tool_calls = []
        self.stagnation_window = stagnation_window

    def check_tool_result(self, tool_result):
        if isinstance(tool_result, dict) and tool_result.get("error"):
            return {"failure": "tool_error", "detail": tool_result["error"]}
        return None

    def check_output_format(self, output, schema=None):
        if schema and not validate(output, schema):
            return {"failure": "invalid_format", "detail": "schema mismatch"}
        return None

    def check_stagnation(self, tool_call):
        self.recent_tool_calls.append(tool_call)
        recent = self.recent_tool_calls[-self.stagnation_window:]
        if len(recent) == self.stagnation_window and len(set(map(str, recent))) == 1:
            return {"failure": "stagnation", "detail": "same tool call repeated"}
        return None
\`\`\`

## Étape 2 — Self-reflection

\`\`\`python
REFLECT_PROMPT = """
You just encountered a failure during your task.

<failure>
Type: {failure_type}
Detail: {detail}
</failure>

<recent_actions>
{recent_messages}
</recent_actions>

Reflect briefly:
1. What went wrong specifically?
2. What's the ROOT cause (not just symptom)?
3. What SHOULD you do differently in the next attempt?

Return JSON: {{"root_cause": "...", "next_strategy": "..."}}
"""

async def reflect(failure, recent_messages):
    return await llm.complete_json(REFLECT_PROMPT.format(
        failure_type=failure["failure"],
        detail=failure["detail"],
        recent_messages=recent_messages[-5:],
    ))
\`\`\`

## Étape 3 — Retry avec leçon

\`\`\`python
async def run_with_recovery(initial_state, tools, max_recovery=3):
    state = initial_state
    detector = FailureDetector()
    lessons = []
    recovery_count = 0

    while state.step < state.max_steps:
        # Inject lessons in system prompt
        sys_with_lessons = SYSTEM_PROMPT
        if lessons:
            sys_with_lessons += "\\n\\n<lessons_from_previous_failures>\\n"
            sys_with_lessons += "\\n".join(f"- {l}" for l in lessons)
            sys_with_lessons += "\\n</lessons_from_previous_failures>"

        response = await llm.complete(system=sys_with_lessons, messages=state.messages, tools=tools)
        # ... execute tools, check failure ...
        for tu, tr in tool_calls_with_results:
            failure = detector.check_tool_result(tr) or detector.check_stagnation(tu)
            if failure:
                if recovery_count >= max_recovery:
                    return {"status": "abandoned", "reason": failure}
                reflection = await reflect(failure, state.messages)
                lessons.append(reflection["next_strategy"])
                recovery_count += 1
                # Rewind state to before the failed action
                state = rewind_to(state, before=failure)
                break
        else:
            recovery_count = 0  # reset on success
        state.step += 1
\`\`\`

## Étape 4 — Test

Scenario test : un tool qui plante systématiquement avec input X. L'agent devrait :
1. Essayer X → fail
2. Reflect : "X cause un timeout, essayer Y"
3. Essayer Y → success
Sans recovery, l'agent boucle ou abandonne. Avec recovery, il passe.

## Pièges à éviter

- **Reflect sans cap** → boucle où chaque retry échoue et déclenche un autre reflect.
- **Ne pas rewind l'état** → tu retries avec l'historique pollué de l'erreur.
- **Leçons trop spécifiques** ("X a échoué à 14h32") → utilité nulle. Force le LLM à formuler la leçon en termes généralisables.
- **Pas d'escalade humaine** → certains échecs ne peuvent pas être auto-résolus.

## Critères de réussite

- ✅ 3 types de failure détectés (tool error, invalid output, stagnation)
- ✅ Reflect produit des leçons exploitables
- ✅ Max 3 retries avec escalade ensuite
- ✅ Test : agent passe une tâche qui aurait échoué sans recovery`,
      practice: `**Livrable** :

1. Module \`recovery.py\` avec FailureDetector et reflect().
2. Boucle agent intégrée.
3. Test : tâche qui inclut un tool flaky → agent termine grâce à la recovery.

**Bonus** : persiste les leçons cross-sessions (long-term memory) — l'agent "apprend" entre runs.`,
      quiz: [
        {
          question: "Pourquoi rewind l'état après une failure détectée ?",
          choices: [
            "Pas nécessaire",
            "Sinon le retry contient l'historique pollué (tool error visible) qui peut perturber le retry",
            "Pour l'esthétique",
            "Aucune raison",
          ],
          answerIndex: 1,
          explanation:
            "Rewind = retry avec un état propre + leçon en system prompt. Sans rewind, le LLM voit l'erreur comme du contexte et peut tourner en rond.",
        },
        {
          question: "Pourquoi un cap sur les retries ?",
          choices: [
            "Pas obligatoire",
            "Sinon boucle infinie quand le failure n'est pas auto-résoluble → coût explose, latence aussi",
            "Pour le fun",
            "Aucune raison",
          ],
          answerIndex: 1,
          explanation:
            "Tous les échecs ne sont pas récupérables. Cap (typiquement 3) + escalade humaine ou abort propre.",
        },
        {
          question: "Comment écrire une 'leçon' utile ?",
          choices: [
            "Très spécifique : 'X a échoué à 14h32'",
            "Généralisable : 'quand le tool Y reçoit un format Z, il timeout — utiliser format W à la place'",
            "Aucune importance",
            "Le plus long possible",
          ],
          answerIndex: 1,
          explanation:
            "Une leçon trop spécifique ne s'applique qu'une fois. Une leçon généralisable change le comportement sur tous les cas similaires.",
        },
      ],
      resources: [
        { label: "Reflexion paper (Shinn et al. 2023)", href: "https://arxiv.org/abs/2303.11366" },
      ],
    },
    {
      slug: "lab-agt-04-human-in-the-loop",
      moduleSlug: "lab-rag-agents",
      index: 9,
      title: "AGT-04 — Human-in-the-loop (HITL)",
      subtitle: "Patterns pause/approve/reject pour les actions sensibles",
      level: "expert",
      durationMin: 18,
      objectives: [
        "Identifier les actions qui requièrent un go humain",
        "Implémenter un pattern 'propose then commit'",
        "Pauser l'agent et reprendre après décision humaine",
        "Tracer toutes les approbations pour audit",
      ],
      vocalScript: `[Intro]
Un agent qui peut envoyer des paiements, supprimer des fichiers, ou poster en public sans validation humaine, c'est un agent qui finira par te coûter cher. Cet exo te fait construire le checkpoint humain.

[Étape 1 - taxonomie]
Étape un : liste les actions qui doivent passer par un humain. Tout ce qui modifie l'état réel et n'est pas trivialement réversible. Paiements, mails sortants, suppressions, posts publics, déploiements prod. Plus tout ce qui est ambigu — l'agent dans le doute demande.

[Étape 2 - propose then commit]
Étape deux : pattern "propose then commit". L'agent ne fait pas l'action directement. Il appelle un tool propose_X qui crée une intention, et un tool commit_X qui l'exécute. Entre les deux, un humain dit oui ou non.

[Étape 3 - pause-resume]
Étape trois : techniquement, l'agent pause sur l'attente d'une approbation. Tu sérialises son état comme dans AGT-zéro-deux, et tu attends. L'humain reçoit une notif, clique approve ou reject, et tu resumes l'agent avec la décision injectée.

[Étape 4 - audit]
Étape quatre : log immuable de toutes les approbations — qui, quand, quoi, raison optionnelle. Indispensable pour compliance, débuggage post-incident, ou simplement pour réviser les patterns d'usage.

[Conclusion]
À la fin tu as un agent qui peut faire des choses sérieuses sans risque incontrôlé. C'est ce qui débloque les use cases enterprise.`,
      visuals: [
        {
          title: "Propose then commit",
          description:
            "Flow : agent → tool propose_payment → DB pending → notify human → human approve/reject → agent resumes → tool commit_payment OU abort. Tracé dans audit log.",
        },
        {
          title: "Niveaux d'approbation",
          description:
            "Matrice : trivial (auto), reversible (auto), sensitive (user confirm), destructive (admin confirm), high-impact (multi-sign).",
        },
      ],
      content: `## Étape 1 — Classer tes actions

| Action | Niveau | Mécanisme |
|---|---|---|
| read_file | Auto | rien |
| send_email | Sensitive | user confirm |
| delete_files | Destructive | admin confirm |
| send_payment > $1k | High-impact | multi-sign |
| post_publicly | Sensitive | user confirm |

## Étape 2 — Propose then commit

\`\`\`python
# Tools exposés à l'agent
tools = [
    {
        "name": "propose_payment",
        "description": "Propose a payment for human approval. Does NOT execute immediately.",
        "input_schema": { "amount": "number", "to": "string", "reason": "string" }
    },
    {
        "name": "commit_payment",
        "description": "Execute a previously approved payment.",
        "input_schema": { "proposal_id": "string" }
    },
]

# Backend
async def propose_payment(amount, to, reason, session_id):
    proposal = await db.proposals.insert({
        "type": "payment",
        "amount": amount, "to": to, "reason": reason,
        "session_id": session_id,
        "status": "pending",
        "created_at": now(),
    })
    await notify_human(proposal)  # email, Slack, push, etc.
    return {"proposal_id": proposal.id, "status": "pending_approval"}

async def commit_payment(proposal_id):
    p = await db.proposals.get(proposal_id)
    if p.status != "approved":
        return {"error": "not_approved", "status": p.status}
    result = await payment_gateway.charge(p.to, p.amount, idempotency_key=proposal_id)
    await db.proposals.update(proposal_id, {"status": "committed", "result": result})
    await audit_log.append({"event": "payment_committed", "proposal_id": proposal_id})
    return {"status": "ok", "tx_id": result.tx_id}
\`\`\`

## Étape 3 — Pause + resume

\`\`\`python
async def run_agent_with_approval(state, tools):
    while True:
        response = await llm.complete(messages=state.messages, tools=tools)
        # ... if tool_use is propose_X ...
        # Execute propose, get proposal_id
        # Save checkpoint with proposal_id pending
        save_checkpoint(state, pending_proposal=proposal_id)
        return {"status": "awaiting_approval", "proposal_id": proposal_id}

# Quand l'humain approuve :
async def on_approval(proposal_id, decision, by_user):
    await db.proposals.update(proposal_id, {
        "status": decision,  # approved | rejected
        "decided_by": by_user, "decided_at": now()
    })
    # Trouver l'agent qui attend et le resumer
    state = load_checkpoint_by_proposal(proposal_id)
    state.messages.append({
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": ..., "content": {
            "approved": decision == "approved",
            "decided_by": by_user
        }}]
    })
    await run_agent_with_approval(state, tools)
\`\`\`

## Étape 4 — Audit log immuable

\`\`\`python
async def audit(event_type, **kwargs):
    entry = {
        "ts": now_iso(),
        "event_type": event_type,
        **kwargs,
    }
    # Append-only, signé optionnel
    with open("audit.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\\n")
\`\`\`

Tout : proposition créée, approuvée, rejetée, committée, abortée, expirée.

## Pièges à éviter

- **Action directe sans propose** → un seul oubli et tu envoies $10k.
- **Pas de TTL sur les proposals** → un humain approve une proposition vieille d'une semaine, contexte plus le même.
- **Pas d'idempotency_key** sur commit → si l'agent retry le commit après timeout, double paiement.
- **Audit log mutable** → un attaquant peut effacer ses traces.

## Critères de réussite

- ✅ Au moins 2 actions sensibles passent par propose/commit
- ✅ Agent peut être pausé sur attente et resumé
- ✅ Audit log capture qui/quand/quoi
- ✅ Test : reject explicite → agent abandonne proprement et explique au user`,
      practice: `**Livrable** :

1. Tools \`propose_X\` / \`commit_X\` pour 2 actions sensibles (au choix).
2. UI minimale (CLI ou web) pour approuver/rejeter les proposals pending.
3. Audit log \`audit.jsonl\`.
4. Scénario démo : agent propose, tu rejettes, agent adapte sa réponse user.

**Bonus** : TTL 1h sur les proposals, auto-expiration → notifier l'humain et abort l'agent.`,
      quiz: [
        {
          question: "Pourquoi le pattern propose/commit plutôt qu'un simple 'confirmation interactive' ?",
          choices: [
            "C'est pareil",
            "Permet de pauser l'agent, libérer la session, et reprendre plus tard quand l'humain décide — async natif",
            "Pour le fun",
            "Aucune raison",
          ],
          answerIndex: 1,
          explanation:
            "Confirmation synchrone bloque la session et fail si l'humain met 10 min. Propose/commit décorrèle agent et humain.",
        },
        {
          question: "Pourquoi l'idempotency_key sur le commit ?",
          choices: [
            "Pas obligatoire",
            "Pour éviter qu'un retry du commit (timeout, re-run agent) exécute l'action 2 fois",
            "Décoratif",
            "Pour la latence",
          ],
          answerIndex: 1,
          explanation:
            "Sans clé d'idempotence, retry = double exécution. Avec, le second appel est dedup côté backend.",
        },
        {
          question: "Pourquoi l'audit log doit-il être append-only / immuable ?",
          choices: [
            "Pour faire bien",
            "Compliance + sécurité : empêche un attaquant (ou un bug) d'effacer la trace d'actions sensibles",
            "Pour économiser de l'espace",
            "Aucune raison",
          ],
          answerIndex: 1,
          explanation:
            "Un audit log modifiable n'a aucune valeur de preuve. Append-only + signing optionnel garantit l'intégrité.",
        },
      ],
      resources: [
        { label: "LangGraph — Human-in-the-Loop", href: "https://langchain-ai.github.io/langgraph/concepts/human_in_the_loop/" },
      ],
    },
    {
      slug: "lab-agt-05-debug-trace",
      moduleSlug: "lab-rag-agents",
      index: 10,
      title: "AGT-05 — Debug a broken agent (capstone)",
      subtitle: "On te donne une trace qui foire. Tu trouves le bug. Tu fix.",
      level: "expert",
      durationMin: 30,
      objectives: [
        "Lire une trace OTel/Langfuse-like",
        "Identifier 4 bugs classiques d'agent (tool, prompt, loop, memory)",
        "Reproduire localement avec replay",
        "Proposer un fix testable",
      ],
      vocalScript: `[Intro]
Dernier exo. Capstone du lab. On te file la trace d'un agent qui a foiré une mission. Tu joues le détective, tu trouves la cause, tu proposes un fix. C'est ce que tu feras toute ta carrière de AI builder, alors entraîne-toi.

[Étape 1 - lire]
Étape un : lire la trace. Tu ouvres le JSONL, tu regardes les spans dans l'ordre. Pour chaque LLM call, regarde le prompt input, l'output, les tokens. Pour chaque tool call, regarde input, output, latence, erreur éventuelle.

[Étape 2 - signaux]
Étape deux : repère les signaux. Tool error répété ? Output bizarre ? Tool call avec mauvais arguments ? Step counter qui grimpe vite ? Token output minuscule sur un step où on attendait du raisonnement ? Chaque pattern correspond à une cause connue.

[Étape 3 - quatre bugs]
Étape trois : on te file quatre traces, chacune avec un bug. Bug un : tool description ambiguë qui fait choisir le mauvais tool. Bug deux : prompt qui demande un format que le LLM ne sait pas suivre, retry en boucle. Bug trois : memory qui contamine — la session précédente leak dans la suivante. Bug quatre : tool result mal parsé qui fait croire à l'agent que tout va bien alors que non.

[Étape 4 - replay]
Étape quatre : pour chacun, tu reproduis localement en re-jouant les LLM calls avec les mêmes prompts. Tu identifies la divergence. Tu écris le fix. Tu re-runs la trace, tu vérifies que la sortie est bonne.

[Conclusion]
À la fin de cet exo, tu sais débugger un agent. C'est rare. C'est précieux. C'est la dernière marche.`,
      visuals: [
        {
          title: "Anatomy d'une trace",
          description:
            "Timeline verticale : t=0 user input, t=100ms LLM call (in/out/tokens), t=1.2s tool_call (in/out/err), t=1.5s LLM call, ... t=8s output final. Annotations sur les bugs typiques.",
        },
        {
          title: "Top 4 bugs",
          description:
            "Tableau : Bug | Signal | Fix typique. Tool ambigu → tool choisi à tort. Format strict raté → retry x N. Memory leak → infos d'autres sessions. Tool result mal parsé → succès fictif.",
        },
      ],
      content: `## Format de trace fourni

\`\`\`jsonl
{"t": 0, "type": "user", "content": "Trouve la dernière facture de Pierre"}
{"t": 120, "type": "llm_call", "model": "sonnet", "in_tokens": 1200, "out_tokens": 180, "tool_uses": [{"id":"t1","name":"search_user","input":{"name":"Pierre"}}]}
{"t": 320, "type": "tool_result", "id": "t1", "output": {"matches": [{"id":"u1"}, {"id":"u2"}, {"id":"u3"}], "count": 3}}
{"t": 450, "type": "llm_call", "tool_uses":[{"id":"t2","name":"get_invoice","input":{"user_id":"u1"}}]}
...
\`\`\`

## Bug #1 — Tool ambigu

**Signal** : l'agent appelle \`get_invoice\` directement après un \`search_user\` qui retourne 3 matches.

**Cause** : la description de \`get_invoice\` ne dit pas "use only after disambiguating the user".

**Fix** : améliorer la description :
\`\`\`
"Use ONLY when you have a single, confirmed user_id. If search returned multiple matches, first call ask_user_for_disambiguation."
\`\`\`

## Bug #2 — Format strict raté en boucle

**Signal** : 6 LLM calls avec out_tokens élevé, à chaque fois suivi d'un message system "JSON parse error".

**Cause** : le prompt demande un JSON mais avec des nested arrays compliqués. Le modèle sort du markdown.

**Fix** : utiliser structured output natif (json_schema) au lieu d'instructions textuelles. Ou bien simplifier le schéma.

## Bug #3 — Memory leak

**Signal** : la réponse mentionne "votre dernier achat de chaussures" alors que l'utilisateur a demandé une facture pro. La long-term memory contient une session perso datée.

**Cause** : filter manquant sur le user_id ou le context (perso vs pro).

**Fix** : ajouter un filter de scope au retrieval long-term memory + tag chaque session par context.

## Bug #4 — Tool result mal parsé

**Signal** : l'agent dit "Facture trouvée : INV-9982" mais le tool_result est \`{"error": "no_invoice_found"}\`.

**Cause** : code de parsing qui fait \`tool_result.get("invoice_id") or "INV-DEFAULT"\` — masque l'erreur.

**Fix** : remonter explicitement les erreurs au modèle :
\`\`\`python
if "error" in result:
    return {"error": result["error"], "hint": "tool failed, do not assume success"}
\`\`\`

## Méthodo de debug

1. **Read top-down** la trace, sans interpréter.
2. **Mark anomalies** : tool error, retry, out_tokens anormal, latence p99.
3. **Hypothesize** : pour chaque anomalie, formule 2-3 causes possibles.
4. **Replay** localement avec le même prompt + même tool result, vérifie si tu reproduis.
5. **Bisect** : modifie une variable à la fois pour confirmer la cause.
6. **Fix + test** : ajoute le bug en eval set, vérifie que le fix passe.

## Critères de réussite (capstone)

- ✅ Tu as identifié les 4 bugs sans regarder la solution
- ✅ Tu as reproduit localement chaque bug
- ✅ Tes 4 fixes sont mergeables (PR-ready)
- ✅ Tu as ajouté 4 cas à ton eval set pour bloquer la régression`,
      practice: `**Capstone final** :

On te fournit 4 traces JSONL (à toi de les construire — utilise ton agent existant et casse-le intentionnellement de 4 façons).

Pour chaque trace :
1. Diagnostique en moins de 10 minutes.
2. Reproduis localement.
3. Propose un fix mergeable.
4. Ajoute un cas eval qui aurait attrapé le bug.

**Livrable final** :
- Document markdown récap des 4 bugs trouvés.
- 4 fixes en code.
- 4 cas eval ajoutés.

**Tu as fini la formation.** Tu es maintenant équipé pour bâtir des agents IA de très haut niveau, en prod, en équipe, à l'échelle.`,
      quiz: [
        {
          question: "Premier réflexe en lisant une trace cassée ?",
          choices: [
            "Réécrire le système",
            "Lire top-down sans interpréter, marquer les anomalies (errors, retries, out_tokens anormal)",
            "Demander au senior",
            "Relancer pour voir si ça marche",
          ],
          answerIndex: 1,
          explanation:
            "Une trace contient toutes les infos. Lecture méthodique d'abord, hypothèses ensuite — pas l'inverse.",
        },
        {
          question: "Comment éviter que le tool result fasse croire à un succès quand c'est un échec ?",
          choices: [
            "Espérer que le LLM devine",
            "Retourner explicitement {error, hint} au modèle, ne JAMAIS silently fallback sur une valeur par défaut",
            "Ignorer le problème",
            "Toujours retourner success",
          ],
          answerIndex: 1,
          explanation:
            "Le silent fallback est le pire pattern : l'agent agit comme si tout allait bien. Erreurs explicites = agent peut adapter.",
        },
        {
          question: "Pourquoi ajouter chaque bug trouvé à l'eval set ?",
          choices: [
            "Pour gonfler les chiffres",
            "Pour bloquer la régression future — sinon le bug peut revenir silencieusement",
            "Pas utile",
            "Pour augmenter la facture",
          ],
          answerIndex: 1,
          explanation:
            "Un bug trouvé = un cas test obligatoire. Sinon, il reviendra à la prochaine refacto. C'est la TDD appliquée aux agents.",
        },
      ],
      resources: [
        { label: "Langfuse — Tracing for LLM apps", href: "https://langfuse.com/" },
        { label: "OpenTelemetry — GenAI conventions", href: "https://opentelemetry.io/docs/specs/semconv/gen-ai/" },
      ],
    },
  ],
};
