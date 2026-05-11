export const metadata = { title: "Roadmap — AI Builder Academy" };

export default function RoadmapPage() {
  const phases = [
    {
      phase: "Phase 1 — Bases solides (semaines 1-2)",
      items: [
        "Module 1 : Fondations LLM",
        "Module 2 : Prompt engineering avancé",
        "Module 3 : Tool use & function calling",
        "Livrable : un agent simple avec 3 tools, observability minimale",
      ],
    },
    {
      phase: "Phase 2 — RAG production (semaines 3-4)",
      items: [
        "Module 4 : RAG avancé (chunking, hybrid, reranking)",
        "Mini-projet RAG complet sur un corpus réel",
        "Eval set RAGAS, mesure faithfulness + precision",
        "Livrable : RAG bout-en-bout avec citations vérifiées",
      ],
    },
    {
      phase: "Phase 3 — Agents et systèmes (semaines 5-7)",
      items: [
        "Module 5 : Architecture d'agent + ReAct/Plan-Execute",
        "Module 6 : MCP — construire un serveur",
        "Module 7 : Multi-agents (router, supervisor)",
        "Livrable : orchestrator avec 2 subagents et tracing complet",
      ],
    },
    {
      phase: "Phase 4 — Production (semaines 8-10)",
      items: [
        "Module 8 : Eval, observability, sécurité",
        "Module 9 : Coût, latence, business case",
        "Red team de ton agent",
        "Livrable : ton produit IA avec dashboard, alertes, business case 1-pager",
      ],
    },
    {
      phase: "Phase 5 — Au-delà",
      items: [
        "Lancer en bêta privée auprès de 5-10 users",
        "Itérer sur leurs retours pendant 4 semaines",
        "Décider : scale, pivot, ou kill",
        "Tu es maintenant un AI builder pro.",
      ],
    },
  ];
  return (
    <div className="max-w-3xl mx-auto px-5 py-10 sm:py-14">
      <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight">Roadmap 10 semaines</h1>
      <p className="mt-2 text-muted">
        Un parcours ramassé pour passer de "je connais les bases" à "j'ai un produit IA en
        production". Adapte le rythme à ton temps disponible — 4h/semaine est un bon minimum.
      </p>
      <div className="mt-10 space-y-6">
        {phases.map((p, i) => (
          <div key={i} className="bg-panel border border-border rounded-xl p-5">
            <h2 className="text-lg font-semibold">{p.phase}</h2>
            <ul className="mt-3 space-y-1.5 text-sm text-text/90">
              {p.items.map((it, j) => (
                <li key={j} className="flex gap-2">
                  <span className="text-accent2">•</span>
                  <span>{it}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
