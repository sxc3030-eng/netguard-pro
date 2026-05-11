export const metadata = { title: "À propos — AI Builder Academy" };

export default function AboutPage() {
  return (
    <div className="max-w-3xl mx-auto px-5 py-10 sm:py-14 space-y-6">
      <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight">À propos</h1>
      <p className="text-text/90 leading-relaxed">
        AI Builder Academy est une formation auto-portée pour devenir un AI builder de très
        haut niveau. Niveau intermédiaire à expert, biais "production" : pas de théorie sans
        exercice, pas d'exercice sans mesure.
      </p>

      <section className="bg-panel border border-border rounded-xl p-5">
        <h2 className="text-lg font-semibold">Format</h2>
        <ul className="mt-3 space-y-1.5 text-sm">
          <li>🎙️ <strong>Vocal</strong> : chaque leçon a un script narré, jouable directement dans le navigateur (synthèse vocale Web Speech, gratuite, fonctionne sur mobile).</li>
          <li>🖼️ <strong>Visuel</strong> : visuels décrits + schémas ASCII pour les concepts clés.</li>
          <li>📚 <strong>Texte</strong> : contenu Markdown structuré, avec code et tableaux.</li>
          <li>🛠️ <strong>Pipeline</strong> : exercice pratique de type pipeline ou mini-projet.</li>
          <li>✅ <strong>Quiz</strong> : 3 QCM avec explications.</li>
          <li>📖 <strong>Ressources</strong> : liens vers papers, docs et outils.</li>
        </ul>
      </section>

      <section className="bg-panel border border-border rounded-xl p-5">
        <h2 className="text-lg font-semibold">Pour qui</h2>
        <p className="mt-2 text-sm text-text/85">
          Devs et makers qui maîtrisent déjà les bases (appels API LLM, tool calling simple)
          et veulent franchir la marche entre "POC qui marche" et "produit qui tient en
          production".
        </p>
      </section>

      <section className="bg-panel border border-border rounded-xl p-5">
        <h2 className="text-lg font-semibold">Bilingue FR/EN</h2>
        <p className="mt-2 text-sm text-text/85">
          Tout le contenu est en français, mais les termes techniques sont en anglais (tokens,
          prompt, embedding, retrieval, etc.) — c'est la langue de travail du domaine et tu en
          auras besoin partout.
        </p>
      </section>

      <section className="bg-panel border border-border rounded-xl p-5">
        <h2 className="text-lg font-semibold">Open + extensible</h2>
        <p className="mt-2 text-sm text-text/85">
          Tout le contenu est en TypeScript dans <code className="bg-bg px-1.5 py-0.5 rounded text-accent2 text-xs">lib/lessons/</code>.
          Tu peux ajouter tes propres modules, leçons, exercices. C'est un curriculum vivant,
          pas un cours figé.
        </p>
      </section>
    </div>
  );
}
