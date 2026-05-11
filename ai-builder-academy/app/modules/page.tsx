import Link from "next/link";
import { curriculum } from "@/lib/curriculum";

export const metadata = { title: "Modules — AI Builder Academy" };

export default function ModulesPage() {
  return (
    <div className="max-w-5xl mx-auto px-5 py-10 sm:py-14">
      <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight">Curriculum complet</h1>
      <p className="mt-2 text-muted max-w-2xl">
        9 modules · {curriculum.reduce((s, m) => s + m.lessons.length, 0)} leçons. Chaque leçon
        contient : objectifs, script vocal jouable, visuels décrits, contenu détaillé, exercice
        pratique de type pipeline, quiz et ressources.
      </p>
      <div className="mt-10 space-y-8">
        {curriculum.map((m) => (
          <section key={m.slug} className="bg-panel border border-border rounded-xl p-5 sm:p-6">
            <div className="flex flex-wrap items-baseline justify-between gap-2 mb-1">
              <h2 className="text-xl sm:text-2xl font-semibold">
                <span className={`bg-gradient-to-r ${m.color} bg-clip-text text-transparent`}>
                  Module {m.index}
                </span>{" "}
                · {m.title}
              </h2>
              <span className="text-xs text-muted">
                {m.lessons.length} leçons · {m.lessons.reduce((s, l) => s + l.durationMin, 0)} min
              </span>
            </div>
            <p className="text-sm text-muted mb-4">{m.description}</p>
            <ol className="space-y-2">
              {m.lessons.map((l) => (
                <li key={l.slug}>
                  <Link
                    href={`/lessons/${l.slug}`}
                    className="flex items-baseline gap-3 px-3 py-2 rounded-lg border border-border hover:border-accent/60 hover:bg-bg transition"
                  >
                    <span className="text-xs text-muted w-10">
                      {m.index}.{l.index}
                    </span>
                    <span className="flex-1">
                      <span className="font-medium">{l.title}</span>
                      <span className="block text-xs text-muted mt-0.5">{l.subtitle}</span>
                    </span>
                    <span className="text-xs text-muted whitespace-nowrap">{l.durationMin} min</span>
                  </Link>
                </li>
              ))}
            </ol>
          </section>
        ))}
      </div>
    </div>
  );
}
