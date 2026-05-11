import Link from "next/link";
import { curriculum, allLessons } from "@/lib/curriculum";
import ProgressOverview from "@/components/ProgressOverview";

export default function HomePage() {
  const totalLessons = allLessons().length;
  const totalMinutes = allLessons().reduce((sum, l) => sum + l.durationMin, 0);
  const firstLessonSlug = allLessons()[0].slug;

  return (
    <div className="max-w-7xl mx-auto px-5 py-10 sm:py-16">
      <section className="grid lg:grid-cols-[1.4fr_1fr] gap-10 items-center">
        <div>
          <div className="text-xs uppercase tracking-widest text-accent2 mb-3">
            Formation bilingue · Niveau intermédiaire à expert
          </div>
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-semibold leading-tight tracking-tight">
            Devenir le <span className="bg-gradient-to-r from-accent to-accent2 bg-clip-text text-transparent">meilleur AI builder</span>.
          </h1>
          <p className="mt-5 text-lg text-text/85 leading-relaxed max-w-2xl">
            Une formation complète, vocale et visuelle, pour bâtir des systèmes IA modernes :
            prompts avancés, RAG production, agents, MCP, multi-agents, observability, business.
            <br />
            <span className="text-muted">Chaque leçon = un script audio jouable, des visuels, du contenu, un exercice pipeline et un quiz.</span>
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link
              href={`/lessons/${firstLessonSlug}`}
              className="bg-accent text-bg font-medium px-6 py-3 rounded-lg hover:opacity-90 transition"
            >
              Commencer la leçon 1
            </Link>
            <Link
              href="/modules"
              className="border border-border hover:border-accent text-text px-6 py-3 rounded-lg transition"
            >
              Voir les modules
            </Link>
          </div>
          <div className="mt-7 grid grid-cols-3 gap-4 max-w-lg">
            <Stat label="Modules" value={curriculum.length.toString()} />
            <Stat label="Leçons" value={totalLessons.toString()} />
            <Stat label="Minutes" value={`${totalMinutes}`} />
          </div>
        </div>
        <div className="space-y-4">
          <ProgressOverview />
          <div className="bg-panel border border-border rounded-xl p-5">
            <div className="text-sm text-muted mb-2">Format</div>
            <ul className="space-y-2 text-sm">
              <li>🎙️ <span className="text-text">Lecture vocale</span> de chaque leçon (Web Speech)</li>
              <li>🖼️ <span className="text-text">Visuels narrés</span> et schémas ASCII</li>
              <li>🛠️ <span className="text-text">Exercices pipeline</span> (RAG, agents, eval)</li>
              <li>✅ <span className="text-text">Quiz</span> 3 questions par leçon</li>
              <li>📱 <span className="text-text">Mobile-friendly</span>, dark mode natif</li>
              <li>💾 Progression sauvée dans le navigateur</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="mt-16 sm:mt-24">
        <div className="flex items-end justify-between mb-6">
          <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight">Le curriculum</h2>
          <Link href="/modules" className="text-sm text-accent2 hover:underline">
            Tout voir →
          </Link>
        </div>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {curriculum.map((m) => (
            <Link
              key={m.slug}
              href={`/lessons/${m.lessons[0].slug}`}
              className="group bg-panel border border-border rounded-xl p-5 hover:border-accent/60 transition"
            >
              <div className={`inline-block text-[11px] font-medium px-2 py-0.5 rounded bg-gradient-to-r ${m.color} text-bg mb-3`}>
                Module {m.index}
              </div>
              <h3 className="font-semibold text-lg group-hover:text-accent2 transition">{m.title}</h3>
              <div className="text-sm text-muted mt-1">{m.tagline}</div>
              <div className="text-xs text-muted mt-3">
                {m.lessons.length} leçons · {m.lessons.reduce((s, l) => s + l.durationMin, 0)} min
              </div>
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-panel border border-border rounded-lg px-3 py-2">
      <div className="text-2xl font-semibold">{value}</div>
      <div className="text-xs text-muted">{label}</div>
    </div>
  );
}
