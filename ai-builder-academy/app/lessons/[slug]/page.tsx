import { notFound } from "next/navigation";
import Link from "next/link";
import { allLessons, getLesson, lessonNeighbors } from "@/lib/curriculum";
import VocalPlayer from "@/components/VocalPlayer";
import MarkdownView from "@/components/MarkdownView";
import QuizWithProgress from "@/components/QuizWithProgress";
import LessonComplete from "@/components/LessonComplete";
import LessonNav from "@/components/LessonNav";

export function generateStaticParams() {
  return allLessons().map((l) => ({ slug: l.slug }));
}

export function generateMetadata({ params }: { params: { slug: string } }) {
  const data = getLesson(params.slug);
  if (!data) return { title: "Leçon" };
  return { title: `${data.lesson.title} — ${data.module.title}` };
}

export default function LessonPage({ params }: { params: { slug: string } }) {
  const data = getLesson(params.slug);
  if (!data) return notFound();
  const { lesson, module } = data;
  const { prev, next } = lessonNeighbors(lesson.slug);

  return (
    <div className="max-w-7xl mx-auto px-0 lg:px-5 lg:grid lg:grid-cols-[18rem_1fr] gap-8">
      <LessonNav />

      <article className="px-5 lg:px-0 py-8 sm:py-10 max-w-4xl">
        <div className="text-xs uppercase tracking-wider text-accent2 mb-2">
          Module {module.index} · Leçon {lesson.index} · {lesson.durationMin} min · niveau {lesson.level}
        </div>
        <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight">{lesson.title}</h1>
        <p className="text-muted mt-2 text-lg">{lesson.subtitle}</p>

        <section className="mt-6">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted mb-2">
            Objectifs
          </h2>
          <ul className="grid sm:grid-cols-2 gap-2">
            {lesson.objectives.map((o, i) => (
              <li key={i} className="text-sm bg-panel border border-border rounded-lg px-3 py-2">
                <span className="text-accent2 mr-1.5">✓</span>{o}
              </li>
            ))}
          </ul>
        </section>

        <section className="mt-8">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted mb-2">
            🎙️ Lecture vocale
          </h2>
          <VocalPlayer text={lesson.vocalScript} lang="fr-FR" />
          <details className="mt-3 text-sm">
            <summary className="cursor-pointer text-muted hover:text-text">
              Voir le script vocal
            </summary>
            <pre className="mt-2 whitespace-pre-wrap bg-panel border border-border rounded-lg p-4 text-[13px] text-text/85">
              {lesson.vocalScript}
            </pre>
          </details>
        </section>

        <section className="mt-8">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted mb-2">
            🖼️ Visuels narrés
          </h2>
          <div className="grid sm:grid-cols-2 gap-3">
            {lesson.visuals.map((v, i) => (
              <div key={i} className="bg-panel border border-border rounded-xl p-4">
                <div className="font-medium text-sm mb-1">{v.title}</div>
                <div className="text-xs text-muted leading-relaxed">{v.description}</div>
                {v.ascii && (
                  <pre className="mt-3 bg-bg border border-border rounded p-2 text-[11px] overflow-x-auto text-accent2">
                    {v.ascii}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </section>

        <section className="mt-10">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted mb-2">
            📚 Cours
          </h2>
          <MarkdownView>{lesson.content}</MarkdownView>
        </section>

        <section className="mt-10">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted mb-2">
            🛠️ Exercice pratique
          </h2>
          <div className="bg-panel border border-accent/30 rounded-xl p-5">
            <MarkdownView>{lesson.practice}</MarkdownView>
          </div>
        </section>

        <section className="mt-10">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted mb-2">
            ✅ Quiz
          </h2>
          <QuizWithProgress slug={lesson.slug} questions={lesson.quiz} />
        </section>

        {lesson.resources.length > 0 && (
          <section className="mt-10">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted mb-2">
              📖 Ressources
            </h2>
            <ul className="space-y-1.5">
              {lesson.resources.map((r, i) => (
                <li key={i} className="text-sm">
                  <a
                    href={r.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-accent2 hover:underline"
                  >
                    → {r.label}
                  </a>
                </li>
              ))}
            </ul>
          </section>
        )}

        <section className="mt-10">
          <LessonComplete slug={lesson.slug} />
        </section>

        <nav className="mt-12 grid sm:grid-cols-2 gap-3">
          {prev ? (
            <Link
              href={`/lessons/${prev.slug}`}
              className="bg-panel border border-border hover:border-accent/60 rounded-xl p-4 transition"
            >
              <div className="text-xs text-muted">← Précédent</div>
              <div className="font-medium mt-1">{prev.title}</div>
            </Link>
          ) : (
            <div />
          )}
          {next && (
            <Link
              href={`/lessons/${next.slug}`}
              className="bg-panel border border-border hover:border-accent/60 rounded-xl p-4 transition sm:text-right"
            >
              <div className="text-xs text-muted">Suivant →</div>
              <div className="font-medium mt-1">{next.title}</div>
            </Link>
          )}
        </nav>
      </article>
    </div>
  );
}
