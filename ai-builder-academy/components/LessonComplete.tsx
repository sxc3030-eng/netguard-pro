"use client";

import { useEffect, useState } from "react";
import { useProgress } from "@/lib/progress";

export default function LessonComplete({ slug }: { slug: string }) {
  const { state, completeLesson } = useProgress();
  const [done, setDone] = useState(false);

  useEffect(() => {
    setDone(state.completedLessons.includes(slug));
  }, [state, slug]);

  if (done) {
    return (
      <div className="bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 rounded-lg px-4 py-3 text-sm">
        ✓ Leçon marquée comme terminée. Bravo !
      </div>
    );
  }

  return (
    <button
      onClick={() => completeLesson(slug)}
      className="bg-accent text-bg font-medium px-5 py-2.5 rounded-md hover:opacity-90"
    >
      Marquer la leçon comme terminée
    </button>
  );
}
