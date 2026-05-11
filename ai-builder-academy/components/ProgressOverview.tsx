"use client";

import { useEffect, useState } from "react";
import { allLessons } from "@/lib/curriculum";
import { getLocalProgress } from "@/lib/progress";

export default function ProgressOverview() {
  const total = allLessons().length;
  const [done, setDone] = useState(0);

  useEffect(() => {
    const refresh = () => setDone(getLocalProgress().completedLessons.length);
    refresh();
    window.addEventListener("progress:updated", refresh);
    window.addEventListener("storage", refresh);
    return () => {
      window.removeEventListener("progress:updated", refresh);
      window.removeEventListener("storage", refresh);
    };
  }, []);

  const pct = total === 0 ? 0 : Math.round((done / total) * 100);

  return (
    <div className="bg-panel border border-border rounded-xl p-4 sm:p-5">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-muted">Progression</span>
        <span className="text-sm font-medium">{done} / {total} leçons</span>
      </div>
      <div className="h-2 bg-bg rounded overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-accent to-accent2 transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="text-xs text-muted mt-2">{pct}% du parcours complété</div>
    </div>
  );
}
