"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { curriculum } from "@/lib/curriculum";
import { getLocalProgress } from "@/lib/progress";

export default function LessonNav() {
  const pathname = usePathname();
  const [completed, setCompleted] = useState<string[]>([]);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const refresh = () => setCompleted(getLocalProgress().completedLessons);
    refresh();
    window.addEventListener("progress:updated", refresh);
    window.addEventListener("storage", refresh);
    return () => {
      window.removeEventListener("progress:updated", refresh);
      window.removeEventListener("storage", refresh);
    };
  }, []);

  return (
    <>
      <button
        onClick={() => setOpen((v) => !v)}
        className="lg:hidden fixed bottom-4 right-4 z-50 bg-accent text-bg font-medium px-4 py-2 rounded-full shadow-lg"
      >
        {open ? "✕ Fermer" : "☰ Modules"}
      </button>
      <aside
        className={`${open ? "block" : "hidden"} lg:block fixed lg:sticky top-[57px] inset-x-0 lg:inset-auto z-40 lg:z-auto bg-bg/95 lg:bg-transparent backdrop-blur lg:h-[calc(100vh-57px)] lg:overflow-y-auto scrollbar border-r border-border lg:w-72 p-4`}
      >
        <div className="text-xs uppercase tracking-wider text-muted mb-3 px-2">
          Curriculum · 9 modules
        </div>
        <nav className="space-y-4">
          {curriculum.map((m) => (
            <div key={m.slug}>
              <div className="px-2 mb-1.5 flex items-center justify-between">
                <span className="text-[13px] font-medium text-text">
                  {m.index}. {m.title}
                </span>
              </div>
              <ul className="space-y-1">
                {m.lessons.map((l) => {
                  const href = `/lessons/${l.slug}`;
                  const isActive = pathname === href;
                  const isDone = completed.includes(l.slug);
                  return (
                    <li key={l.slug}>
                      <Link
                        href={href}
                        onClick={() => setOpen(false)}
                        className={`block px-3 py-1.5 rounded-md text-[13px] transition ${
                          isActive
                            ? "bg-accent/15 text-accent border border-accent/40"
                            : "hover:bg-panel text-text/85"
                        }`}
                      >
                        <span className="inline-block w-4 mr-1.5 text-muted">
                          {isDone ? "✓" : "·"}
                        </span>
                        {l.title}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
      </aside>
    </>
  );
}
