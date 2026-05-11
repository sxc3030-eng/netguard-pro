import type { Module } from "./types";
import { module1 } from "./lessons/module1-llm-foundations";
import { module2 } from "./lessons/module2-prompt-engineering";
import { module3 } from "./lessons/module3-tool-use";
import { module4 } from "./lessons/module4-rag";
import { module5 } from "./lessons/module5-agents";
import { module6 } from "./lessons/module6-mcp";
import { module7 } from "./lessons/module7-multi-agents";
import { module8 } from "./lessons/module8-production";
import { module9 } from "./lessons/module9-business";
import { module10 } from "./lessons/module10-lab-rag-agents";

export const curriculum: Module[] = [
  module1,
  module2,
  module3,
  module4,
  module5,
  module6,
  module7,
  module8,
  module9,
  module10,
];

export function getModule(slug: string) {
  return curriculum.find((m) => m.slug === slug);
}

export function getLesson(slug: string) {
  for (const m of curriculum) {
    const l = m.lessons.find((x) => x.slug === slug);
    if (l) return { lesson: l, module: m };
  }
  return null;
}

export function allLessons() {
  return curriculum.flatMap((m) => m.lessons);
}

export function lessonNeighbors(slug: string) {
  const all = allLessons();
  const i = all.findIndex((l) => l.slug === slug);
  return {
    prev: i > 0 ? all[i - 1] : null,
    next: i >= 0 && i < all.length - 1 ? all[i + 1] : null,
  };
}
