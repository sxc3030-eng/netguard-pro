"use client";

import { useEffect, useState } from "react";

const KEY = "aibuilder.progress.v1";

type ProgressState = {
  completedLessons: string[];
  quizScores: Record<string, number>; // lesson slug → 0..1
  lastVisited?: string;
};

function read(): ProgressState {
  if (typeof window === "undefined") return { completedLessons: [], quizScores: {} };
  try {
    return JSON.parse(localStorage.getItem(KEY) || "") || { completedLessons: [], quizScores: {} };
  } catch {
    return { completedLessons: [], quizScores: {} };
  }
}

function write(state: ProgressState) {
  if (typeof window === "undefined") return;
  localStorage.setItem(KEY, JSON.stringify(state));
  window.dispatchEvent(new CustomEvent("progress:updated"));
}

export function useProgress() {
  const [state, setState] = useState<ProgressState>(() => read());

  useEffect(() => {
    const handler = () => setState(read());
    window.addEventListener("progress:updated", handler);
    window.addEventListener("storage", handler);
    return () => {
      window.removeEventListener("progress:updated", handler);
      window.removeEventListener("storage", handler);
    };
  }, []);

  const completeLesson = (slug: string) => {
    const s = read();
    if (!s.completedLessons.includes(slug)) s.completedLessons.push(slug);
    s.lastVisited = slug;
    write(s);
  };

  const setQuizScore = (slug: string, score: number) => {
    const s = read();
    s.quizScores[slug] = score;
    write(s);
  };

  const reset = () => write({ completedLessons: [], quizScores: {} });

  return { state, completeLesson, setQuizScore, reset };
}

export function getLocalProgress(): ProgressState {
  return read();
}
