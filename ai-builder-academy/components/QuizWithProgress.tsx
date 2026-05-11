"use client";

import Quiz from "./Quiz";
import { useProgress } from "@/lib/progress";
import type { Quiz as QuizType } from "@/lib/types";

export default function QuizWithProgress({
  slug,
  questions,
}: {
  slug: string;
  questions: QuizType[];
}) {
  const { setQuizScore } = useProgress();
  return <Quiz questions={questions} onComplete={(s) => setQuizScore(slug, s)} />;
}
