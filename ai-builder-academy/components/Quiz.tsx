"use client";

import { useState } from "react";
import type { Quiz as QuizType } from "@/lib/types";

export default function Quiz({
  questions,
  onComplete,
}: {
  questions: QuizType[];
  onComplete?: (score: number) => void;
}) {
  const [answers, setAnswers] = useState<Record<number, number>>({});
  const [submitted, setSubmitted] = useState(false);

  function submit() {
    setSubmitted(true);
    const correct = questions.filter((q, i) => answers[i] === q.answerIndex).length;
    onComplete?.(correct / questions.length);
  }

  function reset() {
    setAnswers({});
    setSubmitted(false);
  }

  const allAnswered = questions.every((_, i) => answers[i] !== undefined);
  const correctCount = submitted
    ? questions.filter((q, i) => answers[i] === q.answerIndex).length
    : 0;

  return (
    <div className="space-y-6">
      {questions.map((q, qi) => {
        const userAns = answers[qi];
        return (
          <div key={qi} className="bg-panel border border-border rounded-xl p-4 sm:p-5">
            <div className="text-sm text-muted mb-1">Question {qi + 1} / {questions.length}</div>
            <div className="font-medium mb-4">{q.question}</div>
            <div className="space-y-2">
              {q.choices.map((c, ci) => {
                const isUser = userAns === ci;
                const isCorrect = ci === q.answerIndex;
                let cls = "border-border hover:border-accent/60";
                if (submitted) {
                  if (isCorrect) cls = "border-emerald-500 bg-emerald-500/10";
                  else if (isUser) cls = "border-rose-500 bg-rose-500/10";
                  else cls = "border-border opacity-60";
                } else if (isUser) {
                  cls = "border-accent bg-accent/10";
                }
                return (
                  <button
                    key={ci}
                    disabled={submitted}
                    onClick={() => setAnswers((a) => ({ ...a, [qi]: ci }))}
                    className={`w-full text-left px-3 py-2 rounded-lg border transition ${cls}`}
                  >
                    <span className="text-sm">{c}</span>
                  </button>
                );
              })}
            </div>
            {submitted && (
              <div className="mt-3 text-sm text-muted border-t border-border pt-3">
                {userAns === q.answerIndex ? "✓ Correct. " : "✗ Incorrect. "}
                {q.explanation}
              </div>
            )}
          </div>
        );
      })}
      <div className="flex flex-wrap items-center gap-3">
        {!submitted && (
          <button
            onClick={submit}
            disabled={!allAnswered}
            className="bg-accent text-bg font-medium px-5 py-2.5 rounded-md disabled:opacity-40"
          >
            Valider mes réponses
          </button>
        )}
        {submitted && (
          <>
            <div className="text-lg">
              Score : <span className="font-semibold">{correctCount}/{questions.length}</span>
            </div>
            <button
              onClick={reset}
              className="text-muted hover:text-text underline underline-offset-2 text-sm"
            >
              Recommencer
            </button>
          </>
        )}
      </div>
    </div>
  );
}
