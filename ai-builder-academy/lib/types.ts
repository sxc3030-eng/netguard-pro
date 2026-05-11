export type LessonLevel = "intermediate" | "advanced" | "expert";

export type Quiz = {
  question: string;
  choices: string[];
  answerIndex: number;
  explanation: string;
};

export type VisualSlide = {
  title: string;
  description: string;
  ascii?: string;
};

export type Lesson = {
  slug: string;
  moduleSlug: string;
  index: number;
  title: string;
  subtitle: string;
  level: LessonLevel;
  durationMin: number;
  objectives: string[];
  vocalScript: string;
  visuals: VisualSlide[];
  content: string;
  practice: string;
  quiz: Quiz[];
  resources: { label: string; href: string }[];
};

export type Module = {
  slug: string;
  index: number;
  title: string;
  tagline: string;
  description: string;
  color: string;
  lessons: Lesson[];
};
