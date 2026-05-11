import "./globals.css";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "AI Builder Academy — Devenir le meilleur AI builder",
  description:
    "Formation intermédiaire à expert pour bâtir des agents IA modernes : prompts, RAG, tool use, MCP, multi-agents, production.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="fr">
      <body className="min-h-screen">
        <header className="border-b border-border bg-bg/80 backdrop-blur sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-5 py-3 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-2 group">
              <span className="inline-block w-8 h-8 rounded-lg bg-gradient-to-br from-accent to-accent2 grid place-items-center font-bold text-bg">
                A
              </span>
              <span className="font-semibold tracking-tight">
                AI Builder <span className="text-accent2">Academy</span>
              </span>
            </Link>
            <nav className="flex items-center gap-5 text-sm text-muted">
              <Link href="/" className="hover:text-text">Accueil</Link>
              <Link href="/modules" className="hover:text-text">Modules</Link>
              <Link href="/roadmap" className="hover:text-text">Roadmap</Link>
              <Link href="/about" className="hover:text-text">À propos</Link>
            </nav>
          </div>
        </header>
        <main>{children}</main>
        <footer className="border-t border-border mt-20">
          <div className="max-w-7xl mx-auto px-5 py-8 text-sm text-muted flex flex-wrap gap-3 justify-between">
            <span>AI Builder Academy · Formation bilingue FR/EN</span>
            <span>Built with Next.js · Open curriculum</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
