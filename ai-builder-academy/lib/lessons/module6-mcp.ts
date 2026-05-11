import type { Module } from "../types";

export const module6: Module = {
  slug: "mcp",
  index: 6,
  title: "Model Context Protocol (MCP)",
  tagline: "Le standard ouvert qui change le jeu des intégrations",
  description:
    "Comprendre MCP, l'architecture client/serveur, écrire ton premier serveur MCP. Le protocole qui permet à Claude (et bientôt tout) de se connecter à n'importe quel outil.",
  color: "from-amber-500 to-red-500",
  lessons: [
    {
      slug: "mcp-introduction",
      moduleSlug: "mcp",
      index: 1,
      title: "MCP : pourquoi et comment",
      subtitle: "Le 'USB-C' des intégrations LLM",
      level: "advanced",
      durationMin: 14,
      objectives: [
        "Comprendre le problème que résout MCP",
        "Distinguer client, serveur, ressources, tools, prompts",
        "Lister les serveurs MCP officiels et populaires",
        "Identifier quand utiliser MCP vs tool natif vs API directe",
      ],
      vocalScript: `[Intro]
Avant MCP, chaque intégration entre un LLM et un outil externe était bricolée à la main. Filesystem, GitHub, Slack, Postgres — chaque dev réinventait la roue. MCP standardise tout ça. C'est le protocole HTTP des LLMs.

[Section 1 - le problème]
Imagine : tu construis un agent qui accède à dix systèmes. Filesystem, Notion, GitHub, Linear, Postgres, ton API interne, etc. Sans standard, tu écris dix wrappers, dix sets de tools, dix gestions d'erreurs. Avec MCP, tu utilises ou tu écris dix serveurs MCP, et n'importe quel client compatible — Claude desktop, Cursor, ton agent — les consomme.

[Section 2 - architecture]
MCP c'est client-serveur sur stdio ou HTTP. Le serveur expose trois choses : des resources — des données lisibles, comme un fichier ou une row SQL, des tools — des actions exécutables, et des prompts — des templates réutilisables. Le client — typiquement le LLM — découvre dynamiquement ce qui est dispo et l'appelle.

[Section 3 - écosystème]
Anthropic maintient une liste de serveurs officiels : filesystem, git, github, postgres, sqlite, slack, etc. La communauté en a créé des centaines. Avant d'écrire le tien, vérifie si quelqu'un l'a déjà fait.

[Conclusion]
MCP n'est pas obligatoire. Mais en 2025-2026, c'est en train de devenir le standard. Si tu construis une intégration réutilisable, fais-la en MCP. Tu remercieras ton toi-passé.`,
      visuals: [
        {
          title: "Avant / après MCP",
          description:
            "À gauche : N agents × M outils = N×M wrappers custom. À droite : N agents + M serveurs MCP = N+M (gain quadratique).",
        },
        {
          title: "Architecture MCP",
          description:
            "Diagramme : Client (LLM/Cursor/Claude desktop) ↔ stdio/HTTP ↔ Server MCP (resources + tools + prompts) → Backend (filesystem, API, DB).",
        },
      ],
      content: `## Le problème MCP résout

Avant MCP : chaque assistant a ses propres "plugins", ses propres "tools", ses propres "actions". Tu veux brancher Claude sur GitHub ? Tu écris un tool pour ce projet. Tu veux le brancher sur le projet d'à côté ? Tu réécris.

Avec MCP : un serveur GitHub MCP est écrit **une fois**, n'importe quel client (Claude desktop, Cursor, ton agent custom) l'utilise. C'est le **modèle USB-C** : un connecteur, mille appareils.

## Architecture en 1 minute

\`\`\`
[Host App: Claude Desktop, Cursor, ton agent]
       │
       │ (orchestration)
       ▼
[MCP Client]  ──── JSON-RPC ────▶  [MCP Server]
   (1 par                              │
    serveur)                           ▼
                                  [Backend réel]
                                  (FS, DB, API, ...)
\`\`\`

**Transports** :
- **stdio** : process local, idéal pour outils desktop (filesystem, git).
- **HTTP/SSE** : serveur distant, idéal pour services centraux.

## Trois primitives à connaître

### 1. Resources
Des données **lisibles**, identifiées par URI : \`file:///path\`, \`postgres://table/123\`, \`gh://repo/issue/42\`.
Le client peut **list** et **read**.

### 2. Tools
Des **actions exécutables**, comme un function call. Mêmes principes que Module 3.

### 3. Prompts
Des **templates de prompt** réutilisables fournis par le serveur. Exemple : un serveur "incident response" expose un prompt \`triage_incident\` paramétré.

## Serveurs officiels Anthropic (à connaître)

| Serveur | Usage |
|---|---|
| \`filesystem\` | Lire/écrire des fichiers locaux |
| \`git\` | Operations git read-only |
| \`github\` | Issues, PRs, repos via API GitHub |
| \`postgres\` | Schema + queries read-only |
| \`sqlite\` | Idem SQLite |
| \`slack\` | Channels, messages |
| \`memory\` | KV store persistant pour l'agent |
| \`fetch\` | HTTP fetch |
| \`puppeteer\` | Browser automation |

→ Liste complète : https://github.com/modelcontextprotocol/servers

## MCP vs tool natif vs API directe

| Critère | MCP | Tool natif (in-app) | API directe (no LLM) |
|---|---|---|---|
| Réutilisable | ✅ Cross-clients | ❌ App-specific | ❌ |
| Complexité setup | Moyenne | Faible | Faible |
| Discovery dynamique | ✅ | ❌ | ❌ |
| Pour MVP rapide | ❌ | ✅ | ✅ |
| Pour produit mature | ✅ | ⚠️ | ⚠️ |

**Règle** : MVP en tools natifs, refactor en MCP quand tu veux réutiliser cross-projets ou cross-clients.

## À retenir

- MCP = protocole standardisé client/serveur pour LLMs.
- 3 primitives : resources (read), tools (act), prompts (templates).
- Plein de serveurs déjà existants — vérifie avant d'écrire.
- Transport : stdio (local) ou HTTP/SSE (distant).
- Adopte MCP pour les intégrations réutilisables, pas pour un POC jetable.`,
      practice: `**Exercice : explorer l'écosystème**

1. Installe Claude Desktop ou Cursor.
2. Configure 3 serveurs MCP officiels : \`filesystem\`, \`github\`, \`fetch\`.
3. Vérifie que tu peux : lister un dossier, ouvrir une issue GitHub, fetcher une URL.
4. Note quels tools/resources sont exposés par chaque serveur.

**Bonus** : trouve dans la communauté un serveur MCP utile à ton domaine et installe-le.`,
      quiz: [
        {
          question: "Quel est le bénéfice quadratique de MCP ?",
          choices: [
            "Aucun, c'est marketing",
            "N agents × M outils → N+M (un serveur par outil, réutilisé par tous les agents)",
            "Réduit les coûts API",
            "Accélère les LLMs",
          ],
          answerIndex: 1,
          explanation:
            "Sans standard, chaque (agent, outil) demande une intégration custom. MCP factorise : un serveur écrit une fois sert tous les clients.",
        },
        {
          question: "Quelles sont les 3 primitives MCP ?",
          choices: [
            "GET, POST, DELETE",
            "Resources (data), Tools (actions), Prompts (templates)",
            "Files, Functions, Variables",
            "Input, Output, Logs",
          ],
          answerIndex: 1,
          explanation:
            "MCP unifie data lecture (resources), actions (tools) et prompt templates dans un seul protocole.",
        },
        {
          question: "Quand préférer un tool natif à MCP ?",
          choices: [
            "Toujours",
            "Pour un MVP/POC qu'on n'a pas l'intention de réutiliser cross-app",
            "Jamais",
            "Pour les apps mobiles uniquement",
          ],
          answerIndex: 1,
          explanation:
            "MCP a un coût d'overhead (server, transport, schema). Pour du jetable, va au plus simple. Pour du réutilisable, MCP gagne.",
        },
      ],
      resources: [
        { label: "MCP — Spec officielle", href: "https://modelcontextprotocol.io/" },
        { label: "Serveurs MCP officiels (GitHub)", href: "https://github.com/modelcontextprotocol/servers" },
      ],
    },
    {
      slug: "build-mcp-server",
      moduleSlug: "mcp",
      index: 2,
      title: "Construire ton premier serveur MCP",
      subtitle: "Du Hello World à un serveur utilisable",
      level: "expert",
      durationMin: 22,
      objectives: [
        "Bootstrap un serveur MCP en TypeScript ou Python",
        "Exposer une resource, un tool et un prompt",
        "Tester avec MCP Inspector",
        "Publier et installer dans Claude Desktop",
      ],
      vocalScript: `[Intro]
Place à la pratique. On va construire un serveur MCP minimal mais fonctionnel — une intégration avec une todo-list locale, exposée comme resource et tools. À la fin, tu pourras dire à Claude Desktop "ajoute une tâche" et ça fonctionnera.

[Section 1 - bootstrap]
Tu installes le SDK officiel — TypeScript ou Python, au choix. Tu instancies un Server, tu déclares ton transport stdio. Vingt lignes de boilerplate. Tu lances : ton serveur tourne.

[Section 2 - exposer]
Tu déclares trois choses. Une resource "todos" qui retourne la liste des tâches. Un tool "add_todo" qui prend un titre. Un tool "complete_todo" qui prend un id. Chaque déclaration : un schéma, une fonction handler, fini.

[Section 3 - test et install]
Tu lances le MCP Inspector — un outil officiel qui simule un client et te montre tout ce que ton serveur expose. Tu vérifies. Puis tu ajoutes ton serveur au config Claude Desktop. Tu redémarres l'app. Tu peux maintenant dire "Claude, ajoute 'écrire la doc' à mes tâches" et ça marche.

[Conclusion]
Vingt minutes pour un serveur. Une heure pour un bon serveur production. C'est le ROI le plus élevé d'investissement temps en 2025 si tu vises l'écosystème.`,
      visuals: [
        {
          title: "Cycle de dev MCP",
          description:
            "5 étapes : npm init → declare resources/tools → implement handlers → test with MCP Inspector → register in client config (claude_desktop_config.json).",
        },
        {
          title: "Anatomie d'un handler tool",
          description:
            "Snippet : server.tool('add_todo', { schema: ... }, async (input) => { ... return content; }). Annotations sur chaque partie.",
        },
      ],
      content: `## Le serveur en 80 lignes (TypeScript)

\`\`\`bash
npm init -y
npm install @modelcontextprotocol/sdk zod
\`\`\`

\`\`\`typescript
// server.ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fs from "node:fs/promises";

const FILE = "./todos.json";

async function load() {
  try { return JSON.parse(await fs.readFile(FILE, "utf-8")); }
  catch { return []; }
}
async function save(todos: any[]) {
  await fs.writeFile(FILE, JSON.stringify(todos, null, 2));
}

const server = new Server(
  { name: "todo-mcp", version: "0.1.0" },
  { capabilities: { resources: {}, tools: {} } }
);

// RESOURCE: list of todos
server.setRequestHandler("resources/list", async () => ({
  resources: [{ uri: "todo://list", name: "Todos", mimeType: "application/json" }],
}));

server.setRequestHandler("resources/read", async (req) => {
  if (req.params.uri !== "todo://list") throw new Error("Not found");
  const todos = await load();
  return { contents: [{ uri: req.params.uri, mimeType: "application/json", text: JSON.stringify(todos) }] };
});

// TOOLS
server.setRequestHandler("tools/list", async () => ({
  tools: [
    {
      name: "add_todo",
      description: "Add a new todo. Use when the user wants to create a task.",
      inputSchema: { type: "object", properties: { title: { type: "string" } }, required: ["title"] },
    },
    {
      name: "complete_todo",
      description: "Mark a todo as done by id.",
      inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] },
    },
  ],
}));

server.setRequestHandler("tools/call", async (req) => {
  const { name, arguments: args } = req.params;
  const todos = await load();
  if (name === "add_todo") {
    const t = { id: crypto.randomUUID(), title: args.title, done: false };
    todos.push(t);
    await save(todos);
    return { content: [{ type: "text", text: \`Added: \${t.title} (\${t.id})\` }] };
  }
  if (name === "complete_todo") {
    const t = todos.find((x: any) => x.id === args.id);
    if (!t) throw new Error("Todo not found");
    t.done = true;
    await save(todos);
    return { content: [{ type: "text", text: \`Completed: \${t.title}\` }] };
  }
  throw new Error("Unknown tool");
});

const transport = new StdioServerTransport();
await server.connect(transport);
\`\`\`

\`\`\`bash
npx tsx server.ts  # dev
\`\`\`

## Tester avec MCP Inspector

\`\`\`bash
npx @modelcontextprotocol/inspector npx tsx server.ts
\`\`\`

L'inspector ouvre une UI web où tu vois resources, tools, peux les appeler manuellement, voir les logs JSON-RPC. **Indispensable** avant d'intégrer dans un client.

## Installer dans Claude Desktop

Édite \`~/Library/Application Support/Claude/claude_desktop_config.json\` (Mac) ou \`%APPDATA%\\Claude\\claude_desktop_config.json\` (Windows) :

\`\`\`json
{
  "mcpServers": {
    "todo": {
      "command": "npx",
      "args": ["tsx", "/absolute/path/to/server.ts"]
    }
  }
}
\`\`\`

Redémarre Claude Desktop. Tu vois ton serveur dans le menu MCP. Demande "ajoute 'finir la doc' dans mes tâches" → boom.

## Bonnes pratiques production

1. **Logging** sur stderr (jamais stdout — c'est le canal JSON-RPC en stdio).
2. **Erreurs typées** avec un code et un message clair.
3. **Validation Zod** des inputs avant exécution.
4. **Rate limiting** côté serveur si appelé beaucoup.
5. **Tests** avec MCP Inspector + tests unitaires sur les handlers.
6. **Versioning** sémantique de ton serveur.
7. **README** : liste des resources, tools, prompts, exemples d'usage.

## Pattern : MCP server qui wrappe une API existante

\`\`\`
ton_API_REST  ←─  MCP server (résources + tools)  ←─  client (Claude/Cursor)
\`\`\`

Tu **ne refais pas** l'API. Tu écris une fine couche MCP qui appelle ton API. 2-3h de travail, et toute l'écosystème LLM peut consommer ton produit.

## À retenir

- 80 lignes pour un serveur MCP fonctionnel.
- MCP Inspector = test essentiel avant intégration client.
- Logs sur stderr en stdio. Toujours.
- Wrapper API existante = ROI x10 vs réécrire les intégrations.`,
      practice: `**Mini-projet : ton serveur MCP utile**

Construis un serveur MCP qui wrappe **un service que tu utilises vraiment** :
- Ton outil de notes (Obsidian, Notion, Bear)
- Ton tracker (Linear, Jira)
- Ton CRM
- Une API publique qui t'intéresse (météo, transports, etc.)

**Cahier des charges** :
- 1 resource (data lisible)
- 2-3 tools (actions)
- Validation Zod des inputs
- README complet
- Test passant via MCP Inspector
- Installation dans Claude Desktop

**Livrable** : repo GitHub. Bonus : publie sur npm.`,
      quiz: [
        {
          question: "Pourquoi logger sur stderr en transport stdio ?",
          choices: [
            "C'est plus joli",
            "stdout est utilisé pour le canal JSON-RPC — un log sur stdout casse le protocole",
            "stderr est plus rapide",
            "Aucune raison",
          ],
          answerIndex: 1,
          explanation:
            "En stdio, stdout = communication client/serveur. Tout log y aller corrompt les messages. stderr est sûr.",
        },
        {
          question: "À quoi sert MCP Inspector ?",
          choices: [
            "À auditer la sécurité",
            "À simuler un client MCP, voir resources/tools exposés, et tester les appels avant intégration",
            "À monitorer les coûts",
            "À mesurer la latence réseau",
          ],
          answerIndex: 1,
          explanation:
            "Outil officiel pour développer et débugger un serveur MCP sans installer dans Claude Desktop à chaque itération.",
        },
        {
          question: "Quelle est la stratégie la plus rentable pour intégrer une API existante en MCP ?",
          choices: [
            "Réécrire l'API en MCP-native",
            "Écrire un serveur MCP fin qui wrappe l'API existante",
            "Forker et patcher l'API",
            "Ne pas faire de MCP",
          ],
          answerIndex: 1,
          explanation:
            "Quelques heures pour un wrapper > semaines pour une réécriture. Tu gardes ton API stable et exposes via MCP.",
        },
      ],
      resources: [
        { label: "MCP — TypeScript SDK", href: "https://github.com/modelcontextprotocol/typescript-sdk" },
        { label: "MCP — Python SDK", href: "https://github.com/modelcontextprotocol/python-sdk" },
        { label: "MCP Inspector", href: "https://github.com/modelcontextprotocol/inspector" },
      ],
    },
  ],
};
