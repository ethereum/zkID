# OpenAC Studio

> [!IMPORTANT]
> This code is a reference implementation. It has not been checked for production quality.
>
> Only an internal audit has been completed. The code has not had an external audit.

A guided integration designer and interactive explainer for anonymous credential presentation flows. Design, visualize, and analyze your credential system with deterministic module selection, sequence diagrams, and threat modeling — all running locally in the browser.

## Quick Start

```bash
pnpm install
pnpm dev        # http://localhost:3001
pnpm test       # run Vitest tests
pnpm build      # production build
```

## Pages

### Landing (`/`)
Overview of OpenAC capabilities with an interactive mini-demo. Toggle "repeat presentations" and "cross-verifier unlinkability" to see how module selection and privacy score change in real time.

### Studio (`/studio`)
Guided 3-step integration designer:
1. **Requirements** — Configure scenario parameters with helper tooltips. Load presets or switch between Basic/Advanced mode.
2. **Recommended Design** — View selected modules (with why-selected and risk-if-omitted), Mermaid sequence diagram (high-level / crypto-level), and threat analysis with categorized checklist.
3. **Export** — Download module graph JSON, Mermaid diagram (.mmd), threat model report (.md), or copy a share blob.

### Explore (`/explore`)
Freeform sandbox for experimentation:
- Drag-and-drop modules from palette to canvas
- Real-time diagram, privacy meter, and threat model updates
- Import share blobs or canvas state from clipboard
- Load modules from Studio with "Open in Explore Sandbox"

### Docs (`/docs`)
Lightweight documentation covering:
- How the tool works (rule engine, diagram generator, threat model)
- Key concepts (unlinkability, nonce vs nullifier, device binding, on-chain constraints)
- How to extend (add modules, rules, threat templates)
- Limitations and disclaimers

## Architecture

```
src/
├── app/
│   ├── page.tsx              # Landing page with mini-demo
│   ├── layout.tsx            # Root layout with nav
│   ├── studio/page.tsx       # Guided integration designer
│   ├── explore/page.tsx      # Freeform sandbox
│   └── docs/page.tsx         # Documentation
├── components/
│   ├── ui/                   # shadcn/ui components (Button, Card, Tabs, Accordion, Badge, Tooltip)
│   ├── SiteNav.tsx           # Top navigation
│   ├── MermaidRenderer.tsx   # Client-side Mermaid rendering
│   ├── ThreatModelPanel.tsx  # Threat model display + export
│   ├── ModuleCard.tsx        # Module display card
│   ├── PrivacyMeter.tsx      # Privacy score bar
│   ├── WarningsPanel.tsx     # Warnings list
│   └── CompareView.tsx       # Baseline vs current diff
├── lib/
│   ├── cn.ts                 # Tailwind class merge utility
│   ├── scenario/             # Zod schema + defaults + examples
│   ├── modules/              # Module registry + types
│   ├── rules/                # Rule engine + ruleset
│   ├── diagram/              # Mermaid sequence diagram generator
│   ├── threats/              # Threat model generator + templates + markdown
│   └── io/                   # Import/export utilities (share blob, downloads)
└── store/
    ├── studioStore.ts        # Shared state: scenario + engine + diagram + threats
    └── canvasStore.ts        # Explore sandbox state
```

## Extending

### Add a Module
Edit `src/lib/modules/registry.ts`. Add a `ModuleDefinition` with id, title, provides, requires, conflicts, risksIfOmitted, and diagramHooks. Dependencies are auto-resolved by the engine.

### Add a Rule
Edit `src/lib/rules/ruleset.ts`. Add a `Rule` with a predicate, module adds/removals, and explanation. The engine handles dependency resolution and conflict detection.

### Add a Threat Template
Edit `src/lib/threats/templates.ts`. Add a `ThreatTemplate` with an `appliesWhen` predicate, severity, mitigations (with `dependsOnModules`), detection signals, and references. The generator evaluates satisfaction automatically.

## Tech Stack

- **Next.js 15** (App Router) + React 19 + TypeScript
- **TailwindCSS** + **shadcn/ui** (Radix primitives) for UI
- **Zustand** for state management
- **Mermaid** for sequence diagrams (client-side)
- **dnd-kit** for drag-and-drop
- **Zod** for schema validation
- **Vitest** for testing

## Testing

```bash
pnpm test          # run all tests
pnpm test:watch    # watch mode
```

Tests cover rule engine logic, diagram generation snapshots, threat model applicability/mitigation/severity, and markdown renderer determinism.

## Disclaimer

OpenAC Studio is a checklist-based design tool, not a formal security proof. It identifies potential risks based on scenario configuration and module selection. Always review with a qualified security team before production deployment.
