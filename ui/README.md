# MUVON admin panel

The React SPA served by the `muvon` binary. React 19 + Vite 8 + shadcn/ui,
TypeScript throughout.

## Running it

```bash
npm install          # or: make ui-install from the repo root
npm run dev          # Vite dev server; or: make ui-dev
npm run lint         # ESLint over the SPA
npm run build        # tsc -b && vite build, output in ui/dist
```

The dev server listens on port 3000 and already proxies `/api` to
`http://localhost:9443` (see `vite.config.ts`), so it works against a locally
running `muvon` with no extra setup.

## How it reaches production

`make ui-build` runs the build, wipes `frontend/dist/` and copies `ui/dist/`
into it. `embed.go` at the repo root embeds `frontend/dist` into the binary with
`//go:embed`, so the panel ships inside `muvon` itself and there is nothing to
serve separately.

`frontend/dist/` is generated. Never edit files there, and never commit changes
to it by hand.

## Where things live

| Path | Holds |
|------|-------|
| `src/pages/` | One file per route (Hosts, Routes, Logs, Alerts, Apps, ScheduledJobs, ClientEvents, ContainerLogs, Settings, TLSCerts, Agents, AuditLog, Dashboard) |
| `src/components/` | Shared UI: `Layout.tsx` owns the sidebar, `NewAppDialog.tsx` the create-app wizard, `AgentActionMenu.tsx` the agent command channel |
| `src/components/ui/` | shadcn primitives |

Routes are declared in `src/App.tsx` and the sidebar entries in
`src/components/Layout.tsx`. Adding a page means touching both.
