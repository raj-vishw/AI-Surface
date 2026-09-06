# AI-Recon — Security Operations Dashboard

A React/TypeScript frontend for the `ai-recon-platform` backend (see
`../README.md`). See `../doc_by_me/reports/frontend-report.md` for the
full implementation report.

## Setup

```sh
npm install
npm run dev       # http://localhost:5173
```

By default this runs against realistic, clearly-marked mock data — no
backend is required. To point it at a real backend once one exists (see
"Backend Connection" below), copy `.env.example` to `.env.local` and set
`VITE_API_BASE_URL`.

## Scripts

```sh
npm run dev       # start the dev server
npm run build     # type-check (tsc -b) + production build (vite build)
npm run lint      # oxlint
npm run preview   # serve the production build locally
```

## Backend connection

This backend (`../ai-recon-platform`) exposes exactly three HTTP
endpoints — `GET /health`, `/live`, `/ready` — and no REST API for
assets/findings/alerts/investigations/etc.; every other capability is a
CLI command operating directly against PostgreSQL. This frontend is
built against a documented, proposed REST contract (one path per
existing CLI command family — see each `src/api/*.ts` file's own header
comment) and serves it from `src/mocks/` until that contract exists
server-side. Setting `VITE_API_BASE_URL` switches every `src/api/*.ts`
function from mocks to real `fetch()` calls with zero component changes.

## Project structure

```
src/
  api/          — one module per resource; mock-or-real branch, see api/config.ts
  auth/         — dev-mode auth boundary (no login implemented — see auth/useAuth.ts)
  components/
    ui/         — design system primitives (Button, Badge, Card, Table, ...)
    layout/     — AppShell, Navbar, Sidebar
    navigation/ — TargetSwitcher, CommandPalette, global search
    dashboard/  — KPI cards, attack-surface graph, activity feed
    charts/     — Recharts wrappers (trend, severity distribution, bar)
    ai/         — the AI Trust UI (StructuredResultView)
  hooks/        — TanStack Query hooks, one per resource, scoped by current target
  lib/          — cn(), severity/status token map, formatting helpers
  mocks/        — the in-memory mock dataset (clearly separated, dev-only)
  pages/        — one file per route
  store/        — Zustand workspace store (current target, sidebar state)
  types/        — TypeScript types mirroring the backend's Go domain models
```
