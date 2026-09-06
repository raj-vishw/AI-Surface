/**
 * API base configuration. Backend Connection note (spec §70/§71):
 *
 * This backend (see ../../../README.md and docs/architecture/overview.md)
 * exposes exactly THREE HTTP endpoints today — GET /health, GET /live,
 * GET /ready — and no REST API for assets/findings/alerts/investigations/
 * etc. Every other capability described in this frontend's spec exists
 * only as a CLI command (`ai-recon asset list`, `ai-recon findings list`,
 * ...) operating directly against PostgreSQL.
 *
 * Per spec §44/§72 ("mock data may be used ONLY where backend
 * functionality is not yet available... clearly marked as mock... the
 * dashboard should automatically use real APIs when available") and §71
 * ("document [a mismatch], make the smallest compatible change — do not
 * rewrite backend architecture"), this frontend is built against a
 * documented, proposed REST contract (one resource path per existing CLI
 * command family — see each src/api/*.ts module's own header comment)
 * and serves it from src/mocks/ until that contract is actually
 * implemented server-side. See the frontend implementation report's
 * "Backend Changes Required" section for the exact endpoint list a
 * future backend phase would need to add.
 *
 * Switching this from mock to real data requires ZERO component changes:
 * every src/api/*.ts function already returns the same shape either way.
 * Setting VITE_API_BASE_URL makes USE_MOCKS false and every function
 * starts issuing real fetch() calls against that base URL instead.
 */

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "";

/** True until a real API base URL is configured — see module doc comment. */
export const USE_MOCKS = API_BASE_URL.trim().length === 0;

/** Simulated network latency for mock responses, so loading states
 * (skeletons, spinners) are actually exercised during development rather
 * than resolving instantly (which would make loading-state bugs
 * invisible until a real backend is connected). */
export const MOCK_LATENCY_MS = 280;

export function mockDelay<T>(value: T, ms = MOCK_LATENCY_MS): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms));
}
