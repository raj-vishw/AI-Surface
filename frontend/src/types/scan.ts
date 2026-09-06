/**
 * Scans map to this backend's CLI reconnaissance commands (`ai-recon scan`,
 * `network-scan`, `dns-scan`, `endpoint-scan`, `fingerprint`) — see
 * README.md's "HTTP/Network/DNS/Endpoint Discovery" sections. Today these
 * run synchronously to completion when invoked; there is no async job
 * queue in the backend (confirmed — cmd/worker has no job consumer yet).
 * This type's "status" field (queued/running) therefore describes a
 * FUTURE async execution model this frontend anticipates, not a
 * currently-real backend state machine — see mocks/scans.ts and the
 * frontend implementation report's "Backend Changes Required" section.
 */

export type ScanType =
  | "http"
  | "network"
  | "dns"
  | "subdomain"
  | "endpoint"
  | "fingerprint";

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface Scan {
  id: string;
  targetId: string;
  targetValue: string;
  scanType: ScanType;
  status: ScanStatus;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  assetsDiscovered: number;
  findingsDiscovered: number;
  error: string | null;
}
