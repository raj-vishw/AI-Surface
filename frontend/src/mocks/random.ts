/** A tiny seeded PRNG (mulberry32) so mock data is deterministic across
 * reloads within one build — a dashboard whose numbers reshuffle on every
 * refresh reads as fake; a fixed seed reads as "this is today's data". */
export function mulberry32(seed: number) {
  let a = seed;
  return function random() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = mulberry32(20260306);

export function pick<T>(arr: readonly T[]): T {
  return arr[Math.floor(rand() * arr.length)];
}

export function pickWeighted<T>(entries: [T, number][]): T {
  const total = entries.reduce((sum, [, w]) => sum + w, 0);
  let r = rand() * total;
  for (const [value, weight] of entries) {
    r -= weight;
    if (r <= 0) return value;
  }
  return entries[entries.length - 1][0];
}

export function randInt(min: number, max: number): number {
  return Math.floor(rand() * (max - min + 1)) + min;
}

export function randFloat(min: number, max: number, decimals = 2): number {
  const v = rand() * (max - min) + min;
  return Number(v.toFixed(decimals));
}

export function chance(probability: number): boolean {
  return rand() < probability;
}

let uuidCounter = 0;
/** Deterministic, UUID-*shaped* ids (not cryptographically random — mock
 * data only) so relationships between mock entities are stable and
 * greppable during development. */
export function mockId(prefix: string): string {
  uuidCounter += 1;
  const hex = uuidCounter.toString(16).padStart(8, "0");
  return `${prefix.slice(0, 8).padEnd(8, "0")}-${hex.slice(0, 4)}-4${hex.slice(1, 4)}-a${hex.slice(0, 3)}-${hex}${prefix.length.toString(16).padStart(4, "0")}`;
}

export function daysAgo(days: number, jitterHours = 12): string {
  const ms = Date.now() - days * 86400_000 - randInt(-jitterHours, jitterHours) * 3600_000;
  return new Date(ms).toISOString();
}

export function hoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}
