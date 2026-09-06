import { API_BASE_URL } from "./config";
import type { ApiError } from "@/types/common";

export class HttpError extends Error {
  category: ApiError["category"];
  status: number;

  constructor(status: number, error: ApiError) {
    super(error.message);
    this.name = "HttpError";
    this.status = status;
    this.category = error.category;
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  searchParams?: Record<string, string | number | boolean | undefined>;
  signal?: AbortSignal;
}

/** Thin fetch wrapper for the real (non-mock) API path — see
 * src/api/config.ts's doc comment for why this is not yet exercised by
 * any live backend in this repository. Every resource module in
 * src/api/*.ts calls this the same way it would call a mock function,
 * so wiring a real backend up is a one-line change per module (flip
 * USE_MOCKS false via VITE_API_BASE_URL), never a component rewrite. */
export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const url = new URL(path.replace(/^\//, ""), API_BASE_URL.endsWith("/") ? API_BASE_URL : `${API_BASE_URL}/`);
  if (options.searchParams) {
    for (const [key, value] of Object.entries(options.searchParams)) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }
  }

  const res = await fetch(url.toString(), {
    method: options.method ?? "GET",
    headers: { "Content-Type": "application/json" },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    signal: options.signal,
  });

  if (!res.ok) {
    let error: ApiError = { category: "internal", message: "An unexpected error occurred." };
    try {
      const body = await res.json();
      if (body?.error?.message) {
        error = { category: body.error.category ?? "internal", message: body.error.message };
      }
    } catch {
      // response body wasn't JSON — keep the generic error above rather
      // than exposing a raw parse failure to the UI.
    }
    throw new HttpError(res.status, error);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}
