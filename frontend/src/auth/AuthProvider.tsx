import type { ReactNode } from "react";
import { AuthContext, type AuthState } from "./useAuth";

/**
 * Development-mode auth provider (spec §2/§74): assumes an already-
 * authenticated "Analyst" placeholder and never renders a login screen.
 *
 * To wire up real authentication later: implement a new provider (e.g.
 * `OidcAuthProvider`) that supplies the same `AuthState` shape — a real
 * `user`, `isAuthenticated`, and `logout` — from wherever your identity
 * provider lives, and swap it in at the app root (main.tsx). No
 * component outside this file needs to change, since every consumer
 * only ever calls `useAuth()`.
 */
const DEV_USER: AuthState = {
  user: { id: "dev-analyst", displayName: "Analyst", role: "analyst" },
  isAuthenticated: true,
  logout: () => {
    console.info("[dev-auth] logout is a no-op until a real auth provider is wired up");
  },
};

export function AuthProvider({ children }: { children: ReactNode }) {
  return <AuthContext.Provider value={DEV_USER}>{children}</AuthContext.Provider>;
}
