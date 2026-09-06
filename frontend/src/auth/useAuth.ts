import { createContext, useContext } from "react";

/**
 * The authentication boundary this app will eventually plug a real
 * provider into (spec §2/§74). Authentication is explicitly NOT
 * implemented — this context exists so every component that will
 * eventually need `user`/`isAuthenticated`/`logout` already reads them
 * from one place, and a real AuthProvider can replace
 * DevAuthProvider (see AuthProvider.tsx) later without touching any
 * consumer.
 */
export interface AuthUser {
  id: string;
  displayName: string;
  role: string;
}

export interface AuthState {
  user: AuthUser;
  isAuthenticated: true;
  /** No-op today. A real provider replaces this with an actual sign-out
   * flow; kept in the interface now so call sites don't need to change
   * later. */
  logout: () => void;
}

export const AuthContext = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
