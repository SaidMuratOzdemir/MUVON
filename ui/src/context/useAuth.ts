import { createContext, useContext } from "react";
import type { AdminUser } from "../types";

export interface AuthState {
  user: AdminUser | null;
  isAuthenticated: boolean;
  needsSetup: boolean | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  setup: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthState | undefined>(undefined);

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
