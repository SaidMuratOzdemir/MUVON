import {
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import * as api from "../api";
import type { AdminUser } from "../types";
import { AuthContext, type AuthState } from "./useAuth";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AdminUser | null>(null);
  const [needsSetup, setNeedsSetup] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  // Called by the api layer when a refresh attempt returns 401 — i.e. the
  // refresh token is gone, expired, or revoked. Clearing user state drops the
  // SPA back to the login screen on the next render.
  useEffect(() => {
    api.setAuthExpiredHandler(() => setUser(null));
    return () => api.setAuthExpiredHandler(null);
  }, []);

  // On mount, probe the session and detect whether initial setup is needed.
  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const u = await api.me();
        if (!cancelled) {
          setUser(u);
          setNeedsSetup(false);
          setLoading(false);
        }
        return;
      } catch {
        // No valid session — fall through to the setup probe.
      }

      try {
        await api.health();
      } catch {
        if (!cancelled) setLoading(false);
        return;
      }

      try {
        const res = await fetch("/api/auth/setup", { credentials: "include" });
        if (res.ok) {
          const data = await res.json();
          if (!cancelled) {
            setNeedsSetup(
              data.needs_setup === true || data.setup_required === true,
            );
          }
        } else {
          if (!cancelled) setNeedsSetup(false);
        }
      } catch {
        if (!cancelled) setNeedsSetup(false);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    check();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const { user: u } = await api.login(username, password);
    setUser(u);
    setNeedsSetup(false);
  }, []);

  const setup = useCallback(async (username: string, password: string) => {
    const { user: u } = await api.setup(username, password);
    setUser(u);
    setNeedsSetup(false);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      /* noop */
    }
    setUser(null);
  }, []);

  const value: AuthState = {
    user,
    isAuthenticated: user !== null,
    needsSetup,
    loading,
    login,
    setup,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
