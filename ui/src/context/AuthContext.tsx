import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import * as api from "../api";

interface AuthState {
  token: string | null;
  isAuthenticated: boolean;
  needsSetup: boolean | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  setup: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

const TOKEN_KEY = "dialog_token";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() =>
    localStorage.getItem(TOKEN_KEY),
  );
  const [needsSetup, setNeedsSetup] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  // On mount, verify the stored token and detect whether initial setup is needed.
  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        // If we already have a token, verify it is still valid.
        if (token) {
          try {
            await api.me();
            // Token is good -- no setup needed.
            if (!cancelled) {
              setNeedsSetup(false);
              setLoading(false);
            }
            return;
          } catch (err) {
            // Token invalid or expired -- clear it.
            if (!cancelled) {
              localStorage.removeItem(TOKEN_KEY);
              setToken(null);
            }
          }
        }

        // No valid token. Probe the backend to see if setup is needed.
        // The login endpoint with empty credentials will return a 401 if an
        // admin exists. If no admin exists the backend typically returns a
        // specific status / error that we can detect. As a simpler heuristic
        // we try the health endpoint first, then attempt a lightweight probe.
        try {
          await api.health();
        } catch {
          // Backend unreachable -- leave needsSetup as null.
          if (!cancelled) setLoading(false);
          return;
        }

        // Try to call GET /api/auth/setup to check if setup is required.
        // Many Go APIs expose this; if not supported we fall back to assuming
        // setup is NOT needed (the login form will handle the rest).
        try {
          const res = await fetch("/api/auth/setup");
          if (res.ok) {
            const data = await res.json();
            // The backend returns { needs_setup: true/false } or similar.
            if (!cancelled) {
              setNeedsSetup(
                data.needs_setup === true || data.setup_required === true,
              );
            }
          } else if (res.status === 404) {
            // Endpoint does not exist -- assume setup is not needed.
            if (!cancelled) setNeedsSetup(false);
          } else {
            if (!cancelled) setNeedsSetup(false);
          }
        } catch {
          if (!cancelled) setNeedsSetup(false);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    check();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const { token: newToken } = await api.login(username, password);
    localStorage.setItem(TOKEN_KEY, newToken);
    setToken(newToken);
    setNeedsSetup(false);
  }, []);

  const setup = useCallback(async (username: string, password: string) => {
    const { token: newToken } = await api.setup(username, password);
    localStorage.setItem(TOKEN_KEY, newToken);
    setToken(newToken);
    setNeedsSetup(false);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
  }, []);

  const value: AuthState = {
    token,
    isAuthenticated: token !== null,
    needsSetup,
    loading,
    login,
    setup,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
