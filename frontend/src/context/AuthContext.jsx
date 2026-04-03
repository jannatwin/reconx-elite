import { createContext, useContext, useEffect, useMemo, useState } from "react";

import { api, setAuthHandlers } from "../api/client";
import { decodeJwt } from "../utils/jwt";

const STORAGE_KEY = "reconx_auth";
const AuthContext = createContext(null);

function loadStoredAuth() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(loadStoredAuth);

  useEffect(() => {
    if (auth) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(auth));
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  }, [auth]);

  const login = (tokens) => {
    setAuth({
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
    });
  };

  const logout = () => {
    setAuth(null);
  };

  const refreshTokens = async () => {
    if (!auth?.refreshToken) {
      throw new Error("No refresh token available");
    }
    const { data } = await api.post("/auth/refresh", { refresh_token: auth.refreshToken });
    const nextAuth = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
    };
    setAuth(nextAuth);
    return nextAuth;
  };

  useEffect(() => {
    setAuthHandlers({
      getTokens: () => auth,
      refreshTokens,
      logout,
    });
  }, [auth]);

  const value = useMemo(() => {
    let role = null;
    if (auth?.accessToken) {
      const decoded = decodeJwt(auth.accessToken);
      role = decoded?.role || null;
    }
    return {
      auth,
      accessToken: auth?.accessToken ?? null,
      refreshToken: auth?.refreshToken ?? null,
      isAuthenticated: Boolean(auth?.accessToken),
      role,
      isAdmin: role === "admin",
      login,
      logout,
    };
  }, [auth]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
