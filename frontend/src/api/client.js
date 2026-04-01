import axios from "axios";

const backendBaseUrl = (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000").replace(/\/+$/, "");

let getTokens = () => null;
let refreshTokens = async () => {
  throw new Error("No refresh handler configured");
};
let logout = () => {};
let refreshPromise = null;

export const api = axios.create({
  baseURL: backendBaseUrl,
  withCredentials: false,
});

export function setAuthHandlers(handlers) {
  getTokens = handlers.getTokens;
  refreshTokens = handlers.refreshTokens;
  logout = handlers.logout;
}

api.interceptors.request.use((config) => {
  const tokens = getTokens?.();
  if (tokens?.accessToken) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${tokens.accessToken}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const { response, config } = error;
    if (!response || response.status !== 401 || config?._retry || config?.url?.includes("/auth/refresh")) {
      throw error;
    }

    try {
      if (!refreshPromise) {
        refreshPromise = refreshTokens().finally(() => {
          refreshPromise = null;
        });
      }
      const tokens = await refreshPromise;
      config._retry = true;
      config.headers = config.headers ?? {};
      config.headers.Authorization = `Bearer ${tokens.accessToken}`;
      return api(config);
    } catch (refreshError) {
      logout();
      throw refreshError;
    }
  },
);

export { backendBaseUrl };
