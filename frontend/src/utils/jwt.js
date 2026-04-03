/**
 * Decode JWT payload (without verification - verification happens server-side).
 * Only safe because we trust the server that issued the token.
 */
export function decodeJwt(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const decoded = atob(parts[1]);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}
