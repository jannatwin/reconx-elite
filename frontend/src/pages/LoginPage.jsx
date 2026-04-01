import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";

export default function LoginPage() {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const navigate = useNavigate();
  const { login } = useAuth();

  async function onSubmit(event) {
    event.preventDefault();
    setIsSubmitting(true);
    setError("");
    try {
      const endpoint = mode === "register" ? "/auth/register" : "/auth/login";
      const { data } = await api.post(endpoint, { email, password });
      login(data);
      navigate("/", { replace: true });
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Authentication failed");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-panel">
        <p className="eyebrow">ReconX Elite</p>
        <h1>Operate your recon pipeline with a clean attack-surface view.</h1>
        <p className="auth-copy">
          Use this platform only against infrastructure you own or are explicitly authorized to assess.
        </p>
      </section>
      <section className="auth-card">
        <form onSubmit={onSubmit}>
          <h2>{mode === "register" ? "Create account" : "Welcome back"}</h2>
          <label>
            Email
            <input
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="hunter@team.example"
              type="email"
              required
            />
          </label>
          <label>
            Password
            <input
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Minimum 8 characters"
              type="password"
              required
            />
          </label>
          {error ? <p className="error-text">{error}</p> : null}
          <button className="primary-button" disabled={isSubmitting} type="submit">
            {isSubmitting ? "Working..." : mode === "register" ? "Create account" : "Sign in"}
          </button>
        </form>
        <button className="ghost-button" onClick={() => setMode(mode === "register" ? "login" : "register")} type="button">
          {mode === "register" ? "Already have an account?" : "Need an account?"}
        </button>
      </section>
    </main>
  );
}
