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
  const [mousePos, setMousePos] = useState({ x: 50, y: 50 });
  
  const navigate = useNavigate();
  const { login } = useAuth();

  function handleMouseMove(e) {
    const { clientX, clientY } = e;
    const { innerWidth, innerHeight } = window;
    setMousePos({
      x: (clientX / innerWidth) * 100,
      y: (clientY / innerHeight) * 100,
    });
  }

  async function onSubmit(event) {
    event.preventDefault();
    if (mode === "register" && password.length < 8) {
      setError("Password must be at least 8 characters long");
      return;
    }
    
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
    <main 
      className="auth-shell" 
      onMouseMove={handleMouseMove}
      style={{ "--mouse-x": `${mousePos.x}%`, "--mouse-y": `${mousePos.y}%` }}
    >
      <div className="auth-background"></div>
      <div className="auth-shapes">
        <div className="auth-shape" style={{ top: '10%', left: '10%', width: '350px', height: '350px' }}></div>
        <div className="auth-shape" style={{ top: '65%', left: '85%', width: '450px', height: '450px', animationDelay: '-5s' }}></div>
        <div className="auth-shape" style={{ top: '35%', left: '45%', width: '300px', height: '300px', animationDelay: '-10s' }}></div>
      </div>

      <div className="auth-container">
        <section className="auth-panel">
          <p className="eyebrow">ReconX Elite</p>
          <h1>Operate your recon pipeline with a clean attack-surface view.</h1>
          <p className="auth-copy">
            Use this platform only against infrastructure you own or are explicitly authorized to assess.
          </p>
        </section>

        <section className="auth-card-wrap">
          <div className="auth-card">
            <form onSubmit={onSubmit}>
              <h2>{mode === "register" ? "Create account" : "Sign in"}</h2>
              <label>
                User Name
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
                  placeholder="••••••••"
                  type="password"
                  minLength="8"
                  required
                />
              </label>
              {error ? <p className="error-text">{error}</p> : null}
              <button className="primary-button" disabled={isSubmitting} type="submit">
                {isSubmitting ? "Working..." : "Submit"}
              </button>
            </form>
            <button
              className="ghost-button"
              onClick={() => setMode(mode === "register" ? "login" : "register")}
              type="button"
            >
              {mode === "register" ? "Already have an account?" : "Need an account?"}
            </button>
          </div>
        </section>
      </div>
    </main>
  );
}
