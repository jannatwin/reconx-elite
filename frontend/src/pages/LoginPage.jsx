import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { apiRequest } from "../api";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isRegister, setIsRegister] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    try {
      const endpoint = isRegister ? "/auth/register" : "/auth/login";
      const data = await apiRequest(endpoint, { method: "POST", body: { email, password } });
      localStorage.setItem("reconx_token", data.access_token);
      navigate("/");
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="container">
      <h1>ReconX</h1>
      <p className="disclaimer">
        Use only on domains you own or are explicitly authorized to test.
      </p>
      <form className="card" onSubmit={onSubmit}>
        <h2>{isRegister ? "Register" : "Login"}</h2>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" required />
        <input
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
          type="password"
          required
        />
        {error && <p className="error">{error}</p>}
        <button type="submit">{isRegister ? "Create Account" : "Sign In"}</button>
        <button type="button" onClick={() => setIsRegister((v) => !v)}>
          {isRegister ? "Have an account? Login" : "No account? Register"}
        </button>
      </form>
    </div>
  );
}
