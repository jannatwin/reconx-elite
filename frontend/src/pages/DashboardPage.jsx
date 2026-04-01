import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiRequest } from "../api";

export default function DashboardPage() {
  const [targets, setTargets] = useState([]);
  const [domain, setDomain] = useState("");
  const [error, setError] = useState("");
  const token = localStorage.getItem("reconx_token");
  const navigate = useNavigate();

  async function fetchTargets() {
    try {
      const data = await apiRequest("/targets", { token });
      setTargets(data);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    fetchTargets();
  }, []);

  async function onAddTarget(e) {
    e.preventDefault();
    setError("");
    try {
      await apiRequest("/targets", { method: "POST", token, body: { domain } });
      setDomain("");
      fetchTargets();
    } catch (err) {
      setError(err.message);
    }
  }

  function logout() {
    localStorage.removeItem("reconx_token");
    navigate("/login");
  }

  return (
    <div className="container">
      <div className="row">
        <h1>ReconX Dashboard</h1>
        <button onClick={logout}>Logout</button>
      </div>

      <p className="disclaimer">
        Legal reminder: run scans only on assets where you have explicit authorization.
      </p>

      <form className="card" onSubmit={onAddTarget}>
        <h2>Add Target</h2>
        <input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          required
        />
        <button type="submit">Add Domain</button>
      </form>

      {error && <p className="error">{error}</p>}

      <div className="card">
        <h2>Targets</h2>
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Scans</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {targets.map((target) => (
              <tr key={target.id}>
                <td>{target.domain}</td>
                <td>{target.scans?.length || 0}</td>
                <td>
                  <Link to={`/targets/${target.id}`}>Open</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
