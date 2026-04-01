<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiRequest } from "../api";

export default function DashboardPage() {
  const [targets, setTargets] = useState([]);
  const [notifications, setNotifications] = useState([]);
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

  async function fetchNotifications() {
    try {
      const data = await apiRequest("/notifications", { token });
      setNotifications(data);
    } catch (err) {
      // Ignore errors
    }
  }

  useEffect(() => {
    fetchTargets();
    fetchNotifications();
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

      {notifications.length > 0 && (
        <div className="card">
          <h2>Notifications</h2>
          <ul>
            {notifications.slice(0, 5).map((n) => (
              <li key={n.id} className={n.read ? "" : "unread"}>
                {n.message}
              </li>
            ))}
          </ul>
        </div>
      )}

=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../context/AuthContext'

export default function DashboardPage() {
  const [targets, setTargets] = useState([])
  const [domain, setDomain] = useState('')
  const [error, setError] = useState('')
  const { logout } = useAuth()

  const loadTargets = async () => {
    const { data } = await api.get('/targets')
    setTargets(data)
  }

  useEffect(() => {
    loadTargets().catch(() => setError('Failed to load targets'))
  }, [])

  const addTarget = async (e) => {
    e.preventDefault()
    try {
      await api.post('/targets', { domain })
      setDomain('')
      await loadTargets()
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not add target')
    }
  }

  return (
    <div className="container">
      <div className="header-row">
        <h1>ReconX Dashboard</h1>
        <button onClick={logout}>Logout</button>
      </div>
      <p className="disclaimer">Legal disclaimer: use this tool only on assets with explicit permission.</p>
      <form onSubmit={addTarget} className="card">
        <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" required />
        <button type="submit">Add Target</button>
      </form>
      {error && <p className="error">{error}</p>}
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
      <div className="card">
        <h2>Targets</h2>
        <table>
          <thead>
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
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
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
            <tr><th>Domain</th><th>Latest status</th><th></th></tr>
          </thead>
          <tbody>
            {targets.map((t) => {
              const latest = t.scans?.[0]
              return (
                <tr key={t.id}>
                  <td>{t.domain}</td>
                  <td>{latest?.status || 'not-scanned'}</td>
                  <td><Link to={`/targets/${t.id}`}>View</Link></td>
                </tr>
              )
            })}
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
          </tbody>
        </table>
      </div>
    </div>
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
  );
=======
  )
>>>>>>> theirs
=======
  )
>>>>>>> theirs
=======
  )
>>>>>>> theirs
=======
  )
>>>>>>> theirs
}
