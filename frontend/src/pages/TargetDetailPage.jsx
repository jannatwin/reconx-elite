import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'

export default function TargetDetailPage() {
  const { id } = useParams()
  const [target, setTarget] = useState(null)
  const [filter, setFilter] = useState('')

  const loadTarget = async () => {
    const { data } = await api.get(`/targets/${id}`)
    setTarget(data)
  }

  useEffect(() => {
    loadTarget()
    const interval = setInterval(loadTarget, 5000)
    return () => clearInterval(interval)
  }, [id])

  const latestScan = target?.scans?.[0]

  const filteredEndpoints = useMemo(() => {
    const eps = latestScan?.endpoints || []
    if (!filter) return eps
    return eps.filter((e) => e.url.includes(filter))
  }, [latestScan, filter])

  const triggerScan = async () => {
    await api.post(`/scan/${id}`)
    await loadTarget()
  }

  if (!target) return <div className="container">Loading...</div>

  return (
    <div className="container">
      <Link to="/">← Back</Link>
      <div className="header-row">
        <h1>{target.domain}</h1>
        <button onClick={triggerScan}>Trigger Scan</button>
      </div>
      <p>Status: <strong>{latestScan?.status || 'not-scanned'}</strong></p>

      <div className="card">
        <h2>Subdomains</h2>
        <table><thead><tr><th>Hostname</th><th>Live</th></tr></thead><tbody>
          {(latestScan?.subdomains || []).map((s) => <tr key={s.id}><td>{s.hostname}</td><td>{s.is_live ? 'yes' : 'no'}</td></tr>)}
        </tbody></table>
      </div>

      <div className="card">
        <h2>Endpoints</h2>
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter endpoints" />
        <table><thead><tr><th>URL</th></tr></thead><tbody>
          {filteredEndpoints.map((e) => <tr key={e.id}><td>{e.url}</td></tr>)}
        </tbody></table>
      </div>

      <div className="card">
        <h2>Vulnerabilities</h2>
        <table><thead><tr><th>Template</th><th>Severity</th><th>Matched</th><th>Description</th></tr></thead><tbody>
          {(latestScan?.vulnerabilities || []).map((v) => (
            <tr key={v.id}><td>{v.template_id}</td><td>{v.severity}</td><td>{v.matched_at}</td><td>{v.description}</td></tr>
          ))}
        </tbody></table>
      </div>
    </div>
  )
}
