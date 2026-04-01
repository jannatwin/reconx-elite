import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../context/AuthContext'

export default function AuthPage() {
  const [isRegister, setIsRegister] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const { login } = useAuth()

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    try {
      if (isRegister) {
        await api.post('/auth/register', { email, password })
      }
      const params = new URLSearchParams()
      params.append('username', email)
      params.append('password', password)
      const { data } = await api.post('/auth/login', params)
      login(data.access_token)
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed')
    }
  }

  return (
    <div className="container">
      <h1>ReconX</h1>
      <p className="disclaimer">Only scan domains you own or are explicitly authorized to test.</p>
      <form onSubmit={submit} className="card">
        <h2>{isRegister ? 'Register' : 'Login'}</h2>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" type="email" required />
        <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" required />
        {error && <p className="error">{error}</p>}
        <button type="submit">{isRegister ? 'Create account' : 'Login'}</button>
      </form>
      <button className="link" onClick={() => setIsRegister((v) => !v)}>
        {isRegister ? 'Have an account? Login' : 'No account? Register'}
      </button>
    </div>
  )
}
