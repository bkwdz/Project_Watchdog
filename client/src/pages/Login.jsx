import React, { useEffect, useState, useContext } from 'react';
import { AuthContext } from '../contexts/AuthContext';
import { useNavigate, Link, useLocation } from 'react-router-dom';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { user, loading, login } = useContext(AuthContext);
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(location.state?.message || null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!loading && user) {
      navigate('/', { replace: true });
    }
  }, [loading, user, navigate]);

  const handle = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setMessage(null);

    const redirectPath = location.state?.from || '/';

    try {
      await login(username, password);
      setMessage('Login successful. Redirecting...');
      setTimeout(() => navigate(redirectPath, { replace: true }), 250);
    } catch (err) {
      setError(err.response?.data?.error || 'Invalid login');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ padding: 20 }}>
      <h2>Login</h2>

      {message && <div style={{ color: 'green', marginBottom: '10px' }}>{message}</div>}
      {error && <div style={{ color: 'red', marginBottom: '10px' }}>{error}</div>}

      <form onSubmit={handle}>
        <input 
          placeholder="username"
          value={username}
          onChange={e => setUsername(e.target.value)}
        />

        <input 
          placeholder="password"
          type="password"
          value={password}
          onChange={e => setPassword(e.target.value)}
        />

        <button type="submit" disabled={submitting}>
          {submitting ? 'Logging in...' : 'Login'}
        </button>
      </form>

      {/* Register button */}
      <div style={{ marginTop: '10px' }}>
        <Link to="/register">
          <button>Register</button>
        </Link>
      </div>
    </div>
  );
}
