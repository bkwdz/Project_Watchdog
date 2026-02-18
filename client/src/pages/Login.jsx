import { useContext, useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { AuthContext } from '../contexts/AuthContext';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const { user, loading, login } = useContext(AuthContext);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (!loading && user) {
      navigate('/', { replace: true });
    }
  }, [loading, navigate, user]);

  useEffect(() => {
    if (location.state?.message) {
      setMessage(location.state.message);
    }
  }, [location.state]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    setMessage('');

    const redirectPath = location.state?.from || '/';

    try {
      await login(username, password);
      navigate(redirectPath, { replace: true });
    } catch (err) {
      setError(err?.response?.data?.error || 'Invalid login');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-screen">
      <form className="auth-card" onSubmit={handleSubmit}>
        <p className="brand-overline">Watchdog</p>
        <h2>Sign In</h2>
        <p className="muted">Access your SOC dashboard.</p>

        {message && <p className="success-text">{message}</p>}
        {error && <p className="error-text">{error}</p>}

        <div className="field-stack">
          <label htmlFor="loginUser">Username</label>
          <input
            id="loginUser"
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            required
          />
        </div>

        <div className="field-stack">
          <label htmlFor="loginPass">Password</label>
          <input
            id="loginPass"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
          />
        </div>

        <button type="submit" className="primary-button" disabled={submitting}>
          {submitting ? 'Signing in...' : 'Login'}
        </button>

        <p className="muted">
          Need an account?
          {' '}
          <Link to="/register">Register</Link>
        </p>
      </form>
    </div>
  );
}
