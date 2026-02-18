import { useContext, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AuthContext } from '../contexts/AuthContext';

export default function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const { user, register } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleRegister = async (event) => {
    event.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setSubmitting(true);

    try {
      await register(username, password);
      navigate('/login', {
        replace: true,
        state: { message: 'Account created successfully. You can now log in.' },
      });
    } catch (err) {
      setError(err?.response?.data?.error || 'Register failed');
    } finally {
      setSubmitting(false);
    }
  };

  const blocked = Boolean(user && user.role !== 'admin');

  return (
    <div className="auth-screen">
      <form className="auth-card" onSubmit={handleRegister}>
        <p className="brand-overline">Watchdog</p>
        <h2>Create Account</h2>
        <p className="muted">Admin-only user provisioning.</p>

        {blocked && <p className="error-text">Only administrators can create new accounts.</p>}
        {error && <p className="error-text">{error}</p>}

        <div className="field-stack">
          <label htmlFor="registerUser">Username</label>
          <input
            id="registerUser"
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            required
          />
        </div>

        <div className="field-stack">
          <label htmlFor="registerPass">Password</label>
          <input
            id="registerPass"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="new-password"
            required
          />
        </div>

        <div className="field-stack">
          <label htmlFor="registerConfirm">Confirm Password</label>
          <input
            id="registerConfirm"
            type="password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            autoComplete="new-password"
            required
          />
        </div>

        <button type="submit" className="primary-button" disabled={blocked || submitting}>
          {submitting ? 'Creating...' : 'Create Account'}
        </button>

        <p className="muted">
          Back to
          {' '}
          <Link to="/login">login</Link>
          .
        </p>
      </form>
    </div>
  );
}
