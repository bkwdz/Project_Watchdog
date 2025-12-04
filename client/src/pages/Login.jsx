import React, { useState, useContext } from 'react';
import api from '../api/api';
import { AuthContext } from '../contexts/AuthContext';
import { useNavigate, Link } from 'react-router-dom';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { login } = useContext(AuthContext);
  const navigate = useNavigate();
  const [error, setError] = useState(null);

  const handle = async () => {
    try {
      await login(username, password);
      navigate('/');
    } catch (err) {
      setError('Invalid login');
    }
  };

  return (
    <div style={{ padding: 20 }}>
      <h2>Login</h2>

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

      <button onClick={handle}>Login</button>

      {error && <div style={{ color: 'red' }}>{error}</div>}

      {/* Register button */}
      <div style={{ marginTop: '10px' }}>
        <Link to="/register">
          <button>Register</button>
        </Link>
      </div>
    </div>
  );
}
