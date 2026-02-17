import React, { useState, useContext } from 'react';
import { AuthContext } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import api from '../api/api';

export default function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState(null);

  const { user } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleRegister = async () => {
    setError(null);

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    try {
      await api.post("/auth/register", { username, password });
      navigate("/login");
    } catch (err) {
      console.error("Register error:", err);
      setError(err.response?.data?.error || "Register failed");
    }
  };

  return (
    <div style={{ padding: 20 }}>
      <h2>Create Account</h2>

      {user && user.role !== "admin" && (
        <div style={{ color: "red", marginBottom: 15 }}>
          Only administrators can create new accounts.
        </div>
      )}

      <input
        placeholder="username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        style={{ display: "block", marginBottom: 10 }}
      />

      <input
        placeholder="password"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        style={{ display: "block", marginBottom: 10 }}
      />

      <input
        placeholder="confirm password"
        type="password"
        value={confirmPassword}
        onChange={(e) => setConfirmPassword(e.target.value)}
        style={{ display: "block", marginBottom: 10 }}
      />

      <button
        onClick={handleRegister}
        disabled={user && user.role !== "admin"}
      >
        Create Account
      </button>

      {error && (
        <div style={{ color: "red", marginTop: 10 }}>
          {error}
        </div>
      )}
    </div>
  );
}
