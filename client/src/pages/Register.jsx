import React, { useState, useContext } from 'react';
import { AuthContext } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

export default function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const { user, register } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleRegister = async () => {
    setError(null);
    setSubmitting(true);

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      setSubmitting(false);
      return;
    }

    try {
      await register(username, password);
      navigate("/login", {
        replace: true,
        state: { message: "Account created successfully. You can now log in." },
      });
    } catch (err) {
      setError(err.response?.data?.error || "Register failed");
    } finally {
      setSubmitting(false);
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
        disabled={(user && user.role !== "admin") || submitting}
      >
        {submitting ? "Creating..." : "Create Account"}
      </button>

      {error && (
        <div style={{ color: "red", marginTop: 10 }}>
          {error}
        </div>
      )}
    </div>
  );
}
