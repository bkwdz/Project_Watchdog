import React, { createContext, useState, useEffect } from 'react';
import api from '../api/api';

const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchMe = async () => {
    setLoading(true);
    try {
      const res = await api.get('/auth/me');
      setUser(res.data);
    } catch (err) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMe();
  }, []);

  const login = async (username, password) => {
    const res = await api.post('/auth/login', { username, password });
    setUser(res.data.user);
    return res.data.user;
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      setUser(null);
    }
  };

  const register = async (username, password) => {
    const res = await api.post('/auth/register', { username, password });
    return res.data;
  };

  const value = {
    user,
    loading,
    login,
    logout,
    register,
    refresh: fetchMe,
    setUser,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export { AuthContext, AuthProvider };
