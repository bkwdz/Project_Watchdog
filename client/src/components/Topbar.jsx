import { useContext, useMemo, useState } from 'react';
import { AuthContext } from '../contexts/AuthContext';

export default function Topbar({ title }) {
  const { user, logout } = useContext(AuthContext);
  const [menuOpen, setMenuOpen] = useState(false);

  const initials = useMemo(() => {
    if (!user?.username) {
      return '?';
    }

    return user.username.slice(0, 2).toUpperCase();
  }, [user]);

  return (
    <header className="topbar">
      <div>
        <h2 className="topbar-title">{title}</h2>
        <p className="topbar-subtitle">Security Operations Console</p>
      </div>

      <div className="topbar-user">
        <button type="button" className="avatar-btn" onClick={() => setMenuOpen((value) => !value)}>
          {initials}
        </button>

        {menuOpen && (
          <div className="user-menu">
            <p>{user?.username || 'Unknown user'}</p>
            <p className="user-role">Role: {user?.role || '-'}</p>
            <button type="button" className="danger-button" onClick={logout}>
              Logout
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
