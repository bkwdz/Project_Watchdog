import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useContext } from 'react';
import ProtectedRoute from './components/ProtectedRoute';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Devices from './pages/Devices';
import DeviceDetail from './pages/DeviceDetail';
import Scans from './pages/Scans';
import ScanDetail from './pages/ScanDetail';
import Settings from './pages/Settings';
import { AuthContext } from './contexts/AuthContext';

function resolveTitle(pathname) {
  if (pathname === '/') {
    return 'Dashboard';
  }

  if (pathname === '/devices') {
    return 'Devices';
  }

  if (pathname.startsWith('/devices/')) {
    return 'Device Detail';
  }

  if (pathname === '/scans') {
    return 'Scans';
  }

  if (pathname.startsWith('/scans/')) {
    return 'Scan Detail';
  }

  if (pathname === '/settings') {
    return 'Settings';
  }

  return 'Watchdog';
}

function AppLayout() {
  const location = useLocation();
  const { user, loading } = useContext(AuthContext);

  const isPublicRoute = location.pathname === '/login' || location.pathname === '/register';
  const showShell = !isPublicRoute && !loading && Boolean(user);
  const pageTitle = resolveTitle(location.pathname);

  return (
    <div className={`app-shell ${showShell ? '' : 'app-shell-public'}`.trim()}>
      {showShell && <Sidebar />}

      <div className="app-main">
        {showShell && <Topbar title={pageTitle} />}

        <main className={`app-content ${showShell ? '' : 'app-content-public'}`.trim()}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />

            <Route
              path="/"
              element={(
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              )}
            />

            <Route
              path="/devices"
              element={(
                <ProtectedRoute>
                  <Devices />
                </ProtectedRoute>
              )}
            />

            <Route
              path="/devices/:id"
              element={(
                <ProtectedRoute>
                  <DeviceDetail />
                </ProtectedRoute>
              )}
            />

            <Route
              path="/scans"
              element={(
                <ProtectedRoute>
                  <Scans />
                </ProtectedRoute>
              )}
            />

            <Route
              path="/scans/:id"
              element={(
                <ProtectedRoute>
                  <ScanDetail />
                </ProtectedRoute>
              )}
            />

            <Route
              path="/settings"
              element={(
                <ProtectedRoute>
                  <Settings />
                </ProtectedRoute>
              )}
            />

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppLayout />
    </BrowserRouter>
  );
}
