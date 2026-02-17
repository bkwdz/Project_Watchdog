import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import { useContext } from "react";
import ProtectedRoute from "./components/ProtectedRoute";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import Scans from "./pages/Scans";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import { AuthContext } from "./contexts/AuthContext";

function AppLayout() {
  const location = useLocation();
  const { user, loading } = useContext(AuthContext);

  const publicRoutes = ["/login", "/register"];
  const isPublicRoute = publicRoutes.includes(location.pathname);
  const showShell = !isPublicRoute && !loading && !!user;

  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
      
      {/* Sidebar (only on authenticated pages) */}
      {showShell && <Sidebar />}

      {/* Main area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        
        {/* Top bar only on authenticated pages */}
        {showShell && <Topbar />}

        {/* Page content (scrollable) */}
        <div style={{ flex: 1, overflowY: "auto", padding: "20px" }}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />

            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              }
            />

            <Route
              path="/devices"
              element={
                <ProtectedRoute>
                  <Devices />
                </ProtectedRoute>
              }
            />

            <Route
              path="/scans"
              element={
                <ProtectedRoute>
                  <Scans />
                </ProtectedRoute>
              }
            />
          </Routes>
        </div>
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
