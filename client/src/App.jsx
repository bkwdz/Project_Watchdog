import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import RequireAuth from "./components/RequireAuth";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import Scans from "./pages/Scans";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";

function AppLayout() {
  const location = useLocation();

  const hideSidebarRoutes = ["/login", "/register"];
  const shouldHideSidebar = hideSidebarRoutes.includes(location.pathname);

  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
      
      {/* Sidebar (hidden on login/register) */}
      {!shouldHideSidebar && <Sidebar />}

      {/* Main area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        
        {/* Top bar only on logged-in pages */}
        {!shouldHideSidebar && <Topbar />}

        {/* Page content (scrollable) */}
        <div style={{ flex: 1, overflowY: "auto", padding: "20px" }}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />

            <Route
              path="/"
              element={
                <RequireAuth>
                  <Dashboard />
                </RequireAuth>
              }
            />

            <Route
              path="/devices"
              element={
                <RequireAuth>
                  <Devices />
                </RequireAuth>
              }
            />

            <Route
              path="/scans"
              element={
                <RequireAuth>
                  <Scans />
                </RequireAuth>
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
