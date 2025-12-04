import { useContext } from "react";
import { AuthContext } from "../contexts/AuthContext";
import { Navigate } from "react-router-dom";

export default function RequireAuth({ children }) {
  const { user, loading } = useContext(AuthContext);

  if (loading) return null; // or a spinner

  if (!user) return <Navigate to="/login" replace />;

  return children;
}
