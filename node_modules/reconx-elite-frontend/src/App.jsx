import { Navigate, Route, Routes } from "react-router-dom";

import { AuthProvider, useAuth } from "./context/AuthContext";
import AdminDashboardPage from "./pages/AdminDashboardPage";
import DashboardPage from "./pages/DashboardPage";
import LoginPage from "./pages/LoginPage";
import NotificationCenter from "./components/NotificationCenter";
import TargetPage from "./pages/TargetPage";
import ErrorBoundary from "./components/ErrorBoundary";

function ProtectedRoute({ children }) {
  const { isAuthenticated, error } = useAuth();
  
  try {
    if (error) {
      return (
        <div style={{ padding: "20px", color: "red", fontWeight: "bold" }}>
          Authentication error: {error.message}
          <br />
          <Navigate to="/login" replace />
        </div>
      );
    }
    
    return isAuthenticated ? children : <Navigate to="/login" replace />;
  } catch (error) {
    console.error("Auth context error in ProtectedRoute:", error);
    return (
      <div style={{ padding: "20px", color: "red", fontWeight: "bold" }}>
        Failed to check authentication. Please refresh and try again.
      </div>
    );
  }
}

function AdminRoute({ children }) {
  const { isAuthenticated, isAdmin, error } = useAuth();
  
  try {
    if (error) {
      return (
        <div style={{ padding: "20px", color: "red", fontWeight: "bold" }}>
          Authentication error: {error.message}
          <br />
          <Navigate to="/login" replace />
        </div>
      );
    }
    
    if (!isAuthenticated) {
      return <Navigate to="/login" replace />;
    }
    if (!isAdmin) {
      return (
        <div style={{ padding: "20px", color: "orange", fontWeight: "bold" }}>
          Access denied. Admin privileges required.
          <br />
          <Navigate to="/" replace />
        </div>
      );
    }
    return children;
  } catch (error) {
    console.error("Auth context error in AdminRoute:", error);
    return (
      <div style={{ padding: "20px", color: "red", fontWeight: "bold" }}>
        Failed to verify admin status. Please refresh and try again.
      </div>
    );
  }
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/targets/:targetId"
        element={
          <ProtectedRoute>
            <TargetPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin"
        element={
          <AdminRoute>
            <AdminDashboardPage />
          </AdminRoute>
        }
      />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <NotificationCenter>
        <ErrorBoundary>
          <AppRoutes />
        </ErrorBoundary>
      </NotificationCenter>
    </AuthProvider>
  );
}
