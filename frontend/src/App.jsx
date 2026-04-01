<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
import { Navigate, Route, Routes } from "react-router-dom";
import DashboardPage from "./pages/DashboardPage";
import LoginPage from "./pages/LoginPage";
import TargetPage from "./pages/TargetPage";

function PrivateRoute({ children }) {
  const token = localStorage.getItem("reconx_token");
  return token ? children : <Navigate to="/login" />;
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
import { Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import AuthPage from './pages/AuthPage'
import DashboardPage from './pages/DashboardPage'
import TargetDetailPage from './pages/TargetDetailPage'

function ProtectedRoute({ children }) {
  const { token } = useAuth()
  return token ? children : <Navigate to="/auth" />
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
}

export default function App() {
  return (
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <PrivateRoute>
            <DashboardPage />
          </PrivateRoute>
        }
      />
      <Route
        path="/targets/:targetId"
        element={
          <PrivateRoute>
            <TargetPage />
          </PrivateRoute>
        }
      />
    </Routes>
  );
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
    <AuthProvider>
      <Routes>
        <Route path="/auth" element={<AuthPage />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <DashboardPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/targets/:id"
          element={
            <ProtectedRoute>
              <TargetDetailPage />
            </ProtectedRoute>
          }
        />
      </Routes>
    </AuthProvider>
  )
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
}
