import { Navigate, Route, Routes } from "react-router-dom";
import DashboardPage from "./pages/DashboardPage";
import LoginPage from "./pages/LoginPage";
import TargetPage from "./pages/TargetPage";

function PrivateRoute({ children }) {
  const token = localStorage.getItem("reconx_token");
  return token ? children : <Navigate to="/login" />;
}

export default function App() {
  return (
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
}
