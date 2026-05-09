/**
 * App.tsx — Root component with React Router v6 protected routes.
 *
 * Route protection: unauthenticated users are redirected to /login.
 * The access token lives in module memory in client.ts — ProtectedRoute
 * checks that to gate access.
 */

import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";
import { getAccessToken } from "./api/client";
import Layout from "./components/Layout";
import Alerts from "./views/Alerts";
import Dashboard from "./views/Dashboard";
import Detections from "./views/Detections";
import Ingest from "./views/Ingest";
import Login from "./views/Login";
import Settings from "./views/Settings";
import Workbench from "./views/Workbench";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  if (!getAccessToken()) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/workbench" element={<Workbench />} />
                  <Route path="/detections" element={<Detections />} />
                  <Route path="/alerts" element={<Alerts />} />
                  <Route path="/ingest" element={<Ingest />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
