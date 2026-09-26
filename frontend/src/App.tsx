import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ScanProvider } from './context/ScanContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Landing } from './pages/Landing';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Dashboard } from './pages/Dashboard';
import { Profile } from './pages/Profile';
import { NewScan } from './pages/NewScan';
import { ScanHistory } from './pages/ScanHistory';
import { ScanDetails } from './pages/ScanDetails';
import { ReconResults } from './pages/ReconResults';
import { AnalyticsDashboard } from './pages/AnalyticsDashboard';
import { RiskAnalytics } from './pages/RiskAnalytics';
import { FindingsDashboard } from './pages/FindingsDashboard';
import { Vulnerabilities } from './pages/Vulnerabilities';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <ScanProvider>
        <Router>
        <Routes>
          {/* Public Landing & Marketing Page */}
          <Route path="/" element={<Landing />} />

          {/* Public Auth Routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Protected SOC Routes (wrapped by Layout in ProtectedRoute) */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/scans/new"
            element={
              <ProtectedRoute>
                <NewScan />
              </ProtectedRoute>
            }
          />
          <Route
            path="/scans"
            element={
              <ProtectedRoute>
                <ScanHistory />
              </ProtectedRoute>
            }
          />
          <Route
            path="/scans/:scanId"
            element={
              <ProtectedRoute>
                <ScanDetails />
              </ProtectedRoute>
            }
          />
          <Route
            path="/recon"
            element={
              <ProtectedRoute>
                <ReconResults />
              </ProtectedRoute>
            }
          />
          <Route
            path="/analytics"
            element={
              <ProtectedRoute>
                <AnalyticsDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/analytics/risk"
            element={
              <ProtectedRoute>
                <RiskAnalytics />
              </ProtectedRoute>
            }
          />
          <Route
            path="/findings-dashboard"
            element={
              <ProtectedRoute>
                <FindingsDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/vulnerabilities"
            element={
              <ProtectedRoute>
                <Vulnerabilities />
              </ProtectedRoute>
            }
          />
          <Route
            path="/reports"
            element={
              <ProtectedRoute>
                <Reports />
              </ProtectedRoute>
            }
          />
          <Route
            path="/profile"
            element={
              <ProtectedRoute>
                <Profile />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <Settings />
              </ProtectedRoute>
            }
          />

          {/* Fallback Redirect */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Router>
    </ScanProvider>
  </AuthProvider>
);
};

export default App;
