import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { AppShell } from './components/layout/AppShell';
import { LandingPage } from './pages/LandingPage';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { DashboardPage } from './pages/DashboardPage';
import { Projects } from './pages/Projects';
import { ProjectDetails } from './pages/ProjectDetails';
import { NewScanPage } from './pages/NewScanPage';
import { ScanResultsPage } from './pages/ScanResultsPage';
import { RemediationPage } from './pages/RemediationPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { ReportsPage } from './pages/ReportsPage';
import { DocsPage } from './pages/DocsPage';
import { SettingsPage } from './pages/SettingsPage';
import { ModelDatasetsPage } from './pages/ModelDatasetsPage';
import { VivaDefensePage } from './pages/VivaDefensePage';
import { AstVisualizerPage } from './pages/AstVisualizerPage';

export function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            {/* Public Welcome and Authentication */}
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />

            {/* Core Tool Shell */}
            <Route element={<AppShell />}>
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/projects" element={<Projects />} />
              <Route path="/projects/:projectId" element={<ProjectDetails />} />
              <Route path="/scan" element={<NewScanPage />} />
              <Route path="/results/:scanId" element={<ScanResultsPage />} />
              <Route path="/results" element={<Navigate to="/dashboard" replace />} />
              <Route path="/remediation/:scanId" element={<RemediationPage />} />
              <Route path="/remediation" element={<Navigate to="/dashboard" replace />} />
              <Route path="/ast-visualizer" element={<AstVisualizerPage />} />
              <Route path="/ast" element={<Navigate to="/ast-visualizer" replace />} />
              <Route path="/defense" element={<VivaDefensePage />} />
              <Route path="/viva" element={<Navigate to="/defense" replace />} />
              <Route path="/model-datasets" element={<ModelDatasetsPage />} />
              <Route path="/history" element={<ScanHistoryPage />} />
              <Route path="/reports/:scanId" element={<ReportsPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/docs" element={<DocsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>

            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ErrorBoundary>
  );
}

export default App;
