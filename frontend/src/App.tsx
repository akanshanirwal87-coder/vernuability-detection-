import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { LandingPage } from './pages/LandingPage';
import { DashboardPage } from './pages/DashboardPage';
import { NewScanPage } from './pages/NewScanPage';
import { ScanResultsPage } from './pages/ScanResultsPage';
import { RemediationPage } from './pages/RemediationPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { ReportsPage } from './pages/ReportsPage';
import { DocsPage } from './pages/DocsPage';
import { SettingsPage } from './pages/SettingsPage';
import { ModelDatasetsPage } from './pages/ModelDatasetsPage';

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Landing Welcome Page */}
        <Route path="/" element={<LandingPage />} />

        {/* Core Authenticated / Tool Shell */}
        <Route element={<AppShell />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/scan" element={<NewScanPage />} />
          <Route path="/results/:scanId" element={<ScanResultsPage />} />
          <Route path="/results" element={<Navigate to="/results/scan-demo-01" replace />} />
          <Route path="/remediation/:scanId" element={<RemediationPage />} />
          <Route path="/remediation" element={<Navigate to="/remediation/scan-demo-01" replace />} />
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
  );
}

export default App;
