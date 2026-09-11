import { lazy, Suspense, useEffect } from 'react';
import { HashRouter, Navigate, Route, Routes } from 'react-router-dom';
import { TelemetryService } from './api/TelemetryService';
import { AppLayout } from './AppLayout';

const Dashboard = lazy(() => import('./pages/Dashboard').then((module) => ({ default: module.Dashboard })));
const Health = lazy(() => import('./pages/Health').then((module) => ({ default: module.Health })));
const Dns = lazy(() => import('./pages/Dns').then((module) => ({ default: module.Dns })));
const Logs = lazy(() => import('./pages/Logs').then((module) => ({ default: module.Logs })));
const Connections = lazy(() => import('./pages/Connections').then((module) => ({ default: module.Connections })));
const Capabilities = lazy(() => import('./pages/Capabilities').then((module) => ({ default: module.Capabilities })));
const Operations = lazy(() => import('./pages/Operations').then((module) => ({ default: module.Operations })));
const Deployment = lazy(() => import('./pages/Deployment').then((module) => ({ default: module.Deployment })));
const Profiles = lazy(() => import('./pages/Profiles').then((module) => ({ default: module.Profiles })));
const Rules = lazy(() => import('./pages/Rules').then((module) => ({ default: module.Rules })));
const Settings = lazy(() => import('./pages/Settings').then((module) => ({ default: module.Settings })));

function RouteFallback() {
  return (
    <div className="card" role="status" aria-live="polite">
      <p className="m-0 text-sm text-text-secondary">Loading view…</p>
    </div>
  );
}

function App() {
  useEffect(() => {
    void TelemetryService.connect();
    return () => {
      TelemetryService.disconnect();
    };
  }, []);

  return (
    <HashRouter>
      <Suspense fallback={<RouteFallback />}>
        <Routes>
          <Route path="/" element={<AppLayout />}>
            <Route index element={<Dashboard />} />
            {/* The former 3D Cockpit contained only fabricated topology and is
                intentionally not a production observation surface. Preserve the
                old deep link by taking operators to measured connection evidence. */}
            <Route path="cockpit" element={<Navigate to="/connections" replace />} />
            <Route path="health" element={<Health />} />
            <Route path="rules" element={<Rules />} />
            <Route path="dns" element={<Dns />} />
            <Route path="logs" element={<Logs />} />
            <Route path="connections" element={<Connections />} />
            <Route path="capabilities" element={<Capabilities />} />
            <Route path="operations" element={<Operations />} />
            <Route path="deployment" element={<Deployment />} />
            <Route path="profiles" element={<Profiles />} />
            <Route path="settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </Suspense>
    </HashRouter>
  );
}

export default App;
