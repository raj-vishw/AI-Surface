import { Suspense, lazy } from "react";
import { Routes, Route } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { PageLoading } from "@/components/common/PageLoading";

const Landing = lazy(() => import("@/pages/Landing"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const AssetsList = lazy(() => import("@/pages/AssetsList"));
const AssetDetail = lazy(() => import("@/pages/AssetDetail"));
const Technologies = lazy(() => import("@/pages/Technologies"));
const Reconnaissance = lazy(() => import("@/pages/Reconnaissance"));
const FindingsList = lazy(() => import("@/pages/FindingsList"));
const FindingDetail = lazy(() => import("@/pages/FindingDetail"));
const Risk = lazy(() => import("@/pages/Risk"));
const Alerts = lazy(() => import("@/pages/Alerts"));
const Detections = lazy(() => import("@/pages/Detections"));
const InvestigationsList = lazy(() => import("@/pages/InvestigationsList"));
const InvestigationDetail = lazy(() => import("@/pages/InvestigationDetail"));
const AttackChains = lazy(() => import("@/pages/AttackChains"));
const AttackChainDetail = lazy(() => import("@/pages/AttackChainDetail"));
const IncidentsList = lazy(() => import("@/pages/IncidentsList"));
const Timeline = lazy(() => import("@/pages/Timeline"));
const Intelligence = lazy(() => import("@/pages/Intelligence"));
const Analytics = lazy(() => import("@/pages/Analytics"));
const AIInvestigation = lazy(() => import("@/pages/AIInvestigation"));
const Reports = lazy(() => import("@/pages/Reports"));
const Evidence = lazy(() => import("@/pages/Evidence"));
const ScanHistory = lazy(() => import("@/pages/ScanHistory"));
const AuditLog = lazy(() => import("@/pages/AuditLog"));
const Settings = lazy(() => import("@/pages/Settings"));
const NotFound = lazy(() => import("@/pages/NotFound"));

function App() {
  return (
    <Suspense fallback={<PageLoading />}>
      <Routes>
        <Route path="/" element={<Landing />} />

        <Route element={<AppShell />}>
          <Route path="/dashboard" element={<Dashboard />} />

          <Route path="/assets" element={<AssetsList />} />
          <Route path="/assets/:id" element={<AssetDetail />} />
          <Route path="/technologies" element={<Technologies />} />
          <Route path="/reconnaissance" element={<Reconnaissance />} />

          <Route path="/findings" element={<FindingsList />} />
          <Route path="/findings/:id" element={<FindingDetail />} />
          <Route path="/risk" element={<Risk />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/detections" element={<Detections />} />

          <Route path="/investigations" element={<InvestigationsList />} />
          <Route path="/investigations/:id" element={<InvestigationDetail />} />
          <Route path="/attack-chains" element={<AttackChains />} />
          <Route path="/attack-chains/:id" element={<AttackChainDetail />} />
          <Route path="/incidents" element={<IncidentsList />} />
          <Route path="/timeline" element={<Timeline />} />

          <Route path="/intelligence" element={<Intelligence />} />
          <Route path="/analytics" element={<Analytics />} />

          <Route path="/ai" element={<AIInvestigation />} />
          <Route path="/ai/:sessionId" element={<AIInvestigation />} />

          <Route path="/reports" element={<Reports />} />
          <Route path="/evidence" element={<Evidence />} />

          <Route path="/scans" element={<ScanHistory />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/settings" element={<Settings />} />
        </Route>

        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
  );
}

export default App;
