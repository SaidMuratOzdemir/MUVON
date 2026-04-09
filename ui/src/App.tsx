import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Hosts from './pages/Hosts'
import Logs from './pages/Logs'
import Settings from './pages/Settings'
import TLSCerts from './pages/TLSCerts'
import AuditLog from './pages/AuditLog'
import WafRules from './pages/WafRules'
import WafIPs from './pages/WafIPs'
import WafEvents from './pages/WafEvents'
import Agents from './pages/Agents'
import RoutesPage from './pages/Routes'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('dialog_token')
  if (!token) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="hosts" element={<Hosts />} />
          <Route path="routes" element={<RoutesPage />} />
          <Route path="logs" element={<Logs />} />
          <Route path="settings" element={<Settings />} />
          <Route path="tls" element={<TLSCerts />} />
          <Route path="audit" element={<AuditLog />} />
          <Route path="waf/rules" element={<WafRules />} />
          <Route path="waf/ips" element={<WafIPs />} />
          <Route path="waf/events" element={<WafEvents />} />
          <Route path="agents" element={<Agents />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
