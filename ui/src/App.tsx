import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Hosts from './pages/Hosts'
import Logs from './pages/Logs'
import Settings from './pages/Settings'
import TLSCerts from './pages/TLSCerts'
import AuditLog from './pages/AuditLog'
import Agents from './pages/Agents'
import RoutesPage from './pages/Routes'
import Apps from './pages/Apps'
import ScheduledJobs from './pages/ScheduledJobs'
import Alerts from './pages/Alerts'
import ContainerLogs from './pages/ContainerLogs'
import ClientEvents from './pages/ClientEvents'
import Security from './pages/Security'
import { AuthProvider } from './context/AuthContext'
import { useAuth } from './context/useAuth'

function LoadingScreen() {
  return (
    <div className="flex h-screen items-center justify-center bg-background">
      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
    </div>
  )
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth()
  if (loading) return <LoadingScreen />
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

function LoginGate() {
  const { isAuthenticated, loading } = useAuth()
  if (loading) return <LoadingScreen />
  if (isAuthenticated) return <Navigate to="/" replace />
  return <Login />
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginGate />} />
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
            <Route path="alerts" element={<Alerts />} />
            <Route path="agents" element={<Agents />} />
            <Route path="apps" element={<Apps hostFilter="central" />} />
            <Route path="apps/edge" element={<Apps hostFilter="edge" />} />
            <Route path="jobs" element={<ScheduledJobs />} />
            <Route path="container-logs" element={<ContainerLogs />} />
            <Route path="client-events" element={<ClientEvents />} />
            <Route path="security" element={<Security />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
