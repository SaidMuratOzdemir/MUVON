import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import {
  LayoutDashboard, Server, FileText, Settings, Shield,
  LogOut, Menu, X, Activity, ChevronRight, ClipboardList,
  ShieldAlert, Network, ScrollText, Cpu, Route, Rocket,
  Bell, ShieldOff,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { cn } from '@/lib/utils'
import { Toaster } from '@/components/ui/sonner'
import { ServiceBanner } from '@/components/ServiceBanner'
import { useServiceHealth } from '@/hooks/useServiceHealth'
import { useAuth } from '@/context/useAuth'

const mainNav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/hosts', label: 'Hosts', icon: Server },
  { to: '/routes', label: 'Routes', icon: Route },
  { to: '/apps', label: 'Apps', icon: Rocket },
  { to: '/logs', label: 'SIEM / Logs', icon: FileText },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  { to: '/audit', label: 'Audit Log', icon: ClipboardList },
  { to: '/tls', label: 'TLS Certs', icon: Shield },
  { to: '/agents', label: 'Agents', icon: Cpu },
  { to: '/settings', label: 'Settings', icon: Settings },
]

const wafNav = [
  { to: '/waf/rules', label: 'WAF Rules', icon: ShieldAlert },
  { to: '/waf/ips', label: 'IP Management', icon: Network },
  { to: '/waf/events', label: 'WAF Events', icon: ScrollText },
  { to: '/waf/exclusions', label: 'Exclusions', icon: ShieldOff },
]

export default function Layout() {
  const navigate = useNavigate()
  const auth = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const { wafOnline, logOnline } = useServiceHealth()

  async function logout() {
    await auth.logout()
    navigate('/login')
  }

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={cn(
        'fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-border bg-card transition-transform duration-300 lg:static lg:translate-x-0',
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      )}>
        {/* Logo */}
        <div className="flex h-14 items-center gap-3 px-4 border-b border-border">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10 border border-primary/30">
            <Activity className="h-4 w-4 text-primary" />
          </div>
          <div>
            <span className="font-semibold text-foreground tracking-tight">MUVON</span>
            <p className="text-xs text-muted-foreground leading-none mt-0.5">Reverse Proxy + SIEM</p>
          </div>
          <button
            className="ml-auto lg:hidden text-muted-foreground hover:text-foreground cursor-pointer"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-3 px-2">
          <ul className="space-y-0.5">
            {mainNav.map(({ to, label, icon: Icon, end }) => (
              <li key={to}>
                <NavLink
                  to={to}
                  end={end}
                  onClick={() => setSidebarOpen(false)}
                  className={({ isActive }) => cn(
                    'group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-all duration-150 cursor-pointer',
                    isActive
                      ? 'bg-primary/10 text-primary glow-box'
                      : 'text-muted-foreground hover:bg-accent hover:text-foreground'
                  )}
                >
                  {({ isActive }) => (
                    <>
                      <Icon className="h-4 w-4 shrink-0" />
                      <span className="flex-1">{label}</span>
                      {isActive && <ChevronRight className="h-3 w-3 opacity-60" />}
                    </>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>

          <Separator className="my-3" />

          <p className="px-2 pb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
            <ShieldAlert className="h-3 w-3" />
            Web Application Firewall
            {!wafOnline && (
              <span className="ml-auto h-1.5 w-1.5 rounded-full bg-amber-400" title="muWAF offline" />
            )}
          </p>
          <ul className="space-y-0.5">
            {wafNav.map(({ to, label, icon: Icon }) => (
              <li key={to}>
                <NavLink
                  to={to}
                  onClick={() => setSidebarOpen(false)}
                  className={({ isActive }) => cn(
                    'group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-all duration-150 cursor-pointer',
                    isActive
                      ? 'bg-primary/10 text-primary glow-box'
                      : 'text-muted-foreground hover:bg-accent hover:text-foreground'
                  )}
                >
                  {({ isActive }) => (
                    <>
                      <Icon className="h-4 w-4 shrink-0" />
                      <span className="flex-1">{label}</span>
                      {isActive && <ChevronRight className="h-3 w-3 opacity-60" />}
                    </>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        <Separator />

        {/* Footer */}
        <div className="p-3">
          <div className="flex items-center gap-2 rounded-md px-2 py-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/20 text-primary text-xs font-bold shrink-0">
              A
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-foreground truncate">Admin</p>
              <div className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                <p className="text-xs text-muted-foreground">Online</p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 text-muted-foreground hover:text-destructive hover:bg-destructive/10 cursor-pointer"
              onClick={logout}
              title="Logout"
            >
              <LogOut className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Topbar (mobile) */}
        <header className="flex h-14 items-center gap-4 border-b border-border px-4 lg:hidden">
          <button
            className="text-muted-foreground hover:text-foreground cursor-pointer"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="h-5 w-5" />
          </button>
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            <span className="font-semibold text-sm">MUVON</span>
          </div>
        </header>

        <ServiceBanner wafOnline={wafOnline} logOnline={logOnline} />
        <main className="flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>

      <Toaster richColors position="top-right" />
    </div>
  )
}
