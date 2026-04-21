import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import {
  Activity, AlertTriangle, CheckCircle2, Clock, Cpu, Database,
  Globe, RefreshCw, Server, Shield, TrendingUp, Zap,
} from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { cn, formatBytes, formatUptime, formatNumber } from '@/lib/utils'
import * as api from '@/api'
import type { SystemStats, LogStats } from '@/types'
import { useServiceHealth } from '@/hooks/useServiceHealth'

const STATUS_COLORS = {
  '2xx': 'hsl(142 71% 45%)',
  '3xx': 'hsl(217 91% 60%)',
  '4xx': 'hsl(48 96% 53%)',
  '5xx': 'hsl(0 72% 51%)',
}


function StatCard({
  title, value, sub, icon: Icon, trend, loading, color = 'primary',
}: {
  title: string
  value: string
  sub?: string
  icon: React.ElementType
  trend?: string
  loading?: boolean
  color?: 'primary' | 'warning' | 'destructive' | 'blue'
}) {
  const colorMap = {
    primary: 'text-primary bg-primary/10 border-primary/30',
    warning: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
    destructive: 'text-destructive bg-destructive/10 border-destructive/30',
    blue: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  }
  return (
    <Card className="border-border bg-card hover:border-primary/30 transition-colors duration-200">
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</p>
            {loading ? (
              <Skeleton className="h-8 w-24 mt-2" />
            ) : (
              <p className="text-2xl font-bold text-foreground mt-1 font-mono tracking-tight">{value}</p>
            )}
            {sub && !loading && (
              <p className="text-xs text-muted-foreground mt-1">{sub}</p>
            )}
            {trend && !loading && (
              <p className="text-xs text-primary mt-1 flex items-center gap-1">
                <TrendingUp className="h-3 w-3" />{trend}
              </p>
            )}
          </div>
          <div className={cn('flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border', colorMap[color])}>
            <Icon className="h-5 w-5" />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

export default function Dashboard() {
  const [sys, setSys] = useState<SystemStats | null>(null)
  const [stats, setStats] = useState<LogStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [reloading, setReloading] = useState(false)
  const [lastRefresh, setLastRefresh] = useState(new Date())
  const { wafOnline, logOnline, dbOnline } = useServiceHealth()

  const load = useCallback(async () => {
    try {
      const [s, lg] = await Promise.all([api.systemStats(), api.getLogStats()])
      setSys(s)
      setStats(lg)
      setLastRefresh(new Date())
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Failed to load stats')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [load])

  async function handleReload() {
    setReloading(true)
    try {
      await api.reload()
      toast.success('Configuration reloaded')
      await load()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Reload failed')
    } finally {
      setReloading(false)
    }
  }

  // Build status pie data
  const pieData = stats
    ? Object.entries(stats.status_counts ?? {}).map(([key, count]) => ({
        name: key,
        value: count,
        color: STATUS_COLORS[key as keyof typeof STATUS_COLORS] ?? '#888',
      }))
    : []

  const hasErrors = stats
    ? ((stats.status_counts?.['4xx'] ?? 0) + (stats.status_counts?.['5xx'] ?? 0)) > 0
    : false

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Last updated: {lastRefresh.toLocaleTimeString()}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={handleReload}
          disabled={reloading}
          className="gap-2 cursor-pointer border-border hover:border-primary/50"
        >
          <RefreshCw className={cn('h-3.5 w-3.5', reloading && 'animate-spin')} />
          Reload Config
        </Button>
      </div>

      {/* System Health Banner */}
      {sys && !loading && (
        <div className={cn(
          'flex items-center gap-3 rounded-lg border px-4 py-3 text-sm',
          hasErrors
            ? 'border-yellow-400/30 bg-yellow-400/5 text-yellow-400'
            : 'border-primary/30 bg-primary/5 text-primary'
        )}>
          {hasErrors
            ? <AlertTriangle className="h-4 w-4 shrink-0" />
            : <CheckCircle2 className="h-4 w-4 shrink-0" />
          }
          <span className="font-medium">
            {hasErrors ? 'Errors detected in recent traffic' : 'All systems operational'}
          </span>
          <span className="ml-auto text-muted-foreground font-mono text-xs">
            {new Date().toLocaleDateString()}
          </span>
        </div>
      )}

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          title="Total Requests"
          value={stats ? formatNumber(stats.total_requests) : '—'}
          icon={Activity}
          loading={loading}
          color="primary"
        />
        <StatCard
          title="Avg Response Time"
          value={stats ? `${stats.avg_response_ms.toFixed(0)}ms` : '—'}
          icon={Clock}
          loading={loading}
          color="blue"
        />
        <StatCard
          title="Active Hosts"
          value={sys ? String(sys.config?.active_hosts ?? 0) : '—'}
          icon={Globe}
          loading={loading}
          color="primary"
        />
        <StatCard
          title="Memory Usage"
          value={sys ? formatBytes(sys.memory.alloc_mb * 1024 * 1024) : '—'}
          icon={Cpu}
          loading={loading}
          color="blue"
        />
      </div>

      {/* System Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          title="Uptime"
          value={sys ? formatUptime(sys.uptime_seconds) : '—'}
          icon={Server}
          loading={loading}
          color="primary"
        />
        <StatCard
          title="Log Queue"
          value={sys?.log_pipeline ? String(sys.log_pipeline.queue_len) : '—'}
          icon={Database}
          loading={loading}
          color={sys?.log_pipeline && sys.log_pipeline.dropped > 0 ? 'warning' : 'primary'}
        />
        <StatCard
          title="Enqueued Logs"
          value={sys?.log_pipeline ? formatNumber(sys.log_pipeline.enqueued) : '—'}
          icon={Zap}
          loading={loading}
          color="primary"
        />
      </div>

      {/* Service Health */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {([
          { name: 'PostgreSQL', online: dbOnline, icon: Database },
          { name: 'muWAF', online: wafOnline, icon: Shield },
          { name: 'diaLOG SIEM', online: logOnline, icon: Activity },
        ] as const).map(svc => (
          <Card key={svc.name} className={cn(
            'border bg-card transition-colors duration-200',
            svc.online ? 'border-primary/20' : 'border-amber-500/20',
          )}>
            <CardContent className="p-4 flex items-center gap-3">
              <div className={cn(
                'flex h-9 w-9 items-center justify-center rounded-lg border shrink-0',
                svc.online
                  ? 'bg-primary/10 border-primary/30 text-primary'
                  : 'bg-amber-500/10 border-amber-500/30 text-amber-400',
              )}>
                <svc.icon className="h-4 w-4" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-muted-foreground">{svc.name}</p>
                <p className={cn('text-sm font-semibold', svc.online ? 'text-primary' : 'text-amber-400')}>
                  {svc.online ? 'Connected' : 'Offline'}
                </p>
              </div>
              <span className={cn(
                'h-2 w-2 rounded-full shrink-0',
                svc.online ? 'bg-primary animate-pulse' : 'bg-amber-500',
              )} />
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Req/min + errors summary */}
        <Card className="lg:col-span-2 border-border bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-foreground">Traffic Summary</CardTitle>
          </CardHeader>
          <CardContent className="pb-4">
            {loading ? (
              <Skeleton className="h-48 w-full" />
            ) : (
              <div className="grid grid-cols-3 gap-4 h-48 content-center">
                <div className="flex flex-col items-center justify-center gap-1">
                  <p className="text-3xl font-bold font-mono text-foreground">{stats?.requests_per_min?.toFixed(1) ?? '0'}</p>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">req / min</p>
                </div>
                <div className="flex flex-col items-center justify-center gap-1">
                  <p className="text-3xl font-bold font-mono text-foreground">{stats ? `${stats.avg_response_ms.toFixed(0)}ms` : '—'}</p>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">avg latency</p>
                </div>
                <div className="flex flex-col items-center justify-center gap-1">
                  <p className={`text-3xl font-bold font-mono ${stats && stats.total_errors > 0 ? 'text-destructive' : 'text-foreground'}`}>
                    {stats ? formatNumber(stats.total_errors) : '—'}
                  </p>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">errors</p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Status Distribution */}
        <Card className="border-border bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-foreground">Status Distribution</CardTitle>
          </CardHeader>
          <CardContent className="pb-4">
            {loading ? (
              <Skeleton className="h-48 w-full" />
            ) : pieData.length > 0 ? (
              <div className="flex flex-col items-center gap-3">
                <ResponsiveContainer width="100%" height={150}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={68}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {pieData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: 'hsl(222 47% 7%)', border: '1px solid hsl(217 33% 17%)', borderRadius: 6, fontSize: 12 }}
                      formatter={(v, name) => [formatNumber(Number(v)), String(name)]}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex flex-wrap justify-center gap-x-4 gap-y-1">
                  {pieData.map(d => (
                    <div key={d.name} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <span className="h-2 w-2 rounded-full shrink-0" style={{ background: d.color }} />
                      {d.name}: {formatNumber(d.value)}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">No data</div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Users & Top Countries — side by side when both have data */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {stats?.top_users?.length ? (
          <Card className="border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-foreground">Top Users</CardTitle>
            </CardHeader>
            <CardContent className="pb-4">
              <div className="space-y-1.5">
                {stats.top_users.slice(0, 8).map((u, i) => (
                  <div key={u.query} className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground w-4 text-right shrink-0">{i + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="relative h-6 rounded overflow-hidden bg-muted/30">
                        <div
                          className="absolute inset-y-0 left-0 bg-primary/20 rounded"
                          style={{ width: `${(u.count / stats.top_users[0].count) * 100}%` }}
                        />
                        <Link
                          to={`/logs?user=${encodeURIComponent(u.query)}`}
                          className="relative px-2 text-xs text-foreground hover:text-primary font-mono leading-6 truncate block"
                          title={`View all logs for ${u.display}`}
                        >
                          {u.display}
                        </Link>
                      </div>
                    </div>
                    <Badge variant="secondary" className="shrink-0 font-mono text-xs">
                      {formatNumber(u.count)}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ) : (
          // No top_users means either the SIEM hasn't enriched any logs
          // with JWT identity yet (setting disabled) or zero traffic.
          // Prefer surfacing the actionable case — admins confuse silent
          // empty panels with "nothing to see here" and miss the feature.
          <Card className="border-dashed border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-foreground">Top Users</CardTitle>
            </CardHeader>
            <CardContent className="pb-4 text-xs text-muted-foreground space-y-2">
              <p>
                JWT identity enrichment is off, so incoming requests are not
                attributed to users. Once enabled, this panel lists the most
                active users and each entry links to that user's full log
                timeline.
              </p>
              <Link
                to="/settings"
                className="inline-flex items-center gap-1 text-primary hover:underline"
              >
                Enable in Settings →
              </Link>
            </CardContent>
          </Card>
        )}

        {stats?.top_countries?.length ? (
          <Card className="border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-foreground">Top Ülkeler</CardTitle>
            </CardHeader>
            <CardContent className="pb-4">
              <div className="space-y-1.5">
                {stats.top_countries.slice(0, 8).map((c, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground w-4 text-right shrink-0">{i + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="relative h-6 rounded overflow-hidden bg-muted/30">
                        <div
                          className="absolute inset-y-0 left-0 bg-primary/20 rounded"
                          style={{ width: `${(c.count / stats.top_countries[0].count) * 100}%` }}
                        />
                        <span className="relative px-2 text-xs text-foreground font-mono leading-6 truncate block">{c.country}</span>
                      </div>
                    </div>
                    <Badge variant="secondary" className="shrink-0 font-mono text-xs">
                      {formatNumber(c.count)}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ) : null}
      </div>

      {/* Top Hosts & Paths */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="border-border bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-foreground">Top Hosts</CardTitle>
          </CardHeader>
          <CardContent className="pb-4">
            {loading ? (
              <Skeleton className="h-40 w-full" />
            ) : stats?.top_hosts?.length ? (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={stats.top_hosts.slice(0, 6)} layout="vertical" margin={{ top: 0, right: 8, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: 'hsl(215 20% 55%)' }} />
                  <YAxis type="category" dataKey="host" width={100} tick={{ fontSize: 10, fill: 'hsl(215 20% 55%)' }} />
                  <Tooltip
                    contentStyle={{ background: 'hsl(222 47% 7%)', border: '1px solid hsl(217 33% 17%)', borderRadius: 6, fontSize: 12 }}
                    formatter={(v) => [formatNumber(Number(v)), 'requests']}
                  />
                  <Bar dataKey="count" fill="hsl(142 71% 45%)" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-40 flex items-center justify-center text-muted-foreground text-sm">No data</div>
            )}
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-foreground">Top Paths</CardTitle>
          </CardHeader>
          <CardContent className="pb-4">
            {loading ? (
              <Skeleton className="h-40 w-full" />
            ) : stats?.top_paths?.length ? (
              <div className="space-y-1.5">
                {stats.top_paths.slice(0, 8).map((p, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground w-4 text-right shrink-0">{i + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="relative h-6 rounded overflow-hidden bg-muted/30">
                        <div
                          className="absolute inset-y-0 left-0 bg-primary/20 rounded"
                          style={{ width: `${(p.count / stats.top_paths[0].count) * 100}%` }}
                        />
                        <span className="relative px-2 text-xs text-foreground font-mono leading-6 truncate block">{p.path}</span>
                      </div>
                    </div>
                    <Badge variant="secondary" className="shrink-0 font-mono text-xs">
                      {formatNumber(p.count)}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-40 flex items-center justify-center text-muted-foreground text-sm">No data</div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
