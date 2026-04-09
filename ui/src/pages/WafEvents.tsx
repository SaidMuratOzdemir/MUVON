import { useState, useEffect, useCallback } from 'react'
import {
  ScrollText, Search, RefreshCw, ChevronLeft, ChevronRight,
  ShieldBan, Eye, Gauge,
} from 'lucide-react'
import { toast } from 'sonner'
import {
  BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { cn, formatNumber, relativeTime } from '@/lib/utils'
import { EmptyState } from '@/components/EmptyState'
import * as api from '@/api'
import type { WafEvent, WafStats } from '@/types'

const PAGE_SIZE = 50
const ACTION_COLORS: Record<string, string> = {
  log: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  rate_limit: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  block: 'bg-red-500/10 text-red-400 border-red-500/20',
  temp_ban: 'bg-red-600/10 text-red-500 border-red-600/20',
  ban: 'bg-red-700/10 text-red-600 border-red-700/20',
}

function StatCard({ title, value, icon: Icon, color }: {
  title: string; value: string; icon: React.ElementType; color: string
}) {
  return (
    <Card className="border-border bg-card">
      <CardContent className="p-4 flex items-center gap-3">
        <div className={cn('flex h-10 w-10 items-center justify-center rounded-lg border shrink-0', color)}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <p className="text-xs text-muted-foreground font-medium">{title}</p>
          <p className="text-xl font-bold font-mono text-foreground">{value}</p>
        </div>
      </CardContent>
    </Card>
  )
}

export default function WafEvents() {
  const [events, setEvents] = useState<WafEvent[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [serviceDown, setServiceDown] = useState(false)
  const [stats, setStats] = useState<WafStats | null>(null)
  const [statsLoading, setStatsLoading] = useState(true)
  const [ipFilter, setIpFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [hostFilter, setHostFilter] = useState('')

  const loadEvents = useCallback(async () => {
    setLoading(true)
    try {
      setServiceDown(false)
      const res = await api.searchWafEvents({
        client_ip: ipFilter || undefined,
        action: actionFilter || undefined,
        host: hostFilter || undefined,
        limit: PAGE_SIZE,
        offset,
      })
      setEvents(res.events ?? [])
      setTotal(res.total)
    } catch (err) {
      if (api.isServiceUnavailable(err)) {
        setServiceDown(true)
      } else {
        toast.error(err instanceof api.ApiError ? err.message : 'Failed to load events')
      }
    } finally {
      setLoading(false)
    }
  }, [ipFilter, actionFilter, hostFilter, offset])

  const loadStats = useCallback(async () => {
    try {
      const s = await api.getWafStats()
      setStats(s)
    } catch {
      // stats are optional
    } finally {
      setStatsLoading(false)
    }
  }, [])

  useEffect(() => { loadEvents() }, [loadEvents])
  useEffect(() => { loadStats() }, [loadStats])

  const totalPages = Math.ceil(total / PAGE_SIZE)
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1

  if (serviceDown) {
    return (
      <div className="p-6">
        <h1 className="text-xl font-bold text-foreground tracking-tight mb-6">WAF Events</h1>
        <EmptyState
          variant="service-offline"
          title="muWAF Servisi Cevrimdisi"
          description="WAF event goruntulemesi icin muWAF servisinin calisiyor olmasi gerekiyor."
        />
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">WAF Events</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Threat detection & response log</p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="gap-2 cursor-pointer border-border"
          onClick={() => { loadEvents(); loadStats() }}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          title="Total Events"
          value={stats ? formatNumber(stats.total_events) : '—'}
          icon={ScrollText}
          color="text-blue-400 bg-blue-400/10 border-blue-400/30"
        />
        <StatCard
          title="Blocked Requests"
          value={stats ? formatNumber(stats.total_blocked) : '—'}
          icon={ShieldBan}
          color="text-red-400 bg-red-400/10 border-red-400/30"
        />
        <StatCard
          title="Unique IPs"
          value={stats ? formatNumber(stats.unique_ips) : '—'}
          icon={Eye}
          color="text-amber-400 bg-amber-400/10 border-amber-400/30"
        />
        <StatCard
          title="Block Rate"
          value={stats && stats.total_events > 0
            ? `${((stats.total_blocked / stats.total_events) * 100).toFixed(1)}%`
            : '—'}
          icon={Gauge}
          color="text-purple-400 bg-purple-400/10 border-purple-400/30"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Categories */}
        <Card className="border-border bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-foreground">Top Attack Categories</CardTitle>
            <CardDescription className="text-xs">By detection count</CardDescription>
          </CardHeader>
          <CardContent className="pb-4">
            {statsLoading ? (
              <Skeleton className="h-44 w-full" />
            ) : stats?.top_categories?.length ? (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={stats.top_categories.slice(0, 6)} layout="vertical" margin={{ top: 0, right: 8, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: 'hsl(215 20% 55%)' }} />
                  <YAxis type="category" dataKey="category" width={100} tick={{ fontSize: 10, fill: 'hsl(215 20% 55%)' }} />
                  <Tooltip
                    contentStyle={{ background: 'hsl(222 47% 7%)', border: '1px solid hsl(217 33% 17%)', borderRadius: 6, fontSize: 12 }}
                    formatter={(v) => [formatNumber(Number(v)), 'events']}
                  />
                  <Bar dataKey="count" fill="hsl(0 72% 51%)" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-44 flex items-center justify-center text-muted-foreground text-sm">No data</div>
            )}
          </CardContent>
        </Card>

        {/* Top IPs */}
        <Card className="border-border bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-foreground">Top Threat IPs</CardTitle>
            <CardDescription className="text-xs">Most frequent offenders</CardDescription>
          </CardHeader>
          <CardContent className="pb-4">
            {statsLoading ? (
              <Skeleton className="h-44 w-full" />
            ) : stats?.top_ips?.length ? (
              <div className="space-y-1.5">
                {stats.top_ips.slice(0, 8).map((item, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground w-4 text-right shrink-0">{i + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="relative h-6 rounded overflow-hidden bg-muted/30">
                        <div
                          className="absolute inset-y-0 left-0 bg-red-500/20 rounded"
                          style={{ width: `${(item.count / stats.top_ips[0].count) * 100}%` }}
                        />
                        <span className="relative px-2 text-xs text-foreground font-mono leading-6 truncate block">
                          {item.ip}
                        </span>
                      </div>
                    </div>
                    <Badge variant="secondary" className="shrink-0 font-mono text-xs">
                      {formatNumber(item.count)}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-44 flex items-center justify-center text-muted-foreground text-sm">No data</div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Event Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 max-w-xs min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Filter by IP..."
            className="pl-9 bg-card border-border h-9 font-mono"
            value={ipFilter}
            onChange={e => { setIpFilter(e.target.value); setOffset(0) }}
          />
        </div>
        <Input
          placeholder="Filter by host..."
          className="bg-card border-border h-9 max-w-[200px]"
          value={hostFilter}
          onChange={e => { setHostFilter(e.target.value); setOffset(0) }}
        />
        <Select value={actionFilter || '__all'} onValueChange={v => { setActionFilter(v === '__all' ? '' : v); setOffset(0) }}>
          <SelectTrigger className="w-40 h-9 bg-card border-border cursor-pointer">
            <SelectValue placeholder="All Actions" />
          </SelectTrigger>
          <SelectContent className="bg-card border-border">
            <SelectItem value="__all" className="cursor-pointer">All Actions</SelectItem>
            {['log', 'rate_limit', 'block', 'temp_ban', 'ban'].map(a => (
              <SelectItem key={a} value={a} className="cursor-pointer text-xs">{a}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="ml-auto text-xs text-muted-foreground">
          {total.toLocaleString()} events
        </div>
      </div>

      {/* Events Table */}
      {loading && events.length === 0 ? (
        <div className="space-y-1">
          {Array.from({ length: 10 }, (_, i) => (
            <Skeleton key={i} className="h-10 w-full rounded-sm" />
          ))}
        </div>
      ) : events.length === 0 ? (
        <EmptyState
          title="No WAF events found"
          description={ipFilter || actionFilter || hostFilter ? 'Try adjusting your filters' : 'Events will appear when the WAF detects suspicious activity'}
        />
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="bg-card hover:bg-card border-border">
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-36">Time</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider">Client IP</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-16">Method</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider">Host / Path</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-20 text-center">Score</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-20 text-center">IP Score</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-24">Action</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider">Matched Rules</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map(ev => (
                <TableRow key={ev.id} className="border-border hover:bg-muted/10 transition-colors">
                  <TableCell className="text-xs font-mono text-muted-foreground" title={new Date(ev.created_at).toLocaleString()}>
                    {relativeTime(ev.created_at)}
                  </TableCell>
                  <TableCell className="font-mono text-sm text-foreground">{ev.client_ip}</TableCell>
                  <TableCell className="text-xs font-mono font-semibold text-foreground">{ev.method}</TableCell>
                  <TableCell className="text-xs font-mono text-muted-foreground max-w-xs truncate" title={`${ev.host}${ev.path}`}>
                    <span className="text-foreground">{ev.host}</span>
                    <span className="text-muted-foreground">{ev.path}</span>
                  </TableCell>
                  <TableCell className="text-center">
                    <span className={cn(
                      'font-mono text-xs font-bold',
                      ev.request_score >= 50 ? 'text-red-400' : ev.request_score >= 20 ? 'text-amber-400' : 'text-blue-400',
                    )}>
                      {ev.request_score}
                    </span>
                  </TableCell>
                  <TableCell className="text-center">
                    <span className={cn(
                      'font-mono text-xs font-bold',
                      ev.ip_score >= 100 ? 'text-red-400' : ev.ip_score >= 50 ? 'text-amber-400' : 'text-muted-foreground',
                    )}>
                      {ev.ip_score.toFixed(1)}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className={cn(
                      'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-mono font-medium',
                      ACTION_COLORS[ev.action] ?? 'bg-muted text-muted-foreground border-border',
                    )}>
                      {ev.action}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground max-w-xs truncate font-mono" title={ev.matched_rules}>
                    {ev.matched_rules || '—'}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            Page {currentPage} of {totalPages} &bull; {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="outline" size="icon" className="h-8 w-8 cursor-pointer border-border"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="outline" size="icon" className="h-8 w-8 cursor-pointer border-border"
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
