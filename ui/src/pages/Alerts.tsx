import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle, Search, RefreshCw, ChevronLeft, ChevronRight,
  Check, Bell, BellOff, AlertCircle, Info, Radio, Eye, User,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent } from '@/components/ui/card'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle,
} from '@/components/ui/sheet'
import { cn, formatNumber, relativeTime } from '@/lib/utils'
import { EmptyState } from '@/components/EmptyState'
import * as api from '@/api'
import type { Alert, AlertStats } from '@/types'

const PAGE_SIZE = 50

const SEVERITY_COLORS: Record<string, string> = {
  info: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  warning: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  critical: 'bg-red-500/10 text-red-400 border-red-500/20',
}

const RULE_LABELS: Record<string, string> = {
  path_scan: 'Path scan',
  auth_brute_force: 'Auth brute force',
  waf_repeat_offender: 'WAF repeat offender',
  error_spike: '5xx spike',
  traffic_anomaly: 'Traffic anomaly',
  sensitive_access: 'Sensitive access',
  data_export_burst: 'Export burst',
  test: 'Test alert',
}

function SeverityBadge({ severity }: { severity: string }) {
  const Icon = severity === 'critical' ? AlertCircle : severity === 'warning' ? AlertTriangle : Info
  return (
    <Badge variant="outline" className={cn('gap-1', SEVERITY_COLORS[severity] ?? '')}>
      <Icon className="h-3 w-3" />
      {severity}
    </Badge>
  )
}

function StatCard({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <Card className="border-border bg-card">
      <CardContent className="p-4">
        <p className="text-xs text-muted-foreground font-medium">{label}</p>
        <p className={cn('text-2xl font-bold font-mono mt-1', tone ?? 'text-foreground')}>{value}</p>
      </CardContent>
    </Card>
  )
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState<AlertStats | null>(null)

  // filters
  const [search, setSearch] = useState('')
  const [ruleFilter, setRuleFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [showAcked, setShowAcked] = useState(false)

  const [detail, setDetail] = useState<Alert | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: api.AlertSearchParams = {
        limit: PAGE_SIZE,
        offset,
      }
      if (ruleFilter !== 'all') params.rule = ruleFilter
      if (severityFilter !== 'all') params.severity = severityFilter
      if (!showAcked) params.acknowledged = false
      const searchTrim = search.trim()
      if (searchTrim) {
        // Treat search as source_ip first; if it contains a dot and a letter
        // the backend also accepts host filter. Cheap heuristic to keep the
        // filter UI to one input.
        if (/^\d+\.\d+/.test(searchTrim)) {
          params.source_ip = searchTrim
        } else {
          params.host = searchTrim
        }
      }
      const res = await api.searchAlerts(params)
      setAlerts(res.data ?? [])
      setTotal(res.total ?? 0)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Failed to load alerts')
    } finally {
      setLoading(false)
    }
  }, [offset, ruleFilter, severityFilter, showAcked, search])

  const loadStats = useCallback(async () => {
    try {
      setStats(await api.getAlertStats())
    } catch {
      /* stats are non-critical */
    }
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => { loadStats() }, [loadStats, alerts.length])

  // Debounce rapid filter changes so typing in the search box doesn't fire
  // a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => {
      setOffset(0)
      load()
    }, 250)
    return () => clearTimeout(t)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, ruleFilter, severityFilter, showAcked])

  async function handleAck(id: string) {
    try {
      const updated = await api.acknowledgeAlert(id)
      setAlerts(a => a.map(x => x.id === id ? updated : x))
      if (detail?.id === id) setDetail(updated)
      loadStats()
      toast.success('Alert acknowledged')
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Failed to acknowledge')
    }
  }

  const canPrev = offset > 0
  const canNext = offset + PAGE_SIZE < total

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground tracking-tight flex items-center gap-2">
            <Bell className="h-6 w-6 text-primary" />
            Alerts
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Correlation engine output. Grouped by fingerprint — occurrences show repeats inside the cooldown window.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}>
          <RefreshCw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard
            label="Open (unacked)"
            value={formatNumber(stats.total_open)}
            tone={stats.total_open > 0 ? 'text-red-400' : 'text-emerald-400'}
          />
          <StatCard label="All-time" value={formatNumber(stats.total_all)} />
          <StatCard label="Critical open" value={formatNumber(stats.by_severity?.critical ?? 0)} tone="text-red-400" />
          <StatCard label="Warning open" value={formatNumber(stats.by_severity?.warning ?? 0)} tone="text-yellow-400" />
        </div>
      )}

      {/* Filters */}
      <Card className="border-border bg-card">
        <CardContent className="p-4 flex flex-col lg:flex-row gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
            <Input
              placeholder="Filter by source IP or host…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-9 bg-background border-border"
            />
          </div>
          <Select value={ruleFilter} onValueChange={setRuleFilter}>
            <SelectTrigger className="w-[200px] bg-background border-border cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All rules</SelectItem>
              {Object.entries(RULE_LABELS).map(([k, v]) => (
                <SelectItem key={k} value={k}>{v}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-[160px] bg-background border-border cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All severities</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="warning">Warning</SelectItem>
              <SelectItem value="info">Info</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant={showAcked ? 'default' : 'outline'}
            size="sm"
            onClick={() => setShowAcked(v => !v)}
            className="cursor-pointer"
          >
            {showAcked ? <BellOff className="h-4 w-4 mr-2" /> : <Bell className="h-4 w-4 mr-2" />}
            {showAcked ? 'Including acknowledged' : 'Open only'}
          </Button>
        </CardContent>
      </Card>

      {/* Table */}
      <Card className="border-border bg-card">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-border">
                  <TableHead className="text-xs w-[140px]">When</TableHead>
                  <TableHead className="text-xs w-[110px]">Severity</TableHead>
                  <TableHead className="text-xs w-[180px]">Rule</TableHead>
                  <TableHead className="text-xs">Title</TableHead>
                  <TableHead className="text-xs w-[140px]">Source IP</TableHead>
                  <TableHead className="text-xs w-[180px]">Host</TableHead>
                  <TableHead className="text-xs w-[80px] text-right">Count</TableHead>
                  <TableHead className="text-xs w-[120px] text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && alerts.length === 0 && Array.from({ length: 6 }).map((_, i) => (
                  <TableRow key={i} className="border-border">
                    {Array.from({ length: 8 }).map((__, j) => (
                      <TableCell key={j}><Skeleton className="h-4 w-full" /></TableCell>
                    ))}
                  </TableRow>
                ))}
                {!loading && alerts.length === 0 && (
                  <TableRow className="border-border"><TableCell colSpan={8}>
                    <EmptyState
                      icon={Radio}
                      title="No alerts match"
                      description="Try widening the filters, or toggle 'Including acknowledged' to show older alerts."
                    />
                  </TableCell></TableRow>
                )}
                {alerts.map(a => (
                  <TableRow key={a.id} className={cn('border-border', a.acknowledged && 'opacity-60')}>
                    <TableCell className="text-xs text-muted-foreground font-mono">
                      {relativeTime(a.last_seen_at)}
                    </TableCell>
                    <TableCell><SeverityBadge severity={a.severity} /></TableCell>
                    <TableCell className="text-sm font-medium">
                      {RULE_LABELS[a.rule] ?? a.rule}
                    </TableCell>
                    <TableCell className="text-sm">{a.title}</TableCell>
                    <TableCell className="text-xs font-mono text-muted-foreground">{a.source_ip || '—'}</TableCell>
                    <TableCell className="text-xs font-mono text-muted-foreground">{a.host || '—'}</TableCell>
                    <TableCell className="text-right text-sm font-mono">
                      {a.occurrences > 1 ? (
                        <Badge variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/20">
                          ×{a.occurrences}
                        </Badge>
                      ) : '1'}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer" onClick={() => setDetail(a)}>
                          <Eye className="h-3.5 w-3.5" />
                        </Button>
                        {!a.acknowledged && (
                          <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer hover:text-emerald-400" onClick={() => handleAck(a.id)}>
                            <Check className="h-3.5 w-3.5" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          {total > PAGE_SIZE && (
            <div className="flex items-center justify-between p-4 border-t border-border text-xs text-muted-foreground">
              <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {formatNumber(total)}</span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setOffset(o => Math.max(0, o - PAGE_SIZE))} disabled={!canPrev || loading}>
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="sm" onClick={() => setOffset(o => o + PAGE_SIZE)} disabled={!canNext || loading}>
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Detail sheet */}
      <AlertDetailSheet alert={detail} onClose={() => setDetail(null)} onAck={handleAck} />
    </div>
  )
}

function AlertDetailSheet({
  alert, onClose, onAck,
}: {
  alert: Alert | null
  onClose: () => void
  onAck: (id: string) => void
}) {
  if (!alert) {
    return <Sheet open={false} onOpenChange={v => !v && onClose()}><SheetContent /></Sheet>
  }
  const detailJson = alert.detail ? JSON.stringify(alert.detail, null, 2) : ''
  return (
    <Sheet open={true} onOpenChange={v => !v && onClose()}>
      <SheetContent className="bg-card border-border w-full sm:max-w-xl overflow-y-auto">
        <SheetHeader className="space-y-2">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <Badge variant="outline" className="font-mono text-xs">{RULE_LABELS[alert.rule] ?? alert.rule}</Badge>
          </div>
          <SheetTitle className="text-lg">{alert.title}</SheetTitle>
          <SheetDescription>
            First seen {relativeTime(alert.timestamp)} · last seen {relativeTime(alert.last_seen_at)}
            {alert.occurrences > 1 && ` · ${alert.occurrences} occurrences`}
          </SheetDescription>
        </SheetHeader>

        <div className="space-y-4 p-4">
          {/* Actor — JWT identity if the enricher captured one, otherwise the
               raw fingerprint (e.g. "user:123e4567"). Clickable → /logs filtered
               by the same user so the admin can read the user's whole session. */}
          <AlertActorRow alert={alert} />
          <DetailRow label="Source IP" value={alert.source_ip || '—'} mono />
          <DetailRow label="Host" value={alert.host || '—'} mono />
          <DetailRow label="Fingerprint" value={alert.fingerprint} mono />
          <DetailRow
            label="Notified"
            value={alert.notified ? `Yes (${relativeTime(alert.notified_at ?? '')})` : 'No'}
          />
          {alert.acknowledged ? (
            <DetailRow
              label="Acknowledged"
              value={`by ${alert.acknowledged_by || 'unknown'} · ${relativeTime(alert.acknowledged_at ?? '')}`}
            />
          ) : (
            <Button className="w-full cursor-pointer" onClick={() => onAck(alert.id)}>
              <Check className="h-4 w-4 mr-2" />
              Acknowledge
            </Button>
          )}

          {detailJson && detailJson !== '{}' && (
            <div>
              <p className="text-xs text-muted-foreground font-medium mb-2">Detail</p>
              <pre className="text-xs bg-muted/40 border border-border rounded-md p-3 overflow-x-auto font-mono">
                {detailJson}
              </pre>
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}

// resolveActor pulls the best user label out of an alert's detail map.
// attachIdentity() writes actor_email / actor_name / actor_sub in the
// backend; fingerprint is the fallback for pre-enrichment rows.
function resolveActor(alert: Alert): { display: string; query: string | null } | null {
  const d = (alert.detail ?? {}) as Record<string, unknown>
  const pick = (key: string) => {
    const v = d[key]
    return typeof v === 'string' && v !== '' ? v : null
  }
  const email = pick('actor_email')
  if (email) return { display: email, query: email }
  const name = pick('actor_name')
  if (name) return { display: name, query: name }
  const sub = pick('actor_sub')
  if (sub) return { display: sub, query: sub }

  // Parse fingerprints like "data_export_burst:user:123e4567" — the
  // correlation engine writes these for user-keyed rules when identity
  // enrichment was missing.
  const match = alert.fingerprint.match(/^[^:]+:user:(.+)$/)
  if (match) return { display: match[1], query: match[1] }
  return null
}

function AlertActorRow({ alert }: { alert: Alert }) {
  const actor = resolveActor(alert)
  const verified = (alert.detail as Record<string, unknown> | undefined)?.['actor_verified']
  if (!actor) {
    return <DetailRow label="User" value="—" />
  }
  const content = actor.query ? (
    <Link
      to={`/logs?user=${encodeURIComponent(actor.query)}`}
      className="text-primary hover:underline font-mono text-xs inline-flex items-center gap-1"
      title={`See every request by ${actor.display}`}
    >
      <User className="h-3 w-3" />
      {actor.display}
    </Link>
  ) : (
    <span className="font-mono text-xs">{actor.display}</span>
  )
  return (
    <div className="flex justify-between gap-4 text-sm border-b border-border pb-2 items-start">
      <span className="text-muted-foreground">User</span>
      <div className="text-right break-all flex flex-col items-end gap-1">
        {content}
        {verified === false && (
          <Badge variant="outline" className="text-[10px] bg-amber-500/10 text-amber-400 border-amber-500/30">
            signature not verified
          </Badge>
        )}
      </div>
    </div>
  )
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4 text-sm border-b border-border pb-2">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn('text-right text-foreground break-all', mono && 'font-mono text-xs')}>{value}</span>
    </div>
  )
}
