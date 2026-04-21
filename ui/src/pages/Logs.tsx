import { useState, useEffect, useCallback, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Search, Filter, RefreshCw, X, ChevronLeft, ChevronRight,
  Copy, Star, Shield, ExternalLink, Clock, WifiOff, RotateCcw,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Textarea } from '@/components/ui/textarea'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle,
} from '@/components/ui/sheet'
import { cn, statusClass, statusBadgeVariant, formatBytes, relativeTime } from '@/lib/utils'
import { EmptyState } from '@/components/EmptyState'
import * as api from '@/api'
import type { LogEntry, LogBody } from '@/types'

const METHODS = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const PAGE_SIZE = 50

interface Filters {
  search: string
  host: string
  method: string
  path: string
  status_min: string
  status_max: string
  from: string
  to: string
  waf_blocked: boolean
  starred: boolean
  client_ip: string
  response_time_min: string
  status_group: '' | '2xx' | '3xx' | '4xx' | '5xx'
  user: string
}

const emptyFilters = (): Filters => ({
  search: '', host: '', method: '', path: '',
  status_min: '', status_max: '', from: '', to: '',
  waf_blocked: false, starred: false, client_ip: '',
  response_time_min: '', status_group: '', user: '',
})

function getLogID(log: Pick<LogEntry, 'id' | 'request_id'> | null | undefined) {
  return log?.id || log?.request_id || ''
}

function hasFilters(f: Filters) {
  return (
    f.search !== '' || f.host !== '' || f.method !== '' || f.path !== '' ||
    f.status_min !== '' || f.status_max !== '' || f.from !== '' || f.to !== '' ||
    f.waf_blocked || f.starred || f.client_ip !== '' ||
    f.response_time_min !== '' || f.status_group !== '' || f.user !== ''
  )
}

function filtersToParams(f: Filters, off: number): api.LogSearchParams {
  const params: api.LogSearchParams = { limit: PAGE_SIZE, offset: off }
  if (f.search) params.search = f.search
  if (f.host) params.host = f.host
  if (f.method) params.method = f.method
  if (f.path) params.path = f.path
  if (f.client_ip) params.client_ip = f.client_ip
  if (f.user) params.user = f.user
  if (f.waf_blocked) params.waf_blocked = true
  if (f.starred) params.starred = true
  if (f.response_time_min) params.response_time_min = Number(f.response_time_min)
  if (f.from) params.from = f.from
  if (f.to) params.to = f.to

  // Status group overrides manual min/max
  if (f.status_group) {
    const map: Record<string, [number, number]> = {
      '2xx': [200, 299], '3xx': [300, 399], '4xx': [400, 499], '5xx': [500, 599],
    }
    const [mn, mx] = map[f.status_group]
    params.status_min = mn
    params.status_max = mx
  } else {
    if (f.status_min) params.status_min = Number(f.status_min)
    if (f.status_max) params.status_max = Number(f.status_max)
  }
  return params
}

// ─── Active Filter Chips ─────────────────────────────────────────────────────

function FilterChips({ filters, onClear }: {
  filters: Filters
  onClear: (key: keyof Filters) => void
}) {
  const chips: { key: keyof Filters; label: string }[] = []
  if (filters.search) chips.push({ key: 'search', label: `search: ${filters.search}` })
  if (filters.host) chips.push({ key: 'host', label: `host: ${filters.host}` })
  if (filters.method) chips.push({ key: 'method', label: filters.method })
  if (filters.path) chips.push({ key: 'path', label: `path: ${filters.path}` })
  if (filters.client_ip) chips.push({ key: 'client_ip', label: `ip: ${filters.client_ip}` })
  if (filters.user) chips.push({ key: 'user', label: `user: ${filters.user}` })
  if (filters.status_group) chips.push({ key: 'status_group', label: filters.status_group })
  if (filters.status_min) chips.push({ key: 'status_min', label: `≥${filters.status_min}` })
  if (filters.status_max) chips.push({ key: 'status_max', label: `≤${filters.status_max}` })
  if (filters.response_time_min) chips.push({ key: 'response_time_min', label: `≥${filters.response_time_min}ms` })
  if (filters.waf_blocked) chips.push({ key: 'waf_blocked', label: 'WAF blocked' })
  if (filters.starred) chips.push({ key: 'starred', label: 'starred' })
  if (filters.from) chips.push({ key: 'from', label: `from: ${filters.from.replace('T', ' ')}` })
  if (filters.to) chips.push({ key: 'to', label: `to: ${filters.to.replace('T', ' ')}` })

  if (chips.length === 0) return null

  return (
    <div className="flex flex-wrap gap-1.5 px-6 py-2 border-b border-border bg-card/30 shrink-0">
      {chips.map(({ key, label }) => (
        <span
          key={key}
          className="inline-flex items-center gap-1 rounded-full bg-primary/10 text-primary text-[11px] font-mono px-2 py-0.5"
        >
          {label}
          <button
            onClick={() => onClear(key)}
            className="ml-0.5 hover:text-destructive transition-colors cursor-pointer"
          >
            <X className="h-2.5 w-2.5" />
          </button>
        </span>
      ))}
    </div>
  )
}

// ─── Log Detail Sheet ────────────────────────────────────────────────────────

function LogDetailSheet({
  log, open, onClose,
  onPivotIP, onPivotPath,
}: {
  log: LogEntry | null
  open: boolean
  onClose: () => void
  onPivotIP: (ip: string) => void
  onPivotPath: (path: string) => void
}) {
  const [detail, setDetail] = useState<(LogEntry & { body?: LogBody }) | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [note, setNote] = useState('')
  const [noteTimer, setNoteTimer] = useState<ReturnType<typeof setTimeout> | null>(null)
  const [starred, setStarred] = useState(false)

  useEffect(() => {
    if (!log || !open) return
    setDetail(null)
    setNote('')
    setStarred(log.is_starred ?? false)
    setLoadingDetail(true)
    const id = getLogID(log)
    if (!id) {
      setLoadingDetail(false)
      return
    }
    api.getLogDetail(id)
      .then(d => {
        setDetail(d)
        setNote(d.note ?? '')
        setStarred(d.is_starred ?? false)
      })
      .catch(() => {})
      .finally(() => setLoadingDetail(false))
  }, [log, open])

  function handleNoteChange(val: string) {
    setNote(val)
    if (noteTimer) clearTimeout(noteTimer)
    const t = setTimeout(() => {
      const id = getLogID(log)
      if (id) api.upsertLogNote(id, val).catch(() => {})
    }, 800)
    setNoteTimer(t)
  }

  async function handleToggleStar() {
    const id = getLogID(log)
    if (!id) return
    try {
      const next = !starred
      const res = await api.toggleLogStar(id)
      setStarred(res.is_starred ?? next)
    } catch {
      toast.error('Failed to toggle star')
    }
  }

  function buildCurl(entry: LogEntry & { body?: LogBody }): string {
    const qs = entry.query_string ? `?${entry.query_string}` : ''
    const url = `https://${entry.host}${entry.path}${qs}`
    const parts = [`curl -X ${entry.method} '${url}'`]
    if (entry.request_headers) {
      for (const [k, v] of Object.entries(entry.request_headers)) {
        if (k.toLowerCase() === 'host') continue
        parts.push(`  -H '${k}: ${v}'`)
      }
    }
    if (entry.body?.request_body) {
      parts.push(`  --data-raw '${entry.body.request_body.replace(/'/g, "'\\''")}'`)
    }
    return parts.join(' \\\n')
  }

  if (!log) return null
  const entry = detail ?? log

  return (
    <Sheet open={open} onOpenChange={v => !v && onClose()}>
      <SheetContent className="bg-card border-border w-full sm:max-w-2xl overflow-hidden flex flex-col">
        <SheetHeader className="shrink-0">
          <SheetTitle className="flex items-center gap-2 font-mono text-sm">
            <Badge variant={statusBadgeVariant(entry.response_status)} className="text-xs shrink-0">
              {entry.response_status}
            </Badge>
            {entry.waf_blocked && (
              <Badge variant="destructive" className="text-[10px] shrink-0">WAF BLOCKED</Badge>
            )}
            <span className="text-primary font-semibold">{entry.method}</span>
            <span className="text-foreground truncate">{entry.path}</span>
            <div className="ml-auto flex items-center gap-1 shrink-0">
              {detail && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 cursor-pointer"
                  title="Copy as cURL"
                  onClick={() => {
                    navigator.clipboard.writeText(buildCurl(detail))
                    toast.success('Copied as cURL')
                  }}
                >
                  <Copy className="h-3.5 w-3.5" />
                </Button>
              )}
              <Button
                variant="ghost"
                size="icon"
                className={cn('h-7 w-7 cursor-pointer', starred && 'text-yellow-400')}
                title={starred ? 'Unstar' : 'Star'}
                onClick={handleToggleStar}
              >
                <Star className={cn('h-3.5 w-3.5', starred && 'fill-yellow-400')} />
              </Button>
            </div>
          </SheetTitle>
          <SheetDescription className="font-mono text-xs">
            {new Date(entry.timestamp).toLocaleString()} &bull; ID: {getLogID(entry)}
          </SheetDescription>
        </SheetHeader>

        <ScrollArea className="flex-1 mt-4">
          <div className="space-y-4 pr-4">
            {/* Overview */}
            <section className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Overview</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {[
                  ['Host', entry.host],
                  ['Response Time', entry.response_time_ms != null ? `${entry.response_time_ms}ms` : '—'],
                  ['Request Size', entry.request_size != null ? formatBytes(entry.request_size) : '—'],
                  ['Response Size', entry.response_size != null ? formatBytes(entry.response_size) : '—'],
                  ['Query String', entry.query_string || '—'],
                  ['Konum', entry.country ? (entry.city ? `${entry.city}, ${entry.country}` : entry.country) : '—'],
                ].map(([k, v]) => (
                  <div key={k} className="rounded-md bg-background border border-border px-3 py-2">
                    <p className="text-xs text-muted-foreground">{k}</p>
                    <p className="text-sm font-mono text-foreground mt-0.5 break-all">{v}</p>
                  </div>
                ))}
                {/* Client IP with pivot */}
                <div className="rounded-md bg-background border border-border px-3 py-2">
                  <p className="text-xs text-muted-foreground">Client IP</p>
                  <div className="flex items-center gap-1 mt-0.5">
                    <p className="text-sm font-mono text-foreground break-all flex-1">{entry.client_ip}</p>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-5 w-5 cursor-pointer shrink-0 text-muted-foreground hover:text-primary"
                      title="All logs from this IP"
                      onClick={() => { onPivotIP(entry.client_ip); onClose() }}
                    >
                      <ExternalLink className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
                {/* Path with pivot */}
                <div className="rounded-md bg-background border border-border px-3 py-2">
                  <p className="text-xs text-muted-foreground">Path</p>
                  <div className="flex items-center gap-1 mt-0.5">
                    <p className="text-sm font-mono text-foreground break-all flex-1">{entry.path}</p>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-5 w-5 cursor-pointer shrink-0 text-muted-foreground hover:text-primary"
                      title="All logs to this path"
                      onClick={() => { onPivotPath(entry.path); onClose() }}
                    >
                      <ExternalLink className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </div>
            </section>

            {/* WAF Block Detail */}
            {entry.waf_blocked && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-destructive flex items-center gap-1">
                  <Shield className="h-3.5 w-3.5" /> WAF Block Event
                </h3>
                <div className="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 space-y-1">
                  {entry.waf_block_reason && (
                    <div>
                      <p className="text-[10px] text-destructive/70 uppercase font-semibold">Reason</p>
                      <p className="text-xs font-mono text-destructive">{entry.waf_block_reason}</p>
                    </div>
                  )}
                  {entry.request_id && (
                    <div>
                      <p className="text-[10px] text-destructive/70 uppercase font-semibold">Request ID</p>
                      <p className="text-xs font-mono text-destructive break-all">{entry.request_id}</p>
                    </div>
                  )}
                </div>
              </section>
            )}

            {/* JWT Identity */}
            {entry.user_identity && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1">
                  <Shield className="h-3.5 w-3.5" /> Identity
                </h3>
                <div className={cn(
                  'rounded-md px-3 py-2 space-y-2 border',
                  entry.user_identity.verified
                    ? 'bg-emerald-500/5 border-emerald-500/30'
                    : entry.user_identity.exp_expired
                      ? 'bg-amber-500/5 border-amber-500/30'
                      : 'bg-background border-border',
                )}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge
                      variant="outline"
                      className={cn(
                        'text-[10px]',
                        entry.user_identity.verified
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-muted text-muted-foreground',
                      )}
                    >
                      {entry.user_identity.verified ? 'Verified' : 'Unverified'}
                    </Badge>
                    <Badge variant="outline" className="text-[10px] font-mono">
                      {entry.user_identity.source}
                    </Badge>
                    {entry.user_identity.exp_expired && (
                      <Badge variant="outline" className="text-[10px] bg-amber-500/10 text-amber-400 border-amber-500/30">
                        exp expired
                      </Badge>
                    )}
                  </div>
                  {!entry.user_identity.verified && !entry.user_identity.exp_expired && (
                    <p className="text-[11px] text-muted-foreground italic">
                      Signature did not verify. Claims shown below for observation only — do not use for authorization.
                    </p>
                  )}
                  {entry.user_identity.exp_expired && (
                    <p className="text-[11px] text-amber-400/80 italic">
                      Signature was valid, but the token's exp has passed. Treat as expired, not forged.
                    </p>
                  )}
                  {entry.user_identity.claims && Object.keys(entry.user_identity.claims).length > 0 && (
                    <div className="space-y-1">
                      {Object.entries(entry.user_identity.claims).map(([k, v]) => (
                        <div key={k} className="flex items-start gap-2 text-xs">
                          <span className="text-muted-foreground font-mono shrink-0 min-w-[80px]">{k}</span>
                          <span className="text-foreground font-mono break-all">{v}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </section>
            )}

            {/* Request ID (non-WAF) */}
            {entry.request_id && !entry.waf_blocked && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Request ID</h3>
                <div className="rounded-md bg-background border border-border px-3 py-2">
                  <p className="text-xs font-mono text-foreground break-all">{entry.request_id}</p>
                </div>
              </section>
            )}

            {/* User Agent */}
            {entry.user_agent && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">User Agent</h3>
                <div className="rounded-md bg-background border border-border px-3 py-2">
                  <p className="text-xs font-mono text-foreground break-all">{entry.user_agent}</p>
                </div>
              </section>
            )}

            {/* Error */}
            {entry.error && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-destructive">Error</h3>
                <div className="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2">
                  <p className="text-xs font-mono text-destructive break-all">{entry.error}</p>
                </div>
              </section>
            )}

            {/* Request Headers */}
            {entry.request_headers && Object.keys(entry.request_headers).length > 0 && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Request Headers</h3>
                <div className="rounded-md bg-background border border-border divide-y divide-border">
                  {Object.entries(entry.request_headers).map(([k, v]) => (
                    <div key={k} className="flex flex-col sm:flex-row sm:gap-3 px-3 py-1.5">
                      <span className="text-xs font-mono text-muted-foreground sm:w-36 sm:shrink-0 sm:truncate">{k}</span>
                      <span className="text-xs font-mono text-foreground break-all">{v}</span>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Response Headers */}
            {entry.response_headers && Object.keys(entry.response_headers).length > 0 && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Response Headers</h3>
                <div className="rounded-md bg-background border border-border divide-y divide-border">
                  {Object.entries(entry.response_headers).map(([k, v]) => (
                    <div key={k} className="flex flex-col sm:flex-row sm:gap-3 px-3 py-1.5">
                      <span className="text-xs font-mono text-muted-foreground sm:w-36 sm:shrink-0 sm:truncate">{k}</span>
                      <span className="text-xs font-mono text-foreground break-all">{v}</span>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Bodies */}
            {loadingDetail ? (
              <Skeleton className="h-24 w-full" />
            ) : detail ? (
              <>
                <section className="space-y-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                    Request Body
                    {detail.body?.is_request_truncated && <Badge variant="outline" className="text-[10px]">Truncated</Badge>}
                  </h3>
                  {detail.body?.request_body ? (
                    <pre className="rounded-md bg-background border border-border px-3 py-2 text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap break-all">
                      {detail.body.request_body}
                    </pre>
                  ) : (
                    <div className="rounded-md bg-background border border-border px-3 py-2 text-xs font-mono text-muted-foreground">
                      No request body captured
                    </div>
                  )}
                </section>
                <section className="space-y-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                    Response Body
                    {detail.body?.is_response_truncated && <Badge variant="outline" className="text-[10px]">Truncated</Badge>}
                  </h3>
                  {detail.body?.response_body ? (
                    <pre className="rounded-md bg-background border border-border px-3 py-2 text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap break-all">
                      {detail.body.response_body}
                    </pre>
                  ) : (
                    <div className="rounded-md bg-background border border-border px-3 py-2 text-xs font-mono text-muted-foreground">
                      No response body captured
                    </div>
                  )}
                </section>
              </>
            ) : null}

            {/* Notes */}
            <section className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Notes</h3>
              <Textarea
                className="text-xs font-mono bg-background border-border resize-none"
                rows={3}
                placeholder="Add a note…"
                value={note}
                onChange={e => handleNoteChange(e.target.value)}
              />
            </section>
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  )
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function Logs() {
  const [searchParams] = useSearchParams()
  // Accept ?user=alice from Dashboard Top Users / Alerts page deep links.
  // The initial state seeds both filters (what's applied) and pendingFilters
  // (what's in the form) so the user lands on a pre-filtered page.
  const initialFilters: Filters = (() => {
    const f = emptyFilters()
    const u = searchParams.get('user')
    if (u) f.user = u
    const ip = searchParams.get('client_ip')
    if (ip) f.client_ip = ip
    const host = searchParams.get('host')
    if (host) f.host = host
    return f
  })()
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(false)
  const [serviceDown, setServiceDown] = useState(false)
  const [filters, setFilters] = useState<Filters>(initialFilters)
  const [pendingFilters, setPendingFilters] = useState<Filters>(initialFilters)
  const [showFilters, setShowFilters] = useState(false)
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null)
  const [live, setLive] = useState(false)
  const [sseDisconnected, setSseDisconnected] = useState(false)
  const sseCloseRef = useRef<(() => void) | null>(null)

  const fetchLogs = useCallback(async (f: Filters, off: number) => {
    setLoading(true)
    try {
      setServiceDown(false)
      const res = await api.searchLogs(filtersToParams(f, off))
      setLogs(res.data ?? [])
      setTotal(res.total)
    } catch (err) {
      if (api.isServiceUnavailable(err)) {
        setServiceDown(true)
      } else {
        toast.error(err instanceof api.ApiError ? err.message : 'Failed to fetch logs')
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchLogs(filters, offset)
  }, [filters, offset, fetchLogs])

  // SSE live tail
  useEffect(() => {
    if (sseCloseRef.current) {
      sseCloseRef.current()
      sseCloseRef.current = null
    }
    if (!live) {
      setSseDisconnected(false)
      return
    }
    setSseDisconnected(false)
    const close = api.createLogStream(
      (entry) => {
        if (selectedLog) return // pause while detail open
        setLogs(prev => [entry, ...prev].slice(0, PAGE_SIZE))
        setTotal(t => t + 1)
      },
      () => {
        setSseDisconnected(true)
        setLive(false)
      },
    )
    sseCloseRef.current = close
    return () => { close(); sseCloseRef.current = null }
  }, [live]) // eslint-disable-line react-hooks/exhaustive-deps

  function applyFilters() {
    setFilters(pendingFilters)
    setOffset(0)
    setShowFilters(false)
  }

  function clearFilters() {
    const empty = emptyFilters()
    setPendingFilters(empty)
    setFilters(empty)
    setOffset(0)
  }

  function clearOneFilter(key: keyof Filters) {
    const defaultVal = emptyFilters()[key]
    const next = { ...filters, [key]: defaultVal }
    setFilters(next)
    setPendingFilters(next)
    setOffset(0)
  }

  function setPF<K extends keyof Filters>(k: K, v: Filters[K]) {
    setPendingFilters(f => ({ ...f, [k]: v }))
  }

  function handlePivotIP(ip: string) {
    const next = { ...emptyFilters(), client_ip: ip }
    setFilters(next)
    setPendingFilters(next)
    setOffset(0)
    setSelectedLog(null)
  }

  function handlePivotPath(path: string) {
    const next = { ...emptyFilters(), path }
    setFilters(next)
    setPendingFilters(next)
    setOffset(0)
    setSelectedLog(null)
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1

  const methodColor = (m: string) => {
    const map: Record<string, string> = {
      GET: 'text-primary', POST: 'text-blue-400', PUT: 'text-yellow-400',
      PATCH: 'text-yellow-400', DELETE: 'text-destructive',
      HEAD: 'text-muted-foreground', OPTIONS: 'text-muted-foreground',
    }
    return map[m] ?? 'text-foreground'
  }

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-6 py-3 border-b border-border shrink-0">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Full-text search…"
            className="pl-9 bg-card border-border h-9"
            value={pendingFilters.search}
            onChange={e => setPF('search', e.target.value)}
            onKeyDown={e => e.key === 'Enter' && applyFilters()}
          />
        </div>

        {/* Status group quick buttons */}
        <div className="flex gap-1">
          {(['2xx', '3xx', '4xx', '5xx'] as const).map(g => (
            <Button
              key={g}
              variant={filters.status_group === g ? 'default' : 'outline'}
              size="sm"
              className={cn('h-8 px-2 text-[11px] cursor-pointer border-border font-mono',
                g === '5xx' && filters.status_group !== g && 'text-destructive',
                g === '4xx' && filters.status_group !== g && 'text-yellow-500',
              )}
              onClick={() => {
                const next = { ...filters, status_group: filters.status_group === g ? ('' as const) : g, status_min: '', status_max: '' }
                setFilters(next)
                setPendingFilters(next)
                setOffset(0)
              }}
            >
              {g}
            </Button>
          ))}
        </div>

        {/* WAF blocked quick toggle */}
        <Button
          variant={filters.waf_blocked ? 'default' : 'outline'}
          size="sm"
          className={cn('gap-1.5 cursor-pointer border-border h-8', filters.waf_blocked && 'bg-destructive hover:bg-destructive/90 border-destructive')}
          onClick={() => {
            const next = { ...filters, waf_blocked: !filters.waf_blocked }
            setFilters(next)
            setPendingFilters(next)
            setOffset(0)
          }}
        >
          <Shield className="h-3 w-3" />
          WAF
        </Button>

        {/* Starred quick toggle */}
        <Button
          variant={filters.starred ? 'default' : 'outline'}
          size="sm"
          className={cn('gap-1.5 cursor-pointer border-border h-8', filters.starred && 'bg-yellow-500 hover:bg-yellow-500/90 border-yellow-500 text-white')}
          onClick={() => {
            const next = { ...filters, starred: !filters.starred }
            setFilters(next)
            setPendingFilters(next)
            setOffset(0)
          }}
        >
          <Star className={cn('h-3 w-3', filters.starred && 'fill-white')} />
        </Button>

        <Button
          variant={showFilters ? 'default' : 'outline'}
          size="sm"
          className="gap-2 cursor-pointer border-border"
          onClick={() => setShowFilters(v => !v)}
        >
          <Filter className="h-3.5 w-3.5" />
          Filters
          {hasFilters(filters) && (
            <span className="flex h-4 w-4 items-center justify-center rounded-full bg-primary text-primary-foreground text-[10px] font-bold">
              !
            </span>
          )}
        </Button>
        {hasFilters(filters) && (
          <Button variant="ghost" size="sm" onClick={clearFilters} className="gap-1.5 cursor-pointer text-muted-foreground hover:text-foreground">
            <X className="h-3.5 w-3.5" /> Clear
          </Button>
        )}
        <Button
          variant="outline"
          size="icon"
          className={cn('h-9 w-9 cursor-pointer border-border', loading && 'opacity-50')}
          onClick={() => fetchLogs(filters, offset)}
          disabled={loading || live}
        >
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
        </Button>
        <Button
          variant={live ? 'default' : 'outline'}
          size="sm"
          className="cursor-pointer border-border gap-1.5"
          onClick={() => setLive(v => !v)}
        >
          <span className={cn('h-1.5 w-1.5 rounded-full', live ? 'bg-primary-foreground animate-pulse' : 'bg-muted-foreground')} />
          Live
        </Button>
        <div className="ml-auto text-xs text-muted-foreground">
          {total.toLocaleString()} entries
        </div>
      </div>

      {/* SSE disconnected indicator */}
      {sseDisconnected && (
        <div className="flex items-center gap-3 px-6 py-2 border-b border-amber-500/20 bg-amber-500/5 shrink-0">
          <WifiOff className="h-3.5 w-3.5 text-amber-400 shrink-0" />
          <span className="text-xs text-amber-400 font-medium">Canli akis baglantisi kesildi</span>
          <Button
            variant="outline"
            size="sm"
            className="h-6 px-2 text-[11px] gap-1.5 cursor-pointer border-amber-500/30 text-amber-400 hover:bg-amber-500/10 ml-auto"
            onClick={() => { setSseDisconnected(false); setLive(true) }}
          >
            <RotateCcw className="h-3 w-3" />
            Yeniden Baglan
          </Button>
        </div>
      )}

      {/* Active filter chips */}
      <FilterChips filters={filters} onClear={clearOneFilter} />

      {/* Expanded Filter Panel */}
      {showFilters && (
        <div className="border-b border-border bg-card/50 px-6 py-4 shrink-0">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Host</Label>
              <Input placeholder="example.com" className="h-8 text-xs bg-background border-border" value={pendingFilters.host} onChange={e => setPF('host', e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Client IP</Label>
              <Input placeholder="1.2.3.4" className="h-8 text-xs bg-background border-border font-mono" value={pendingFilters.client_ip} onChange={e => setPF('client_ip', e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">User (JWT claim)</Label>
              <Input
                placeholder="alice@foo.com"
                className="h-8 text-xs bg-background border-border font-mono"
                value={pendingFilters.user}
                onChange={e => setPF('user', e.target.value)}
                title="Matches the value against email, name and sub JWT claims"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Method</Label>
              <Select value={pendingFilters.method || '__all'} onValueChange={v => setPF('method', v === '__all' ? '' : v)}>
                <SelectTrigger className="h-8 text-xs bg-background border-border cursor-pointer">
                  <SelectValue placeholder="Any" />
                </SelectTrigger>
                <SelectContent className="bg-card border-border">
                  {METHODS.map(m => (
                    <SelectItem key={m || '__all'} value={m || '__all'} className="cursor-pointer text-xs">
                      {m || 'Any'}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Path contains</Label>
              <Input placeholder="/api/v1" className="h-8 text-xs bg-background border-border font-mono" value={pendingFilters.path} onChange={e => setPF('path', e.target.value)} />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label className="text-xs">Status min</Label>
                <Input placeholder="200" type="number" className="h-8 text-xs bg-background border-border" value={pendingFilters.status_min} onChange={e => setPF('status_min', e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Status max</Label>
                <Input placeholder="599" type="number" className="h-8 text-xs bg-background border-border" value={pendingFilters.status_max} onChange={e => setPF('status_max', e.target.value)} />
              </div>
            </div>
            <div className="space-y-1">
              <Label className="text-xs flex items-center gap-1"><Clock className="h-3 w-3" /> Min response time (ms)</Label>
              <Input placeholder="500" type="number" className="h-8 text-xs bg-background border-border" value={pendingFilters.response_time_min} onChange={e => setPF('response_time_min', e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">From</Label>
              <Input type="datetime-local" className="h-8 text-xs bg-background border-border" value={pendingFilters.from} onChange={e => setPF('from', e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">To</Label>
              <Input type="datetime-local" className="h-8 text-xs bg-background border-border" value={pendingFilters.to} onChange={e => setPF('to', e.target.value)} />
            </div>
          </div>
          <div className="flex gap-2 mt-3">
            <Button size="sm" onClick={applyFilters} className="cursor-pointer">Apply Filters</Button>
            <Button size="sm" variant="outline" onClick={clearFilters} className="cursor-pointer border-border">Clear</Button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="flex-1 overflow-hidden">
        <div className="h-full overflow-auto">
          {serviceDown ? (
            <EmptyState
              variant="service-offline"
              title="diaLOG SIEM Servisi Cevrimdisi"
              description="Log goruntulemesi icin diaLOG servisinin calisiyor olmasi gerekiyor."
              className="py-24"
            />
          ) : <>
          {/* Header */}
          <div className="sticky top-0 z-10 bg-card border-b border-border">
            <div className="grid grid-cols-[70px_110px_75px_minmax(0,1fr)_150px_110px_55px_100px_70px_70px] gap-2 px-4 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              <span>Status</span>
              <span>Time</span>
              <span>Method</span>
              <span>Path</span>
              <span>User</span>
              <span>Client IP</span>
              <span>Ülke</span>
              <span>Host</span>
              <span>Süre</span>
              <span>Boyut</span>
            </div>
          </div>

          {loading && logs.length === 0 ? (
            <div className="p-4 space-y-1">
              {Array.from({ length: 12 }, (_, i) => (
                <Skeleton key={i} className="h-9 w-full rounded-sm" />
              ))}
            </div>
          ) : logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <Search className="h-12 w-12 text-muted-foreground/30 mb-4" />
              <p className="text-muted-foreground">No logs found</p>
              {hasFilters(filters) && (
                <Button variant="link" onClick={clearFilters} className="mt-2 text-primary cursor-pointer">Clear filters</Button>
              )}
            </div>
          ) : (
            <div className="divide-y divide-border/50">
              {logs.map(log => (
                <div
                  key={getLogID(log)}
                  onClick={() => setSelectedLog(log)}
                  className="grid grid-cols-[70px_110px_75px_minmax(0,1fr)_150px_110px_55px_100px_70px_70px] gap-2 px-4 py-2 hover:bg-muted/10 cursor-pointer transition-colors group"
                >
                  <span className={cn('text-xs font-mono font-semibold flex items-center gap-1', statusClass(log.response_status))}>
                    {log.response_status}
                    {log.waf_blocked && <Shield className="h-2.5 w-2.5 text-destructive" />}
                    {log.is_starred && <Star className="h-2.5 w-2.5 fill-yellow-400 text-yellow-400" />}
                  </span>
                  <span className="text-xs text-muted-foreground font-mono truncate" title={new Date(log.timestamp).toLocaleString()}>
                    {relativeTime(log.timestamp)}
                  </span>
                  <span className={cn('text-xs font-mono font-semibold', methodColor(log.method))}>
                    {log.method}
                  </span>
                  <span className="text-xs font-mono text-foreground truncate group-hover:text-primary transition-colors">
                    {log.path}{log.query_string ? `?${log.query_string}` : ''}
                  </span>
                  {log.user_display ? (
                    <button
                      type="button"
                      className="text-xs font-mono text-primary/80 hover:text-primary truncate text-left cursor-pointer"
                      title={`Filter by user ${log.user_display}`}
                      onClick={(e) => {
                        e.stopPropagation()
                        setPendingFilters(f => ({ ...f, user: log.user_query || log.user_display || '' }))
                        setFilters(f => ({ ...f, user: log.user_query || log.user_display || '' }))
                      }}
                    >
                      {log.user_display}
                    </button>
                  ) : (
                    <span className="text-xs font-mono text-muted-foreground/50">—</span>
                  )}
                  <span className="text-xs font-mono text-muted-foreground truncate">{log.client_ip}</span>
                  <span className="text-xs font-mono text-muted-foreground truncate" title={log.city ? `${log.city}, ${log.country}` : undefined}>
                    {log.country || '—'}
                  </span>
                  <span className="text-xs text-muted-foreground truncate font-mono">{log.host}</span>
                  <span className="text-xs font-mono text-muted-foreground">
                    {log.response_time_ms != null ? `${log.response_time_ms}ms` : '—'}
                  </span>
                  <span className="text-xs font-mono text-muted-foreground">
                    {log.response_size != null ? formatBytes(log.response_size) : '—'}
                  </span>
                </div>
              ))}
            </div>
          )}
          </>}
        </div>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between px-6 py-3 border-t border-border shrink-0">
        <span className="text-xs text-muted-foreground">
          Page {currentPage} of {totalPages || 1}
          {' '}&bull; {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          {live && <span className="ml-2 text-primary animate-pulse">● live</span>}
        </span>
        <div className="flex items-center gap-1">
          <Button
            variant="outline" size="icon" className="h-8 w-8 cursor-pointer border-border"
            disabled={offset === 0 || live}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline" size="icon" className="h-8 w-8 cursor-pointer border-border"
            disabled={offset + PAGE_SIZE >= total || live}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Detail Sheet */}
      <LogDetailSheet
        log={selectedLog}
        open={!!selectedLog}
        onClose={() => setSelectedLog(null)}
        onPivotIP={handlePivotIP}
        onPivotPath={handlePivotPath}
      />
    </div>
  )
}
