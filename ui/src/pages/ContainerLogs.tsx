import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Search, RefreshCw, Server, History as HistoryIcon, Activity, AlertTriangle,
} from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import type { ContainerSummary, ContainerLogRow, IngestStatus } from '@/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { cn, relativeTime } from '@/lib/utils'
import ContainerLogPane from '@/components/ContainerLogPane'

// ContainerLogs is the dedicated /container-logs page. Tabs:
//  - Live: pick a (still-running) container, see its stdout/stderr
//    streamed via SSE.
//  - History: full text + structured search across the entire
//    container_logs hypertable, including dead containers.
//
// State is kept in URL search params so a hard refresh / shared link
// preserves the open container + filters.
export default function ContainerLogs() {
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') ?? 'live') as 'live' | 'history'
  const setTab = (v: 'live' | 'history') => {
    const next = new URLSearchParams(params)
    next.set('tab', v)
    setParams(next, { replace: true })
  }

  return (
    <div className="flex h-full flex-col gap-4 p-6">
      <div className="flex items-center gap-3">
        <Activity className="h-5 w-5 text-primary" />
        <div>
          <h1 className="text-lg font-semibold">Container Logs</h1>
          <p className="text-xs text-muted-foreground">
            Konteyner stdout/stderr akışı — canlı tail ve geçmiş arama.
          </p>
        </div>
        <IngestBadge className="ml-auto" />
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as 'live' | 'history')} className="flex-1">
        <TabsList>
          <TabsTrigger value="live"><Activity className="mr-1 h-3.5 w-3.5" /> Live</TabsTrigger>
          <TabsTrigger value="history"><HistoryIcon className="mr-1 h-3.5 w-3.5" /> History</TabsTrigger>
        </TabsList>
        <TabsContent value="live" className="mt-4">
          <LiveTab />
        </TabsContent>
        <TabsContent value="history" className="mt-4">
          <HistoryTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

// ── Live tab ────────────────────────────────────────────────────────────

function LiveTab() {
  const [params, setParams] = useSearchParams()
  const selected = params.get('id') ?? ''
  const setSelected = (id: string) => {
    const next = new URLSearchParams(params)
    if (id) next.set('id', id)
    else next.delete('id')
    setParams(next, { replace: true })
  }

  const [containers, setContainers] = useState<ContainerSummary[]>([])
  const [filter, setFilter] = useState('')
  const [loading, setLoading] = useState(false)

  async function reload() {
    setLoading(true)
    try {
      const resp = await api.listContainers({ state: 'running' })
      setContainers(resp.data ?? [])
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Konteyner listesi alınamadı'
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void reload() }, [])

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return containers
    return containers.filter((c) =>
      c.container_name.toLowerCase().includes(q)
      || (c.project ?? '').toLowerCase().includes(q)
      || (c.component ?? '').toLowerCase().includes(q)
      || (c.release_id ?? '').toLowerCase().includes(q)
      || c.container_id.toLowerCase().includes(q),
    )
  }, [containers, filter])

  const current = containers.find((c) => c.container_id === selected)

  return (
    <div className="grid h-full grid-cols-1 gap-4 lg:grid-cols-[320px_1fr]">
      <div className="flex flex-col gap-2 rounded-lg border border-border bg-card p-3">
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4 text-primary" />
          <span className="text-sm font-medium">Çalışan Konteynerler</span>
          <Button size="icon" variant="ghost" className="ml-auto h-7 w-7" onClick={reload} disabled={loading}>
            <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
          </Button>
        </div>
        <Input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="ad / proje / release ile filtrele"
          className="h-8 text-xs"
        />
        <div className="-mx-1 flex-1 overflow-y-auto">
          {filtered.length === 0 ? (
            <div className="px-2 py-6 text-center text-xs text-muted-foreground">
              {loading ? 'Yükleniyor…' : 'Çalışan konteyner bulunamadı.'}
            </div>
          ) : (
            <ul className="space-y-1 px-1">
              {filtered.map((c) => (
                <li key={c.container_id}>
                  <button
                    onClick={() => setSelected(c.container_id)}
                    className={cn(
                      'flex w-full flex-col items-start gap-0.5 rounded-md border border-transparent px-2 py-2 text-left text-xs hover:border-border hover:bg-accent',
                      selected === c.container_id && 'border-primary/40 bg-primary/10',
                    )}
                  >
                    <div className="flex w-full items-center gap-1">
                      <span className="truncate font-mono">{c.container_name || c.container_id.slice(0, 12)}</span>
                      {c.live ? (
                        <Badge variant="outline" className="ml-auto border-emerald-400/40 text-[10px] text-emerald-300">live</Badge>
                      ) : (
                        <Badge variant="outline" className="ml-auto text-[10px]">{c.state}</Badge>
                      )}
                    </div>
                    <div className="flex w-full items-center gap-2 text-muted-foreground">
                      {c.project && <span>{c.project}/{c.component}</span>}
                      {c.release_id && <span className="font-mono text-[10px]">{c.release_id.slice(0, 12)}</span>}
                      {c.host_id && c.host_id !== 'central' && (
                        <Badge variant="outline" className="ml-auto text-[10px]">{c.host_id}</Badge>
                      )}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="min-h-0">
        {selected ? (
          <ContainerLogPane
            key={selected}
            containerId={selected}
            tail={200}
            title={current ? `${current.project ?? '?'}/${current.component ?? '?'} · ${current.release_id?.slice(0, 12) ?? ''}` : selected.slice(0, 12)}
          />
        ) : (
          <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-border text-sm text-muted-foreground">
            Soldan bir konteyner seçin.
          </div>
        )}
      </div>
    </div>
  )
}

// ── History tab ─────────────────────────────────────────────────────────

function HistoryTab() {
  // Initial filter values come from URL search params so that links
  // like `/container-logs?tab=history&release_id=aef3a8a` (used by the
  // Apps deployment-detail "Container logs" pivot) land pre-filtered.
  const [searchParams] = useSearchParams()
  const [filters, setFilters] = useState(() => ({
    q: searchParams.get('q') ?? '',
    container_id: searchParams.get('container_id') ?? '',
    project: searchParams.get('project') ?? '',
    component: searchParams.get('component') ?? '',
    release_id: searchParams.get('release_id') ?? '',
    host_id: searchParams.get('host_id') ?? '',
    stream: (searchParams.get('stream') ?? '') as '' | 'stdout' | 'stderr',
    from: searchParams.get('from') ?? '',
    to: searchParams.get('to') ?? '',
  }))
  const [rows, setRows] = useState<ContainerLogRow[]>([])
  const [nextBefore, setNextBefore] = useState<string | undefined>()
  const [loading, setLoading] = useState(false)
  const [contextRows, setContextRows] = useState<{ anchorId: string; rows: ContainerLogRow[] } | null>(null)

  async function search(reset = true) {
    setLoading(true)
    try {
      const resp = await api.searchContainerLogs({
        ...filters,
        before: reset ? undefined : nextBefore,
        limit: 200,
      })
      setNextBefore(resp.next_before_cursor)
      setRows((prev) => (reset ? resp.data : [...prev, ...resp.data]))
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Arama başarısız'
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void search(true) }, [])

  async function loadContext(row: ContainerLogRow) {
    try {
      const resp = await api.getContainerLogContext(row.id, 50)
      setContextRows({ anchorId: row.id, rows: resp.data ?? [] })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Bağlam yüklenemedi'
      toast.error(msg)
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-2 rounded-lg border border-border bg-card p-3 lg:grid-cols-4">
        <div>
          <Label className="text-[10px] uppercase">Free text</Label>
          <Input
            value={filters.q}
            onChange={(e) => setFilters({ ...filters, q: e.target.value })}
            placeholder="ILIKE %term%"
            className="h-8 text-xs"
            onKeyDown={(e) => { if (e.key === 'Enter') void search(true) }}
          />
        </div>
        <div>
          <Label className="text-[10px] uppercase">Project</Label>
          <Input
            value={filters.project}
            onChange={(e) => setFilters({ ...filters, project: e.target.value })}
            className="h-8 text-xs"
          />
        </div>
        <div>
          <Label className="text-[10px] uppercase">Component</Label>
          <Input
            value={filters.component}
            onChange={(e) => setFilters({ ...filters, component: e.target.value })}
            className="h-8 text-xs"
          />
        </div>
        <div>
          <Label className="text-[10px] uppercase">Release</Label>
          <Input
            value={filters.release_id}
            onChange={(e) => setFilters({ ...filters, release_id: e.target.value })}
            placeholder="aef3a8a…"
            className="h-8 font-mono text-xs"
          />
        </div>
        <div>
          <Label className="text-[10px] uppercase">Container ID</Label>
          <Input
            value={filters.container_id}
            onChange={(e) => setFilters({ ...filters, container_id: e.target.value })}
            className="h-8 font-mono text-xs"
          />
        </div>
        <div>
          <Label className="text-[10px] uppercase">Host</Label>
          <Input
            value={filters.host_id}
            onChange={(e) => setFilters({ ...filters, host_id: e.target.value })}
            placeholder="central"
            className="h-8 text-xs"
          />
        </div>
        <div>
          <Label className="text-[10px] uppercase">Stream</Label>
          <Select value={filters.stream || 'all'} onValueChange={(v) => setFilters({ ...filters, stream: v === 'all' ? '' : (v as 'stdout' | 'stderr') })}>
            <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">all</SelectItem>
              <SelectItem value="stdout">stdout</SelectItem>
              <SelectItem value="stderr">stderr</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-end gap-2">
          <Button size="sm" onClick={() => void search(true)} disabled={loading}>
            <Search className="mr-1 h-3.5 w-3.5" /> Ara
          </Button>
          <Button size="sm" variant="ghost" onClick={() => { setFilters({ q: '', container_id: '', project: '', component: '', release_id: '', host_id: '', stream: '', from: '', to: '' }); void search(true) }}>
            Temizle
          </Button>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card">
        <div className="border-b border-border px-3 py-2 text-xs text-muted-foreground">
          {rows.length} satır
          {nextBefore && (
            <Button
              size="sm"
              variant="ghost"
              className="ml-auto h-6 px-2 text-xs"
              onClick={() => void search(false)}
              disabled={loading}
            >
              Daha eski yükle
            </Button>
          )}
        </div>
        <div className="max-h-[640px] overflow-y-auto font-mono text-[11px]">
          {rows.length === 0 ? (
            <div className="flex h-32 items-center justify-center text-muted-foreground">Sonuç yok.</div>
          ) : rows.map((r) => (
            <div
              key={r.id}
              className={cn(
                'group flex items-start gap-2 border-b border-border/30 px-3 py-1 hover:bg-accent/50',
                r.stream === 'stderr' && 'bg-red-400/5 text-red-200',
              )}
              onClick={() => void loadContext(r)}
              role="button"
              tabIndex={0}
            >
              <span className="shrink-0 text-muted-foreground">{r.timestamp}</span>
              <span className={cn('shrink-0 rounded px-1 text-[10px]', r.stream === 'stderr' ? 'bg-red-400/15' : 'bg-muted/40')}>
                {r.stream}
              </span>
              <span className="shrink-0 text-muted-foreground" title={r.container_id}>
                {r.container_name.slice(0, 32)}
              </span>
              <span className="flex-1 whitespace-pre-wrap break-words">{r.line}</span>
            </div>
          ))}
        </div>
      </div>

      {contextRows && (
        <div className="rounded-lg border border-border bg-card">
          <div className="flex items-center gap-2 border-b border-border px-3 py-2 text-xs">
            <Badge variant="outline">±50 bağlam</Badge>
            <span className="text-muted-foreground">anchor: {contextRows.anchorId.slice(0, 16)}</span>
            <Button size="sm" variant="ghost" className="ml-auto h-6 px-2 text-xs" onClick={() => setContextRows(null)}>Kapat</Button>
          </div>
          <div className="max-h-[480px] overflow-y-auto font-mono text-[11px]">
            {contextRows.rows.map((r) => (
              <div
                key={r.id}
                className={cn(
                  'flex items-start gap-2 border-b border-border/30 px-3 py-1',
                  r.id === contextRows.anchorId && 'bg-amber-400/10',
                  r.stream === 'stderr' && 'text-red-200',
                )}
              >
                <span className="shrink-0 text-muted-foreground">{r.timestamp}</span>
                <span className="shrink-0 text-[10px]">{r.stream}</span>
                <span className="flex-1 whitespace-pre-wrap break-words">{r.line}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Ingest health badge ─────────────────────────────────────────────────

function IngestBadge({ className }: { className?: string }) {
  const [status, setStatus] = useState<IngestStatus | null>(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const s = await api.getIngestStatus()
        if (!cancelled) setStatus(s)
      } catch {
        // best effort
      }
    }
    void load()
    const t = setInterval(() => { void load() }, 15000)
    return () => { cancelled = true; clearInterval(t) }
  }, [])

  if (!status) return null

  const degraded = status.dialog?.degraded || !status.deployer_available || !status.dialog_available
  const tooltip = [
    status.dialog ? `enqueued ${status.dialog.enqueued_total ?? 0}` : null,
    status.dialog?.dropped_total ? `dropped ${status.dialog.dropped_total}` : null,
    status.dialog?.spool_bytes ? `spool ${formatBytes(status.dialog.spool_bytes)}` : null,
    status.dialog?.last_batch_at ? `last batch ${relativeTime(status.dialog.last_batch_at)}` : null,
    status.deployer?.shipper_active_containers ? `${status.deployer.shipper_active_containers} containers tailed` : null,
  ].filter(Boolean).join(' · ')

  return (
    <Badge
      variant="outline"
      className={cn(
        degraded ? 'border-amber-400/40 text-amber-300 bg-amber-400/10' : 'border-emerald-400/40 text-emerald-300',
        className,
      )}
      title={tooltip}
    >
      {degraded && <AlertTriangle className="mr-1 h-3 w-3" />}
      Ingest: {degraded ? 'degraded' : 'ok'}
    </Badge>
  )
}

function formatBytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB']
  let v = n
  let u = 0
  while (v > 1024 && u < units.length - 1) {
    v /= 1024
    u++
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)}${units[u]}`
}
