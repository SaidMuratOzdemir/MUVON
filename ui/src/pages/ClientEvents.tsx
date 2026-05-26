import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Search, RefreshCw, MousePointerClick, MapPin, Link2 } from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import type { ClientEventRow, ClientEventSearchParams } from '@/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { cn, relativeTime } from '@/lib/utils'

// ClientEvents is the /client-events page: browser RUM telemetry shipped to
// the reserved /__muvon/rum endpoint. The headline is the trace_id join —
// arriving with ?trace_id=<hex> (e.g. from a log detail) pins the view to a
// single request's client-side story.
const PAGE_SIZE = 200

// Event names that signal a problem get a red badge; everything else neutral.
const errorEvents = new Set(['js_error', 'unhandled_rejection', 'resource_error', 'dom_error'])

export default function ClientEvents() {
  const [params, setParams] = useSearchParams()
  const [rows, setRows] = useState<ClientEventRow[]>([])
  const [loading, setLoading] = useState(false)
  const [cursor, setCursor] = useState<string | undefined>()
  const [expanded, setExpanded] = useState<string | null>(null)

  // Filters live in the URL so a shared/refreshed link keeps its context.
  const filters: ClientEventSearchParams = {
    trace_id: params.get('trace_id') ?? '',
    session_id: params.get('session_id') ?? '',
    event_name: params.get('event_name') ?? '',
    app: params.get('app') ?? '',
  }
  const setFilter = (key: keyof ClientEventSearchParams, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  const load = useCallback(
    async (before?: string) => {
      setLoading(true)
      try {
        const resp = await api.searchClientEvents({
          trace_id: params.get('trace_id') ?? undefined,
          session_id: params.get('session_id') ?? undefined,
          event_name: params.get('event_name') ?? undefined,
          app: params.get('app') ?? undefined,
          limit: PAGE_SIZE,
          before,
        })
        const data = resp.data ?? []
        setRows((prev) => (before ? [...prev, ...data] : data))
        setCursor(data.length === PAGE_SIZE ? resp.next_before_cursor : undefined)
      } catch (e) {
        toast.error(e instanceof Error ? e.message : 'client events yüklenemedi')
      } finally {
        setLoading(false)
      }
    },
    [params],
  )

  // Reload whenever the URL filters change.
  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.get('trace_id'), params.get('session_id'), params.get('event_name'), params.get('app')])

  return (
    <div className="flex h-full flex-col gap-4 p-6">
      <div className="flex items-center gap-3">
        <MousePointerClick className="h-5 w-5 text-primary" />
        <div>
          <h1 className="text-lg font-semibold">Client Events</h1>
          <p className="text-xs text-muted-foreground">
            Tarayıcı telemetrisi (RUM). trace_id ile http_logs'a bağlanır.
          </p>
        </div>
        <Button variant="outline" size="sm" className="ml-auto" onClick={() => void load()} disabled={loading}>
          <RefreshCw className={cn('mr-1 h-3.5 w-3.5', loading && 'animate-spin')} /> Yenile
        </Button>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Field label="trace_id" value={filters.trace_id ?? ''} onChange={(v) => setFilter('trace_id', v)} mono />
        <Field label="session_id" value={filters.session_id ?? ''} onChange={(v) => setFilter('session_id', v)} mono />
        <Field label="event_name" value={filters.event_name ?? ''} onChange={(v) => setFilter('event_name', v)} />
        <Field label="app" value={filters.app ?? ''} onChange={(v) => setFilter('app', v)} />
      </div>

      <div className="min-h-0 flex-1 overflow-auto rounded-md border">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-muted/60 text-xs uppercase text-muted-foreground">
            <tr>
              <th className="px-3 py-2 text-left font-medium">Zaman</th>
              <th className="px-3 py-2 text-left font-medium">Event</th>
              <th className="px-3 py-2 text-left font-medium">App</th>
              <th className="px-3 py-2 text-left font-medium">Route</th>
              <th className="px-3 py-2 text-left font-medium">Trace</th>
              <th className="px-3 py-2 text-left font-medium">Konum</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && !loading && (
              <tr>
                <td colSpan={6} className="px-3 py-10 text-center text-muted-foreground">
                  Kayıt yok. Bir host'ta RUM'u açıp tarayıcıdan event bekleyin.
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <FragmentRow
                key={r.id}
                row={r}
                expanded={expanded === r.id}
                onToggle={() => setExpanded(expanded === r.id ? null : r.id)}
                onTrace={(t) => setFilter('trace_id', t)}
              />
            ))}
          </tbody>
        </table>
      </div>

      {cursor && (
        <div className="flex justify-center">
          <Button variant="outline" size="sm" onClick={() => void load(cursor)} disabled={loading}>
            <Search className="mr-1 h-3.5 w-3.5" /> Daha fazla
          </Button>
        </div>
      )}
    </div>
  )
}

function Field({
  label, value, onChange, mono,
}: { label: string; value: string; onChange: (v: string) => void; mono?: boolean }) {
  return (
    <div className="space-y-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="—"
        className={cn('h-8', mono && 'font-mono text-xs')}
      />
    </div>
  )
}

function FragmentRow({
  row, expanded, onToggle, onTrace,
}: {
  row: ClientEventRow
  expanded: boolean
  onToggle: () => void
  onTrace: (t: string) => void
}) {
  const isErr = errorEvents.has(row.event_name)
  const loc = [row.city, row.country].filter(Boolean).join(', ')
  return (
    <>
      <tr className="cursor-pointer border-t hover:bg-muted/40" onClick={onToggle}>
        <td className="whitespace-nowrap px-3 py-2 text-xs text-muted-foreground" title={row.time}>
          {relativeTime(row.time)}
        </td>
        <td className="px-3 py-2">
          <Badge variant={isErr ? 'destructive' : 'secondary'} className="font-mono text-[11px]">
            {row.event_name}
          </Badge>
        </td>
        <td className="px-3 py-2 text-xs">{row.app || '—'}</td>
        <td className="max-w-[200px] truncate px-3 py-2 text-xs" title={row.route ?? row.url_path ?? ''}>
          {row.route || row.url_path || '—'}
        </td>
        <td className="px-3 py-2">
          {row.trace_id ? (
            <button
              className="flex items-center gap-1 font-mono text-[11px] text-primary hover:underline"
              onClick={(e) => { e.stopPropagation(); onTrace(row.trace_id!) }}
              title="Bu trace'e göre filtrele"
            >
              <Link2 className="h-3 w-3" />
              {row.trace_id.slice(0, 12)}…
            </button>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          )}
        </td>
        <td className="whitespace-nowrap px-3 py-2 text-xs text-muted-foreground">
          {loc ? (<span className="flex items-center gap-1"><MapPin className="h-3 w-3" />{loc}</span>) : '—'}
        </td>
      </tr>
      {expanded && (
        <tr className="border-t bg-muted/20">
          <td colSpan={6} className="px-3 py-3">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-3">
              <Detail label="session_id" value={row.session_id} mono />
              <Detail label="view_id" value={row.view_id} mono />
              <Detail label="span_id" value={row.span_id} mono />
              <Detail label="host" value={row.host} />
              <Detail label="client_ip" value={row.client_ip} mono />
              <Detail label="user_agent" value={row.user_agent} />
              <Detail label="client_ts" value={row.client_ts} />
              <Detail label="url_path" value={row.url_path} />
              <Detail label="release" value={row.release} />
            </dl>
            {row.attrs_json && (
              <pre className="mt-2 overflow-auto rounded bg-background p-2 text-[11px] leading-relaxed">
                {prettyJSON(row.attrs_json)}
              </pre>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

function Detail({ label, value, mono }: { label: string; value?: string; mono?: boolean }) {
  if (!value) return null
  return (
    <div className="flex flex-col">
      <dt className="text-[10px] uppercase text-muted-foreground">{label}</dt>
      <dd className={cn('break-all', mono && 'font-mono')}>{value}</dd>
    </div>
  )
}

function prettyJSON(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}
