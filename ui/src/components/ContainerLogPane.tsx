import { useEffect, useMemo, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { Pause, Play, Trash2, Filter as FilterIcon, AlignLeft } from 'lucide-react'
import * as api from '@/api'
import type { ContainerLogChunk } from '@/types'

// Local item shape that the pane renders. id stays stable across renders
// so React's reconciliation does not thrash, even when older items are
// pruned from the head of the ring buffer.
interface PaneLine {
  id: string
  ts?: string
  stream: string
  line: string
  truncated?: boolean
  synthetic?: boolean
  attrs?: Record<string, unknown>
}

interface Props {
  containerId: string
  /** Initial tail line count requested from the server. Default 200. */
  tail?: number
  /** When provided, the pane shows this label in its header instead of
   * the container_id. Useful from deployment-detail tabs that already
   * know the project/component. */
  title?: string
  /** Max lines retained in memory; older lines get pruned (still
   * recoverable via the History tab + cursor pagination). Default 5000. */
  maxLines?: number
  /** Optional dense mode — shrinks vertical padding for embedding into
   * a panel within Apps.tsx / Routes.tsx. */
  dense?: boolean
}

// ContainerLogPane renders a virtual-ish (cap + slice) live tail of one
// container. JSON-line auto-detect: lines that parse as objects render
// as expanded key/value rows. Auto-follow with pause-on-scroll-up; the
// "Pause" button forces pause regardless of scroll. Filter text is
// applied client-side against an in-memory ring.
export default function ContainerLogPane({ containerId, tail = 200, title, maxLines = 5000, dense }: Props) {
  const [lines, setLines] = useState<PaneLine[]>([])
  const [paused, setPaused] = useState(false)
  const [autoFollow, setAutoFollow] = useState(true)
  const [filter, setFilter] = useState('')
  const [streamFilter, setStreamFilter] = useState<'all' | 'stdout' | 'stderr'>('all')
  const [error, setError] = useState<string | null>(null)
  const closeRef = useRef<(() => void) | null>(null)
  const seqRef = useRef(0)
  const scrollRef = useRef<HTMLDivElement | null>(null)

  // Open the SSE stream once per containerId/tail combo. Pause/resume
  // toggles do not reopen — they just stop appending to state.
  useEffect(() => {
    setLines([])
    setError(null)
    seqRef.current = 0
    const close = api.createContainerLogStream(
      containerId,
      { tail, follow: true },
      (chunk: ContainerLogChunk) => {
        if (paused) return
        seqRef.current += 1
        const id = `${chunk.timestamp ?? ''}:${seqRef.current}`
        const next: PaneLine = {
          id,
          ts: chunk.timestamp,
          stream: chunk.stream,
          line: chunk.line,
          truncated: chunk.truncated,
          synthetic: chunk.synthetic,
        }
        // Cheap JSON probe — only when the line looks like an object.
        if (next.line && next.line.charCodeAt(0) === 123 /* { */) {
          try {
            const parsed = JSON.parse(next.line)
            if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
              next.attrs = parsed as Record<string, unknown>
            }
          } catch {
            // not JSON — leave as raw line
          }
        }
        setLines((prev) => {
          const out = prev.length >= maxLines ? prev.slice(prev.length - maxLines + 1) : prev.slice()
          out.push(next)
          return out
        })
      },
      () => setError('Live tail bağlantısı koptu — yeniden bağlanmak için tekrar açın.'),
    )
    closeRef.current = close
    return () => {
      close()
      closeRef.current = null
    }
    // We intentionally only re-open when containerId or tail changes.
    // pause/maxLines re-renders are handled by the consumer side.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [containerId, tail])

  // Auto-follow: when the user is near the bottom we scroll on every
  // append; if they scroll up we suspend follow until they scroll back.
  useEffect(() => {
    const el = scrollRef.current
    if (!el || !autoFollow) return
    el.scrollTop = el.scrollHeight
  }, [lines, autoFollow])

  function onScroll(e: React.UIEvent<HTMLDivElement>) {
    const el = e.currentTarget
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 64
    setAutoFollow(nearBottom)
  }

  const filtered = useMemo(() => {
    const term = filter.trim().toLowerCase()
    if (!term && streamFilter === 'all') return lines
    return lines.filter((l) => {
      if (streamFilter !== 'all' && l.stream !== streamFilter) return false
      if (term && !l.line.toLowerCase().includes(term)) return false
      return true
    })
  }, [lines, filter, streamFilter])

  const dropped = useMemo(() => lines.filter((l) => l.synthetic && l.line.includes('dropped')).length, [lines])
  const stdoutCount = useMemo(() => lines.filter((l) => l.stream === 'stdout').length, [lines])
  const stderrCount = useMemo(() => lines.filter((l) => l.stream === 'stderr').length, [lines])

  return (
    <div className={cn('flex flex-col rounded-lg border border-border bg-card', dense ? 'h-[480px]' : 'h-[640px]')}>
      <div className="flex items-center gap-2 border-b border-border px-3 py-2 text-xs">
        <Badge variant="outline" className="font-mono">
          {title ?? containerId.slice(0, 12)}
        </Badge>
        <span className="text-muted-foreground">
          {lines.length} satır · stdout {stdoutCount} · stderr {stderrCount}
          {dropped > 0 && <span className="text-amber-300"> · {dropped} drop</span>}
        </span>
        <div className="ml-auto flex items-center gap-2">
          <FilterIcon className="h-3.5 w-3.5 text-muted-foreground" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="filtrele…"
            className="h-7 w-44 rounded-md border border-border bg-background px-2 text-xs"
          />
          <select
            value={streamFilter}
            onChange={(e) => setStreamFilter(e.target.value as 'all' | 'stdout' | 'stderr')}
            className="h-7 rounded-md border border-border bg-background px-2 text-xs"
          >
            <option value="all">all</option>
            <option value="stdout">stdout</option>
            <option value="stderr">stderr</option>
          </select>
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2"
            onClick={() => setPaused((p) => !p)}
            title={paused ? 'Devam ettir' : 'Duraklat'}
          >
            {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2"
            onClick={() => setLines([])}
            title="Paneli temizle"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {error && (
        <div className="border-b border-amber-400/40 bg-amber-400/10 px-3 py-1 text-xs text-amber-200">
          {error}
        </div>
      )}

      <div
        ref={scrollRef}
        onScroll={onScroll}
        className="flex-1 overflow-y-auto bg-background/40 font-mono text-[11px] leading-relaxed"
      >
        {filtered.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            <AlignLeft className="mr-2 h-4 w-4" /> Henüz log yok…
          </div>
        ) : (
          filtered.map((l) => (
            <div
              key={l.id}
              className={cn(
                'whitespace-pre-wrap break-words border-b border-border/30 px-3 py-1',
                l.stream === 'stderr' && 'bg-red-400/5 text-red-200',
                l.synthetic && 'text-amber-300 italic',
              )}
            >
              {l.ts && (
                <span className="mr-2 text-muted-foreground">{shortTimestamp(l.ts)}</span>
              )}
              {l.attrs ? (
                <span>
                  {Object.entries(l.attrs).map(([k, v]) => (
                    <span key={k} className="mr-2">
                      <span className="text-blue-300">{k}</span>=<span>{String(v)}</span>
                    </span>
                  ))}
                </span>
              ) : (
                <span>{l.line}</span>
              )}
              {l.truncated && <span className="ml-2 text-muted-foreground">…(truncated)</span>}
            </div>
          ))
        )}
      </div>

      <div className="border-t border-border px-3 py-1 text-[10px] text-muted-foreground">
        {paused
          ? 'Duraklatıldı — yeni satırlar atlanıyor.'
          : autoFollow
            ? 'Auto-follow açık · son satıra bağlı.'
            : 'Yukarı kaydırdınız — auto-follow kapalı (en alta dönün).'}
      </div>
    </div>
  )
}

function shortTimestamp(iso: string): string {
  // Render just HH:MM:SS.mmm — keeps line dense but still useful for
  // burst patterns. Fall back to the raw value on parse failure.
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  const ss = String(d.getSeconds()).padStart(2, '0')
  const ms = String(d.getMilliseconds()).padStart(3, '0')
  return `${hh}:${mm}:${ss}.${ms}`
}
