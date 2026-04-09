import { useState, useEffect, useCallback } from 'react'
import {
  ChevronDown, ChevronRight, ChevronLeft, RefreshCw, Filter, X,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { cn, relativeTime } from '@/lib/utils'
import * as api from '@/api'
import type { AuditEntry } from '@/types'

const PAGE_SIZE = 50

function actionBadgeVariant(action: string): 'default' | 'destructive' | 'secondary' | 'outline' {
  if (action.endsWith('.delete')) return 'destructive'
  if (action.endsWith('.create')) return 'default'
  if (action.endsWith('.update')) return 'secondary'
  return 'outline'
}

function AuditRow({ entry }: { entry: AuditEntry }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="border-b border-border/50 last:border-0">
      <div
        className="grid grid-cols-[140px_120px_180px_160px_1fr_32px] gap-2 px-4 py-2 hover:bg-muted/10 cursor-pointer transition-colors items-center"
        onClick={() => setExpanded(v => !v)}
      >
        <span className="text-xs font-mono text-muted-foreground truncate" title={new Date(entry.timestamp).toLocaleString()}>
          {relativeTime(entry.timestamp)}
        </span>
        <span className="text-xs font-mono text-foreground truncate">{entry.admin_user}</span>
        <span>
          <Badge variant={actionBadgeVariant(entry.action)} className="text-[11px] font-mono">
            {entry.action}
          </Badge>
        </span>
        <span className="text-xs text-muted-foreground font-mono truncate">
          {entry.target_type && entry.target_id ? `${entry.target_type}/${entry.target_id}` : entry.target_type ?? '—'}
        </span>
        <span className="text-xs text-muted-foreground font-mono truncate">{entry.ip ?? '—'}</span>
        <span className="text-muted-foreground">
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </span>
      </div>
      {expanded && entry.detail != null && (
        <div className="px-4 pb-3">
          <pre className="rounded-md bg-background border border-border px-3 py-2 text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap break-all">
            {JSON.stringify(entry.detail as Record<string, unknown>, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(false)
  const [showFilters, setShowFilters] = useState(false)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [action, setAction] = useState('')
  const [appliedFilters, setAppliedFilters] = useState({ from: '', to: '', action: '' })

  const load = useCallback(async (filters: typeof appliedFilters, off: number) => {
    setLoading(true)
    try {
      const res = await api.listAuditLog({
        limit: PAGE_SIZE,
        offset: off,
        from: filters.from || undefined,
        to: filters.to || undefined,
        action: filters.action || undefined,
      })
      setEntries(res.data)
      setTotal(res.total)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Failed to load audit log')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(appliedFilters, offset)
  }, [appliedFilters, offset, load])

  function applyFilters() {
    setAppliedFilters({ from, to, action })
    setOffset(0)
    setShowFilters(false)
  }

  function clearFilters() {
    setFrom('')
    setTo('')
    setAction('')
    setAppliedFilters({ from: '', to: '', action: '' })
    setOffset(0)
  }

  const hasActive = appliedFilters.from || appliedFilters.to || appliedFilters.action
  const totalPages = Math.ceil(total / PAGE_SIZE)
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-6 py-3 border-b border-border shrink-0">
        <h1 className="text-base font-semibold text-foreground">Audit Log</h1>
        <div className="flex-1" />
        <Button
          variant={showFilters ? 'default' : 'outline'}
          size="sm"
          className="gap-2 cursor-pointer border-border"
          onClick={() => setShowFilters(v => !v)}
        >
          <Filter className="h-3.5 w-3.5" />
          Filters
          {hasActive && (
            <span className="flex h-4 w-4 items-center justify-center rounded-full bg-primary text-primary-foreground text-[10px] font-bold">!</span>
          )}
        </Button>
        {hasActive && (
          <Button variant="ghost" size="sm" onClick={clearFilters} className="gap-1.5 cursor-pointer text-muted-foreground hover:text-foreground">
            <X className="h-3.5 w-3.5" /> Clear
          </Button>
        )}
        <Button
          variant="outline"
          size="icon"
          className={cn('h-9 w-9 cursor-pointer border-border', loading && 'opacity-50')}
          onClick={() => load(appliedFilters, offset)}
          disabled={loading}
        >
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
        </Button>
        <div className="text-xs text-muted-foreground">{total.toLocaleString()} entries</div>
      </div>

      {/* Filter panel */}
      {showFilters && (
        <div className="border-b border-border bg-card/50 px-6 py-4 shrink-0">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Action contains</Label>
              <Input
                placeholder="host.create"
                className="h-8 text-xs bg-background border-border font-mono"
                value={action}
                onChange={e => setAction(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">From</Label>
              <Input type="datetime-local" className="h-8 text-xs bg-background border-border" value={from} onChange={e => setFrom(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">To</Label>
              <Input type="datetime-local" className="h-8 text-xs bg-background border-border" value={to} onChange={e => setTo(e.target.value)} />
            </div>
          </div>
          <div className="flex gap-2 mt-3">
            <Button size="sm" onClick={applyFilters} className="cursor-pointer">Apply</Button>
            <Button size="sm" variant="outline" onClick={clearFilters} className="cursor-pointer border-border">Clear</Button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="flex-1 overflow-hidden">
        <div className="h-full overflow-auto">
          <div className="sticky top-0 z-10 bg-card border-b border-border">
            <div className="grid grid-cols-[140px_120px_180px_160px_1fr_32px] gap-2 px-4 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              <span>Time</span>
              <span>User</span>
              <span>Action</span>
              <span>Target</span>
              <span>IP</span>
              <span />
            </div>
          </div>

          {loading && entries.length === 0 ? (
            <div className="p-4 space-y-1">
              {Array.from({ length: 12 }, (_, i) => (
                <Skeleton key={i} className="h-9 w-full rounded-sm" />
              ))}
            </div>
          ) : entries.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <p className="text-muted-foreground">No audit entries found</p>
            </div>
          ) : (
            <div>
              {entries.map(e => <AuditRow key={e.id} entry={e} />)}
            </div>
          )}
        </div>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between px-6 py-3 border-t border-border shrink-0">
        <span className="text-xs text-muted-foreground">
          Page {currentPage} of {totalPages || 1} &bull; {total} total
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
    </div>
  )
}
