import { useEffect, useState, useCallback } from 'react'
import {
  Network, Plus, Pencil, Trash2, RefreshCw, Search,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { cn } from '@/lib/utils'
import * as api from '@/api'
import type { Host, Route } from '@/types'
import { RouteDialog } from '@/components/RouteDialog'

interface RouteWithHost extends Route {
  hostDomain: string
}

export default function Routes() {
  const [hosts, setHosts] = useState<Host[]>([])
  const [routes, setRoutes] = useState<RouteWithHost[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [hostFilter, setHostFilter] = useState('all')
  const [routeDialog, setRouteDialog] = useState<{ open: boolean; route: Route | null; hostId: number }>({
    open: false, route: null, hostId: 0,
  })
  const [deleteTarget, setDeleteTarget] = useState<RouteWithHost | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const hostList = await api.listHosts()
      setHosts(hostList)
      const routeGroups = await Promise.all(
        hostList.map(h => api.listRoutesByHost(h.id).then(rs => rs.map(r => ({ ...r, hostDomain: h.domain }))))
      )
      setRoutes(routeGroups.flat().sort((a, b) => a.hostDomain.localeCompare(b.hostDomain) || a.path_prefix.localeCompare(b.path_prefix)))
    } catch {
      toast.error('Failed to load routes')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleDelete() {
    if (!deleteTarget) return
    try {
      await api.deleteRoute(deleteTarget.id)
      toast.success('Route deleted')
      setRoutes(prev => prev.filter(r => r.id !== deleteTarget.id))
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Delete failed')
    } finally {
      setDeleteTarget(null)
    }
  }

  const filtered = routes.filter(r => {
    const matchHost = hostFilter === 'all' || r.hostDomain === hostFilter
    const matchSearch = search === '' ||
      r.path_prefix.toLowerCase().includes(search.toLowerCase()) ||
      r.hostDomain.toLowerCase().includes(search.toLowerCase()) ||
      (r.backend_url ?? '').toLowerCase().includes(search.toLowerCase())
    return matchHost && matchSearch
  })

  const routeTypeBadge = (t: Route['route_type']) => {
    const map = { proxy: 'default', static: 'secondary', redirect: 'outline' } as const
    return map[t]
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">Routes</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{routes.length} route{routes.length !== 1 ? 's' : ''} across {hosts.length} host{hosts.length !== 1 ? 's' : ''}</p>
        </div>
        <Button variant="outline" size="icon" onClick={load} className="h-9 w-9 cursor-pointer border-border">
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
        </Button>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Search routes…"
            className="pl-9 bg-card border-border"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <Select value={hostFilter} onValueChange={setHostFilter}>
          <SelectTrigger className="w-[220px] bg-card border-border cursor-pointer">
            <SelectValue placeholder="All hosts" />
          </SelectTrigger>
          <SelectContent className="bg-card border-border">
            <SelectItem value="all" className="cursor-pointer">All hosts</SelectItem>
            {hosts.map(h => (
              <SelectItem key={h.id} value={h.domain} className="cursor-pointer font-mono text-xs">{h.domain}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      {loading ? (
        <div className="space-y-2">
          {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-12 w-full rounded-lg" />)}
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <Network className="h-12 w-12 text-muted-foreground/30 mb-4" />
          <p className="text-muted-foreground">
            {search || hostFilter !== 'all' ? 'No routes match your filters' : 'No routes configured yet'}
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[1fr_auto_auto_auto_auto_auto_auto_auto] gap-x-4 px-4 py-2 bg-muted/20 border-b border-border text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            <span>Path</span>
            <span>Host</span>
            <span>Type</span>
            <span className="hidden md:block">Backend</span>
            <span>WAF</span>
            <span>Rate</span>
            <span>Status</span>
            <span></span>
          </div>

          <div className="divide-y divide-border">
            {filtered.map(route => (
              <div
                key={route.id}
                className="grid grid-cols-[1fr_auto_auto_auto_auto_auto_auto_auto] gap-x-4 items-center px-4 py-2.5 hover:bg-muted/10 transition-colors"
              >
                <span className="font-mono text-sm text-foreground truncate">{route.path_prefix}</span>
                <span className="text-xs font-mono text-muted-foreground truncate max-w-[140px]">{route.hostDomain}</span>
                <Badge variant={routeTypeBadge(route.route_type)} className="text-xs">{route.route_type}</Badge>
                <span className="text-xs text-muted-foreground font-mono hidden md:block truncate max-w-[180px]">
                  {route.backend_url ?? (route.static_root ?? route.redirect_url ?? '—')}
                  {(route.backend_urls?.length ?? 0) > 0 && (
                    <span className="text-primary ml-1">+{route.backend_urls!.length}</span>
                  )}
                </span>
                <span>
                  {route.waf_enabled
                    ? <Badge variant="outline" className="text-[10px] text-primary border-primary/40">WAF</Badge>
                    : <span className="text-xs text-muted-foreground/40">—</span>}
                </span>
                <span>
                  {route.rate_limit_rps && route.rate_limit_rps > 0
                    ? <Badge variant="outline" className="text-[10px] text-yellow-500 border-yellow-500/40">{route.rate_limit_rps}rps</Badge>
                    : <span className="text-xs text-muted-foreground/40">—</span>}
                </span>
                <Badge variant={route.is_active ? 'default' : 'secondary'} className="text-xs">
                  {route.is_active ? 'On' : 'Off'}
                </Badge>
                <div className="flex items-center gap-1">
                  <Button
                    variant="ghost" size="icon" className="h-7 w-7 cursor-pointer hover:text-primary"
                    onClick={() => setRouteDialog({ open: true, route, hostId: route.host_id })}
                  >
                    <Pencil className="h-3 w-3" />
                  </Button>
                  <Button
                    variant="ghost" size="icon" className="h-7 w-7 cursor-pointer hover:text-destructive"
                    onClick={() => setDeleteTarget(route)}
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Add route button — only when a host filter is active */}
      {hostFilter !== 'all' && (() => {
        const host = hosts.find(h => h.domain === hostFilter)
        if (!host) return null
        return (
          <Button
            onClick={() => setRouteDialog({ open: true, route: null, hostId: host.id })}
            variant="outline"
            className="gap-2 cursor-pointer"
          >
            <Plus className="h-4 w-4" />
            Add Route to {host.domain}
          </Button>
        )
      })()}

      <RouteDialog
        open={routeDialog.open}
        onClose={() => setRouteDialog(s => ({ ...s, open: false, route: null }))}
        hostId={routeDialog.hostId}
        route={routeDialog.route}
        onSaved={load}
      />

      <AlertDialog open={!!deleteTarget} onOpenChange={v => !v && setDeleteTarget(null)}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Route</AlertDialogTitle>
            <AlertDialogDescription>
              Delete route <code className="font-mono text-foreground">{deleteTarget?.path_prefix}</code> on <code className="font-mono">{deleteTarget?.hostDomain}</code>? This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer border-border">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90 cursor-pointer"
              onClick={handleDelete}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
