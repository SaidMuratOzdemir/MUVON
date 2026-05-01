import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Globe, Plus, Pencil, Trash2, ChevronDown, ChevronRight,
  ArrowUpRight, RefreshCw, Loader2, Network, ToggleLeft, ToggleRight,
  ExternalLink,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { cn } from '@/lib/utils'
import * as api from '@/api'
import type { Host, Route } from '@/types'
import { RouteDialog, TagInput } from '@/components/RouteDialog'

// ─── Health Dot ─────────────────────────────────────────────────────────────────

function HealthDot({ state }: { state?: string }) {
  if (!state) return null
  const map: Record<string, string> = {
    closed: 'bg-green-500',
    open: 'bg-red-500',
    half_open: 'bg-yellow-500',
  }
  const color = map[state] ?? 'bg-muted'
  return (
    <span
      className={cn('h-2 w-2 rounded-full shrink-0', color)}
      title={state.replace('_', ' ')}
    />
  )
}

// ─── Host Row ───────────────────────────────────────────────────────────────────

function HostRow({
  host, onEdit, onDelete, onToggle, onViewRoutes,
}: {
  host: Host
  onEdit: () => void
  onDelete: () => void
  onToggle: () => void
  onViewRoutes: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [routes, setRoutes] = useState<Route[]>([])
  const [loadingRoutes, setLoadingRoutes] = useState(false)
  const [healthState, setHealthState] = useState<Record<string, string>>({})
  const [routeDialog, setRouteDialog] = useState<{ open: boolean; route: Route | null }>({ open: false, route: null })
  const [deleteRoute, setDeleteRoute] = useState<Route | null>(null)

  const loadRoutes = useCallback(async () => {
    setLoadingRoutes(true)
    try {
      const [r, health] = await Promise.all([
        api.listRoutesByHost(host.id),
        api.getBackendHealth().catch(() => ({})),
      ])
      setRoutes(r)
      setHealthState(health)
    } catch {
      toast.error('Failed to load routes')
    } finally {
      setLoadingRoutes(false)
    }
  }, [host.id])

  function toggleExpand() {
    if (!expanded) loadRoutes()
    setExpanded(v => !v)
  }

  async function handleDeleteRoute(route: Route) {
    try {
      await api.deleteRoute(route.id)
      toast.success('Route deleted')
      setRoutes(prev => prev.filter(r => r.id !== route.id))
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Delete failed')
    } finally {
      setDeleteRoute(null)
    }
  }

  function routeHealthState(route: Route): string | undefined {
    const url = route.backend_url
    if (!url) return undefined
    return healthState[url]
  }

  const routeTypeBadge = (t: Route['route_type']) => {
    const map = { proxy: 'default', static: 'secondary', redirect: 'outline' } as const
    return map[t]
  }

  return (
    <>
      <div className="border border-border rounded-lg bg-card overflow-hidden">
        <div className="flex items-center gap-3 px-4 py-3">
          <button
            className="text-muted-foreground hover:text-foreground cursor-pointer transition-colors"
            onClick={toggleExpand}
          >
            {expanded
              ? <ChevronDown className="h-4 w-4" />
              : <ChevronRight className="h-4 w-4" />
            }
          </button>
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
            <Globe className="h-4 w-4 text-primary" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium text-foreground font-mono">{host.domain}</span>
              <a
                href={`https://${host.domain}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-primary transition-colors cursor-pointer"
              >
                <ArrowUpRight className="h-3.5 w-3.5" />
              </a>
              {host.force_https && (
                <Badge variant="outline" className="text-[10px] text-primary border-primary/40">HTTPS</Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground">ID: {host.id}</p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={host.is_active ? 'default' : 'secondary'} className="text-xs">
              {host.is_active ? 'Active' : 'Inactive'}
            </Badge>
            <button
              onClick={onToggle}
              className="text-muted-foreground hover:text-foreground cursor-pointer transition-colors"
              title={host.is_active ? 'Disable host' : 'Enable host'}
            >
              {host.is_active
                ? <ToggleRight className="h-5 w-5 text-primary" />
                : <ToggleLeft className="h-5 w-5" />
              }
            </button>
            <Button
              variant="ghost" size="icon" className="h-8 w-8 cursor-pointer hover:text-primary"
              onClick={onViewRoutes}
              title="View all routes for this host"
            >
              <ExternalLink className="h-3.5 w-3.5" />
            </Button>
            <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer hover:text-primary" onClick={onEdit}>
              <Pencil className="h-3.5 w-3.5" />
            </Button>
            <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer hover:text-destructive" onClick={onDelete}>
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>

        {expanded && (
          <div className="border-t border-border">
            <div className="px-4 py-2 flex items-center justify-between bg-muted/20">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Routes</span>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 text-xs gap-1.5 cursor-pointer hover:text-primary"
                onClick={() => setRouteDialog({ open: true, route: null })}
              >
                <Plus className="h-3.5 w-3.5" /> Add Route
              </Button>
            </div>
            {loadingRoutes ? (
              <div className="p-4 space-y-2">
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
              </div>
            ) : routes.length === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-muted-foreground">
                No routes configured. Add one to start routing traffic.
              </div>
            ) : (
              <div className="divide-y divide-border">
                {routes.map(route => (
                  <div key={route.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-muted/10 transition-colors">
                    <div className="flex h-6 w-6 items-center justify-center rounded bg-muted/30">
                      <Network className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                    <HealthDot state={routeHealthState(route)} />
                    <span className="font-mono text-sm text-foreground flex-1 min-w-0 truncate">{route.path_prefix}</span>
                    <Badge variant={routeTypeBadge(route.route_type)} className="text-xs shrink-0">{route.route_type}</Badge>
                    {route.backend_url && (
                      <span className="text-xs text-muted-foreground font-mono hidden md:block truncate max-w-[200px]">
                        {route.backend_url}
                        {(route.backend_urls?.length ?? 0) > 0 && (
                          <span className="text-primary ml-1">+{route.backend_urls!.length}</span>
                        )}
                      </span>
                    )}
                    <span className="text-xs text-muted-foreground shrink-0">P:{route.priority}</span>
                    {route.rate_limit_rps && route.rate_limit_rps > 0 ? (
                      <Badge variant="outline" className="text-[10px] shrink-0 text-yellow-500 border-yellow-500/40">{route.rate_limit_rps}rps</Badge>
                    ) : null}
                    <Badge variant={route.is_active ? 'default' : 'secondary'} className="text-xs shrink-0">
                      {route.is_active ? 'On' : 'Off'}
                    </Badge>
                    {!route.log_enabled && (
                      <Badge variant="outline" className="text-xs shrink-0 text-muted-foreground">no-log</Badge>
                    )}
                    {route.waf_enabled && (
                      <Badge variant="outline" className="text-xs shrink-0 text-primary border-primary/40">WAF</Badge>
                    )}
                    <div className="flex items-center gap-1 shrink-0">
                      <Button
                        variant="ghost" size="icon" className="h-7 w-7 cursor-pointer hover:text-primary"
                        onClick={() => setRouteDialog({ open: true, route })}
                      >
                        <Pencil className="h-3 w-3" />
                      </Button>
                      <Button
                        variant="ghost" size="icon" className="h-7 w-7 cursor-pointer hover:text-destructive"
                        onClick={() => setDeleteRoute(route)}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <RouteDialog
        open={routeDialog.open}
        onClose={() => setRouteDialog({ open: false, route: null })}
        hostId={host.id}
        route={routeDialog.route}
        onSaved={loadRoutes}
      />

      <AlertDialog open={!!deleteRoute} onOpenChange={v => !v && setDeleteRoute(null)}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Route</AlertDialogTitle>
            <AlertDialogDescription>
              Delete route <code className="font-mono text-foreground">{deleteRoute?.path_prefix}</code>? This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer border-border">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90 cursor-pointer"
              onClick={() => deleteRoute && handleDeleteRoute(deleteRoute)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── Main Page ──────────────────────────────────────────────────────────────────

export default function Hosts() {
  const navigate = useNavigate()
  const [hosts, setHosts] = useState<Host[]>([])
  const [loading, setLoading] = useState(true)
  const [hostDialog, setHostDialog] = useState<{ open: boolean; host: Host | null }>({ open: false, host: null })
  const [deleteTarget, setDeleteTarget] = useState<Host | null>(null)
  // jwt_secret stays empty on edit — backend reads empty as "keep existing"
  // so we never have to round-trip ciphertext. `jwt_secret_set` mirrors
  // whether the saved row has a secret so the form can show "********"
  // instead of a blank field when the admin is reviewing an existing host.
  const [hostForm, setHostForm] = useState({
    domain: '',
    is_active: true,
    force_https: false,
    trusted_proxies: [] as string[],
    jwt_identity_enabled: false,
    jwt_identity_mode: 'verify',
    jwt_claims: '',
    jwt_secret: '',
    jwt_secret_set: false,
    identity_header_name: '',
    store_raw_jwt: false,
  })
  const [saving, setSaving] = useState(false)
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setHosts(await api.listHosts())
    } catch {
      toast.error('Failed to load hosts')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function openAddHost() {
    setHostForm({
      domain: '', is_active: true, force_https: false, trusted_proxies: [],
      jwt_identity_enabled: false, jwt_identity_mode: 'verify', jwt_claims: '',
      jwt_secret: '', jwt_secret_set: false, identity_header_name: '',
      store_raw_jwt: false,
    })
    setHostDialog({ open: true, host: null })
  }

  function openEditHost(h: Host) {
    setHostForm({
      domain: h.domain,
      is_active: h.is_active,
      force_https: h.force_https ?? false,
      trusted_proxies: h.trusted_proxies ?? [],
      jwt_identity_enabled: h.jwt_identity_enabled ?? false,
      jwt_identity_mode: h.jwt_identity_mode || 'verify',
      jwt_claims: h.jwt_claims || '',
      jwt_secret: '',
      // Backend masks the ciphertext as "********" when a secret is set;
      // the UI shows a "secret is set" hint instead of a blank field.
      jwt_secret_set: typeof h.jwt_secret === 'string' && h.jwt_secret !== '',
      identity_header_name: h.identity_header_name || '',
      store_raw_jwt: h.store_raw_jwt ?? false,
    })
    setHostDialog({ open: true, host: h })
  }

  async function handleSaveHost() {
    if (!hostForm.domain) { toast.error('Domain is required'); return }
    setSaving(true)
    try {
      // jwt_secret_set is a UI-only flag; strip before sending. Empty
      // jwt_secret tells the backend "keep the existing ciphertext".
      const { jwt_secret_set: _unused, ...payload } = hostForm
      void _unused
      if (hostDialog.host) {
        await api.updateHost(hostDialog.host.id, payload)
        toast.success('Host updated')
      } else {
        await api.createHost(payload)
        toast.success('Host created')
      }
      await load()
      setHostDialog({ open: false, host: null })
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  async function handleDeleteHost(h: Host) {
    try {
      await api.deleteHost(h.id)
      toast.success('Host deleted')
      setHosts(prev => prev.filter(x => x.id !== h.id))
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Delete failed')
    } finally {
      setDeleteTarget(null)
    }
  }

  async function handleToggleHost(h: Host) {
    try {
      const updated = await api.updateHost(h.id, { is_active: !h.is_active })
      setHosts(prev => prev.map(x => x.id === h.id ? updated : x))
      toast.success(updated.is_active ? 'Host enabled' : 'Host disabled')
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Toggle failed')
    }
  }

  const filtered = hosts.filter(h =>
    h.domain.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">Hosts &amp; Routes</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{hosts.length} host{hosts.length !== 1 ? 's' : ''} configured</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon" onClick={load} className="h-9 w-9 cursor-pointer border-border">
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </Button>
          <Button onClick={openAddHost} className="gap-2 cursor-pointer">
            <Plus className="h-4 w-4" /> Add Host
          </Button>
        </div>
      </div>

      {/* Search */}
      <Input
        placeholder="Search hosts…"
        className="max-w-sm bg-card border-border"
        value={search}
        onChange={e => setSearch(e.target.value)}
      />

      {/* List */}
      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3].map(i => <Skeleton key={i} className="h-16 w-full rounded-lg" />)}
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <Globe className="h-12 w-12 text-muted-foreground/30 mb-4" />
          <p className="text-muted-foreground">
            {search ? 'No hosts match your search' : 'No hosts configured yet'}
          </p>
          {!search && (
            <Button onClick={openAddHost} className="mt-4 gap-2 cursor-pointer" variant="outline">
              <Plus className="h-4 w-4" /> Add your first host
            </Button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(h => (
            <HostRow
              key={h.id}
              host={h}
              onEdit={() => openEditHost(h)}
              onDelete={() => setDeleteTarget(h)}
              onToggle={() => handleToggleHost(h)}
              onViewRoutes={() => navigate(`/routes?host=${encodeURIComponent(h.domain)}`)}
            />
          ))}
        </div>
      )}

      {/* Host Dialog */}
      <Dialog open={hostDialog.open} onOpenChange={v => !v && setHostDialog({ open: false, host: null })}>
        <DialogContent className="bg-card border-border">
          <DialogHeader>
            <DialogTitle>{hostDialog.host ? 'Edit Host' : 'Add Host'}</DialogTitle>
            <DialogDescription>Configure a virtual host for the reverse proxy</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label>Domain</Label>
              <Input
                placeholder="example.com"
                className="bg-background border-border font-mono"
                value={hostForm.domain}
                onChange={e => setHostForm(f => ({ ...f, domain: e.target.value }))}
              />
            </div>
            <div className="flex items-center justify-between rounded-md border border-border px-4 py-3">
              <div>
                <p className="text-sm font-medium">Active</p>
                <p className="text-xs text-muted-foreground">Accept traffic for this host</p>
              </div>
              <Switch
                checked={hostForm.is_active}
                onCheckedChange={v => setHostForm(f => ({ ...f, is_active: v }))}
                className="cursor-pointer"
              />
            </div>
            <div className="flex items-center justify-between rounded-md border border-border px-4 py-3">
              <div>
                <p className="text-sm font-medium">Force HTTPS</p>
                <p className="text-xs text-muted-foreground">Redirect all HTTP requests to HTTPS (301)</p>
              </div>
              <Switch
                checked={hostForm.force_https}
                onCheckedChange={v => setHostForm(f => ({ ...f, force_https: v }))}
                className="cursor-pointer"
              />
            </div>
            <TagInput
              label="Trusted Proxy IPs / CIDRs"
              values={hostForm.trusted_proxies}
              onChange={v => setHostForm(f => ({ ...f, trusted_proxies: v }))}
              placeholder="10.0.0.0/8 or 192.168.1.1"
            />

            {/* JWT Identity override — per-host so one MUVON can front
                multiple tenant apps with different signing secrets. When
                the toggle is off, the global Settings → JWT Identity rules
                apply to this host's requests. */}
            <div className="rounded-md border border-border divide-y divide-border">
              <div className="flex items-center justify-between px-4 py-3">
                <div>
                  <p className="text-sm font-medium">JWT Identity override</p>
                  <p className="text-xs text-muted-foreground">
                    Use this host's own claims + secret. Off → fall back to global Settings.
                  </p>
                </div>
                <Switch
                  checked={hostForm.jwt_identity_enabled}
                  onCheckedChange={v => setHostForm(f => ({ ...f, jwt_identity_enabled: v }))}
                  className="cursor-pointer"
                />
              </div>
              {hostForm.jwt_identity_enabled && (
                <>
                  <div className="px-4 py-3 space-y-1">
                    <Label className="text-xs">Claims (comma-separated)</Label>
                    <Input
                      placeholder="sub,email,name,role,holding_id"
                      className="bg-background border-border font-mono text-xs"
                      value={hostForm.jwt_claims}
                      onChange={e => setHostForm(f => ({ ...f, jwt_claims: e.target.value }))}
                    />
                    <p className="text-[11px] text-muted-foreground">
                      Keys extracted from the JWT payload. Leave empty to inherit the
                      global list.
                    </p>
                  </div>
                  <div className="px-4 py-3 space-y-1">
                    <Label className="text-xs">
                      HS256 Secret
                      {hostForm.jwt_secret_set && !hostForm.jwt_secret && (
                        <span className="ml-2 text-emerald-400 text-[11px]">(already set — type to rotate)</span>
                      )}
                    </Label>
                    <Input
                      type="password"
                      placeholder={hostForm.jwt_secret_set ? '••••••••  (leave blank to keep)' : 'Enter secret or leave blank for decode-only'}
                      className="bg-background border-border font-mono text-xs"
                      value={hostForm.jwt_secret}
                      onChange={e => setHostForm(f => ({ ...f, jwt_secret: e.target.value }))}
                      autoComplete="off"
                    />
                    <p className="text-[11px] text-muted-foreground">
                      With a secret: signatures are verified. Without: claims are
                      still decoded but marked "not verified" — useful when you
                      front multiple tenants with different secrets.
                    </p>
                  </div>
                  <div className="px-4 py-3 space-y-1">
                    <Label className="text-xs">Identity header</Label>
                    <Input
                      placeholder="Authorization"
                      className="bg-background border-border font-mono text-xs"
                      value={hostForm.identity_header_name}
                      onChange={e => setHostForm(f => ({ ...f, identity_header_name: e.target.value }))}
                    />
                    <p className="text-[11px] text-muted-foreground">
                      Header to read the bearer token from. Default
                      <code className="font-mono px-1">Authorization</code>. Use
                      <code className="font-mono px-1">X-Auth-Token</code> for hosts
                      that don't follow RFC 6750, or
                      <code className="font-mono px-1">Cookie:session</code> to pull
                      the token from a named cookie.
                    </p>
                  </div>
                  <div className="flex items-start justify-between px-4 py-3 gap-3">
                    <div className="min-w-0">
                      <p className="text-xs font-medium">Store raw token alongside logs</p>
                      <p className="text-[11px] text-muted-foreground mt-0.5">
                        Persists the original signed JWT in <code className="font-mono">http_logs.raw_jwt</code> so support
                        flows can replay or decode it. Each reveal is audit-logged.
                        Off by default — only turn on for hosts where this is
                        explicitly accepted, since the column carries valid
                        credentials until they expire.
                      </p>
                    </div>
                    <Switch
                      checked={hostForm.store_raw_jwt}
                      onCheckedChange={v => setHostForm(f => ({ ...f, store_raw_jwt: v }))}
                      className="cursor-pointer"
                    />
                  </div>
                </>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setHostDialog({ open: false, host: null })} className="cursor-pointer border-border">
              Cancel
            </Button>
            <Button onClick={handleSaveHost} disabled={saving} className="cursor-pointer">
              {saving && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
              {hostDialog.host ? 'Update Host' : 'Create Host'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Host Dialog */}
      <AlertDialog open={!!deleteTarget} onOpenChange={v => !v && setDeleteTarget(null)}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Host</AlertDialogTitle>
            <AlertDialogDescription>
              Delete <code className="font-mono text-foreground">{deleteTarget?.domain}</code> and all its routes? This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer border-border">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90 cursor-pointer"
              onClick={() => deleteTarget && handleDeleteHost(deleteTarget)}
            >
              Delete Host
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
