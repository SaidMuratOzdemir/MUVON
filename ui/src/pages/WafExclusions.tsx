import { useState, useEffect, useCallback, useMemo } from 'react'
import { ShieldOff, Plus, Trash2, RefreshCw, Filter } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { EmptyState } from '@/components/EmptyState'
import { cn } from '@/lib/utils'
import * as api from '@/api'
import type { WafExclusion, WafRule, Route, Host } from '@/types'

// Full mapping per muWAF: exclusion "location" narrows which part of the
// request the excluded parameter lives in. "all" is the broad default.
const LOCATIONS = [
  { value: 'all', label: 'All (any location)' },
  { value: 'header', label: 'Headers' },
  { value: 'query', label: 'Query string' },
  { value: 'body', label: 'Request body' },
  { value: 'cookie', label: 'Cookies' },
  { value: 'path', label: 'Path' },
]

type RouteWithHost = Route & { host: Host }

export default function WafExclusions() {
  const [exclusions, setExclusions] = useState<WafExclusion[]>([])
  const [rules, setRules] = useState<WafRule[]>([])
  const [routes, setRoutes] = useState<RouteWithHost[]>([])
  const [loading, setLoading] = useState(true)

  const [ruleFilter, setRuleFilter] = useState<string>('all')
  const [routeFilter, setRouteFilter] = useState<string>('all')

  const [createOpen, setCreateOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<WafExclusion | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [ex, ru, hosts] = await Promise.all([
        api.listWafExclusions(),
        api.listWafRules(),
        api.listHosts(),
      ])
      setExclusions(ex ?? [])
      setRules(ru ?? [])
      const allRoutes: RouteWithHost[] = []
      for (const h of hosts ?? []) {
        const hostRoutes = await api.listRoutesByHost(h.id)
        for (const r of hostRoutes ?? []) {
          allRoutes.push({ ...r, host: h })
        }
      }
      setRoutes(allRoutes)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Failed to load exclusions')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const rulesById = useMemo(
    () => new Map(rules.map(r => [r.id, r])),
    [rules],
  )
  const routesById = useMemo(
    () => new Map(routes.map(r => [r.id, r])),
    [routes],
  )

  const filtered = useMemo(() => {
    return exclusions.filter(e => {
      if (ruleFilter !== 'all' && e.rule_id !== Number(ruleFilter)) return false
      if (routeFilter !== 'all' && e.route_id !== Number(routeFilter)) return false
      return true
    })
  }, [exclusions, ruleFilter, routeFilter])

  async function handleDelete() {
    if (!deleteTarget) return
    try {
      await api.deleteWafExclusion(deleteTarget.id)
      setExclusions(cur => cur.filter(x => x.id !== deleteTarget.id))
      toast.success('Exclusion deleted')
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Failed to delete')
    } finally {
      setDeleteTarget(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground tracking-tight flex items-center gap-2">
            <ShieldOff className="h-6 w-6 text-primary" />
            WAF Exclusions
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Per-route exemptions from a given WAF rule. Use sparingly — each exclusion is a way around a check.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
            Refresh
          </Button>
          <Button size="sm" className="cursor-pointer" onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Add Exclusion
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card className="border-border bg-card">
        <CardContent className="p-4 flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <Label className="text-xs text-muted-foreground mb-1.5 flex items-center gap-1">
              <Filter className="h-3 w-3" />
              Rule
            </Label>
            <Select value={ruleFilter} onValueChange={setRuleFilter}>
              <SelectTrigger className="bg-background border-border cursor-pointer">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All rules</SelectItem>
                {rules.map(r => (
                  <SelectItem key={r.id} value={String(r.id)}>
                    #{r.id} · {r.description || r.pattern.slice(0, 40)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex-1">
            <Label className="text-xs text-muted-foreground mb-1.5 flex items-center gap-1">
              <Filter className="h-3 w-3" />
              Route
            </Label>
            <Select value={routeFilter} onValueChange={setRouteFilter}>
              <SelectTrigger className="bg-background border-border cursor-pointer">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All routes</SelectItem>
                {routes.map(r => (
                  <SelectItem key={r.id} value={String(r.id)}>
                    {r.host.domain}{r.path_prefix}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      <Card className="border-border bg-card">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-border">
                  <TableHead className="text-xs w-[80px]">ID</TableHead>
                  <TableHead className="text-xs">Rule</TableHead>
                  <TableHead className="text-xs">Route</TableHead>
                  <TableHead className="text-xs w-[120px]">Location</TableHead>
                  <TableHead className="text-xs">Parameter</TableHead>
                  <TableHead className="text-xs w-[80px] text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {!loading && filtered.length === 0 && (
                  <TableRow className="border-border"><TableCell colSpan={6}>
                    <EmptyState
                      icon={ShieldOff}
                      title="No exclusions"
                      description="Exclusions let a rule skip a specific route+parameter combination. Add one when a legitimate payload trips a rule."
                    />
                  </TableCell></TableRow>
                )}
                {filtered.map(e => {
                  const rule = rulesById.get(e.rule_id)
                  const route = routesById.get(e.route_id)
                  return (
                    <TableRow key={e.id} className="border-border">
                      <TableCell className="font-mono text-xs text-muted-foreground">{e.id}</TableCell>
                      <TableCell className="text-sm">
                        <div className="font-medium">#{e.rule_id}</div>
                        <div className="text-xs text-muted-foreground truncate max-w-[320px]">
                          {rule?.description || rule?.pattern || 'unknown rule'}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">
                        {route ? (
                          <span className="font-mono">{route.host.domain}{route.path_prefix}</span>
                        ) : (
                          <span className="text-muted-foreground text-xs">#{e.route_id} (deleted)</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs">{e.location || 'all'}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{e.parameter || <span className="text-muted-foreground italic">any</span>}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost" size="icon"
                          className="h-8 w-8 cursor-pointer hover:text-red-400"
                          onClick={() => setDeleteTarget(e)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <CreateExclusionDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        rules={rules}
        routes={routes}
        onCreated={(e) => {
          setExclusions(cur => [e, ...cur])
          setCreateOpen(false)
        }}
      />

      <AlertDialog open={!!deleteTarget} onOpenChange={v => !v && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete exclusion?</AlertDialogTitle>
            <AlertDialogDescription>
              The rule will apply to this route again. If the payload that triggered it comes back, it will be blocked.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function CreateExclusionDialog({
  open, onClose, rules, routes, onCreated,
}: {
  open: boolean
  onClose: () => void
  rules: WafRule[]
  routes: RouteWithHost[]
  onCreated: (e: WafExclusion) => void
}) {
  const [ruleId, setRuleId] = useState('')
  const [routeId, setRouteId] = useState('')
  const [location, setLocation] = useState('all')
  const [parameter, setParameter] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (open) {
      setRuleId('')
      setRouteId('')
      setLocation('all')
      setParameter('')
    }
  }, [open])

  async function handleSubmit() {
    if (!ruleId || !routeId) {
      toast.error('Select both a rule and a route')
      return
    }
    setSaving(true)
    try {
      const ex = await api.createWafExclusion({
        rule_id: Number(ruleId),
        route_id: Number(routeId),
        location,
        parameter,
      })
      toast.success('Exclusion created')
      onCreated(ex)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Failed to create exclusion')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={v => !v && onClose()}>
      <DialogContent className="bg-card border-border">
        <DialogHeader>
          <DialogTitle>New WAF Exclusion</DialogTitle>
          <DialogDescription>
            Skip a specific WAF rule for a specific route. Narrow with location + parameter when possible.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div>
            <Label className="text-xs text-muted-foreground mb-1.5">Rule</Label>
            <Select value={ruleId} onValueChange={setRuleId}>
              <SelectTrigger className="bg-background border-border cursor-pointer">
                <SelectValue placeholder="Pick a rule…" />
              </SelectTrigger>
              <SelectContent>
                {rules.map(r => (
                  <SelectItem key={r.id} value={String(r.id)}>
                    #{r.id} · {r.category} · {r.description || r.pattern.slice(0, 40)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs text-muted-foreground mb-1.5">Route</Label>
            <Select value={routeId} onValueChange={setRouteId}>
              <SelectTrigger className="bg-background border-border cursor-pointer">
                <SelectValue placeholder="Pick a route…" />
              </SelectTrigger>
              <SelectContent>
                {routes.map(r => (
                  <SelectItem key={r.id} value={String(r.id)}>
                    {r.host.domain}{r.path_prefix}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs text-muted-foreground mb-1.5">Location</Label>
            <Select value={location} onValueChange={setLocation}>
              <SelectTrigger className="bg-background border-border cursor-pointer">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LOCATIONS.map(l => (
                  <SelectItem key={l.value} value={l.value}>{l.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs text-muted-foreground mb-1.5">Parameter</Label>
            <Input
              value={parameter}
              onChange={e => setParameter(e.target.value)}
              placeholder="e.g. content, password — leave empty to match any"
              className="bg-background border-border font-mono text-sm"
            />
            <p className="text-xs text-muted-foreground mt-1">
              Optional. Narrows the exclusion to a specific field inside the chosen location.
            </p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={saving}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={saving}>
            {saving ? 'Creating…' : 'Create'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
