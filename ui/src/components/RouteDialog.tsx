import { useState, useEffect } from 'react'
import {
  ChevronDown, ChevronRight, X, Eye, EyeOff, Loader2, Plus, Server,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import * as api from '@/api'
import type { Route, DeployComponent } from '@/types'

// ─── Header KV Editor ──────────────────────────────────────────────────────────

export function HeaderKVEditor({
  label, value, onChange,
}: {
  label: string
  value: Record<string, string>
  onChange: (v: Record<string, string>) => void
}) {
  const entries = Object.entries(value ?? {})

  function update(idx: number, k: string, v: string) {
    const next = [...entries]
    next[idx] = [k, v]
    onChange(Object.fromEntries(next.filter(([key]) => key !== '')))
  }

  function remove(idx: number) {
    const next = entries.filter((_, i) => i !== idx)
    onChange(Object.fromEntries(next))
  }

  function add() {
    onChange({ ...value, '': '' })
  }

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <Label className="text-xs">{label}</Label>
        <Button variant="ghost" size="sm" className="h-6 text-xs cursor-pointer gap-1" onClick={add}>
          <Plus className="h-3 w-3" /> Add
        </Button>
      </div>
      {entries.length === 0 ? (
        <p className="text-xs text-muted-foreground italic">None</p>
      ) : (
        <div className="space-y-1">
          {entries.map(([k, v], i) => (
            <div key={i} className="flex gap-1.5 items-center">
              <Input
                className="h-7 text-xs bg-background border-border font-mono flex-1"
                placeholder="Header-Name"
                value={k}
                onChange={e => update(i, e.target.value, v)}
              />
              <Input
                className="h-7 text-xs bg-background border-border font-mono flex-1"
                placeholder="value"
                value={v}
                onChange={e => update(i, k, e.target.value)}
              />
              <Button variant="ghost" size="icon" className="h-7 w-7 cursor-pointer hover:text-destructive shrink-0" onClick={() => remove(i)}>
                <X className="h-3 w-3" />
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Tag Input ─────────────────────────────────────────────────────────────────

export function TagInput({
  label, values, onChange, placeholder, hint,
}: {
  label: string
  values: string[]
  onChange: (v: string[]) => void
  placeholder?: string
  hint?: string
}) {
  const [input, setInput] = useState('')

  function add() {
    const v = input.trim()
    if (v && !values.includes(v)) onChange([...values, v])
    setInput('')
  }

  return (
    <div className="space-y-1.5">
      <Label className="text-xs">{label}</Label>
      <div className="flex gap-1.5">
        <Input
          className="h-7 text-xs bg-background border-border font-mono flex-1"
          placeholder={placeholder ?? 'value'}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add() } }}
        />
        <Button variant="outline" size="sm" className="h-7 cursor-pointer border-border" onClick={add}>
          Add
        </Button>
      </div>
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      {values.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1">
          {values.map(v => (
            <span key={v} className="inline-flex items-center gap-1 rounded-full bg-muted text-foreground text-[11px] font-mono px-2 py-0.5">
              {v}
              <button onClick={() => onChange(values.filter(x => x !== v))} className="hover:text-destructive cursor-pointer">
                <X className="h-2.5 w-2.5" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Collapsible Section ───────────────────────────────────────────────────────

export function CollapsibleSection({ title, open, onToggle, children }: {
  title: string
  open: boolean
  onToggle: () => void
  children: React.ReactNode
}) {
  return (
    <div className="border border-border rounded-md">
      <button
        className="w-full flex items-center justify-between px-4 py-2.5 text-sm font-medium cursor-pointer hover:bg-muted/10 transition-colors"
        onClick={onToggle}
      >
        {title}
        {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-4 border-t border-border pt-3">
          {children}
        </div>
      )}
    </div>
  )
}

// ─── Field Error ───────────────────────────────────────────────────────────────

function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null
  return <p className="text-xs text-destructive mt-1">{msg}</p>
}

// ─── Route Form Data ───────────────────────────────────────────────────────────

export type RouteFormData = {
  path_prefix: string
  route_type: 'proxy' | 'static' | 'redirect'
  // proxy — direct
  backend_url: string
  backend_urls: string[]
  // proxy — managed component
  managed_component_id: number | null
  // static
  static_root: string
  static_spa: boolean
  // redirect
  redirect_url: string
  // proxy + static
  strip_prefix: boolean
  rewrite_pattern: string
  rewrite_to: string
  // proxy
  rate_limit_rps: number
  rate_limit_burst: number
  max_body_bytes: number
  timeout_seconds: number
  accel_root: string
  accel_signed_secret: string
  // all
  priority: number
  is_active: boolean
  log_enabled: boolean
  waf_enabled: boolean
  waf_exclude_paths: string[]
  waf_detection_only: boolean
  // RFC3339 (or empty when no soak window). The form treats this as
  // read-only metadata — the only mutation we support from the dialog is
  // ending the soak early via a "Stop soak" button below.
  waf_detection_only_until: string
  // proxy + static
  cors_enabled: boolean
  cors_origins: string
  cors_methods: string
  cors_headers: string
  cors_max_age: number
  cors_credentials: boolean
  // proxy + static
  error_page_4xx: string
  error_page_5xx: string
  // all
  req_headers_add: Record<string, string>
  req_headers_del: string[]
  resp_headers_add: Record<string, string>
  resp_headers_del: string[]
}

export const defaultRouteForm = (): RouteFormData => ({
  path_prefix: '/',
  route_type: 'proxy',
  backend_url: '',
  backend_urls: [],
  managed_component_id: null,
  static_root: '',
  static_spa: false,
  redirect_url: '',
  strip_prefix: true,
  rewrite_pattern: '',
  rewrite_to: '',
  priority: 0,
  is_active: true,
  log_enabled: true,
  waf_enabled: false,
  waf_exclude_paths: [],
  waf_detection_only: false,
  waf_detection_only_until: '',
  rate_limit_rps: 0,
  rate_limit_burst: 0,
  max_body_bytes: 0,
  timeout_seconds: 0,
  cors_enabled: false,
  cors_origins: '',
  cors_methods: 'GET,POST,PUT,DELETE,OPTIONS,PATCH',
  cors_headers: '*',
  cors_max_age: 86400,
  cors_credentials: false,
  error_page_4xx: '',
  error_page_5xx: '',
  accel_root: '',
  accel_signed_secret: '',
  req_headers_add: {},
  req_headers_del: [],
  resp_headers_add: {},
  resp_headers_del: [],
})

// ─── Route Dialog ───────────────────────────────────────────────────────────────

export function RouteDialog({
  open, onClose, hostId, route, onSaved,
}: {
  open: boolean
  onClose: () => void
  hostId: number
  route: Route | null
  onSaved: () => void
}) {
  const [form, setForm] = useState<RouteFormData>(defaultRouteForm())
  const [errors, setErrors] = useState<Partial<Record<keyof RouteFormData, string>>>({})
  const [saving, setSaving] = useState(false)
  const [showHeaders, setShowHeaders] = useState(false)
  const [showCORS, setShowCORS] = useState(false)
  const [showFileServing, setShowFileServing] = useState(false)
  const [showErrorPages, setShowErrorPages] = useState(false)
  const [showSecret, setShowSecret] = useState(false)
  const [components, setComponents] = useState<(DeployComponent & { projectSlug: string })[]>([])

  // Fetch available managed components when dialog opens
  useEffect(() => {
    if (!open) return
    api.listDeployProjects().then(projects => {
      const all = projects.flatMap(p =>
        p.components
          .filter(c => c.is_routable)
          .map(c => ({ ...c, projectSlug: p.project.slug }))
      )
      setComponents(all)
    }).catch(() => { /* non-critical */ })
  }, [open])

  useEffect(() => {
    if (route) {
      setForm({
        path_prefix: route.path_prefix,
        route_type: route.route_type,
        backend_url: route.backend_url ?? '',
        backend_urls: route.backend_urls ?? [],
        managed_component_id: route.managed_component_id ?? null,
        static_root: route.static_root ?? '',
        static_spa: route.static_spa ?? false,
        redirect_url: route.redirect_url ?? '',
        strip_prefix: route.strip_prefix,
        rewrite_pattern: route.rewrite_pattern ?? '',
        rewrite_to: route.rewrite_to ?? '',
        priority: route.priority,
        is_active: route.is_active,
        log_enabled: route.log_enabled,
        waf_enabled: route.waf_enabled,
        waf_exclude_paths: route.waf_exclude_paths ?? [],
        waf_detection_only: route.waf_detection_only ?? false,
        waf_detection_only_until: route.waf_detection_only_until ?? '',
        rate_limit_rps: route.rate_limit_rps ?? 0,
        rate_limit_burst: route.rate_limit_burst ?? 0,
        max_body_bytes: route.max_body_bytes ?? 0,
        timeout_seconds: route.timeout_seconds ?? 0,
        cors_enabled: route.cors_enabled ?? false,
        cors_origins: route.cors_origins ?? '',
        cors_methods: route.cors_methods ?? 'GET,POST,PUT,DELETE,OPTIONS,PATCH',
        cors_headers: route.cors_headers ?? '*',
        cors_max_age: route.cors_max_age ?? 86400,
        cors_credentials: route.cors_credentials ?? false,
        error_page_4xx: route.error_page_4xx ?? '',
        error_page_5xx: route.error_page_5xx ?? '',
        accel_root: route.accel_root ?? '',
        accel_signed_secret: route.accel_signed_secret ?? '',
        req_headers_add: route.req_headers_add ?? {},
        req_headers_del: route.req_headers_del ?? [],
        resp_headers_add: route.resp_headers_add ?? {},
        resp_headers_del: route.resp_headers_del ?? [],
      })
    } else {
      setForm(defaultRouteForm())
    }
    setErrors({})
    setShowHeaders(false)
    setShowCORS(false)
    setShowFileServing(false)
    setShowErrorPages(false)
    setShowSecret(false)
  }, [route, open])

  function set<K extends keyof RouteFormData>(k: K, v: RouteFormData[K]) {
    setForm(f => ({ ...f, [k]: v }))
    setErrors(e => ({ ...e, [k]: undefined }))
  }

  // Clear type-specific fields when route type changes so stale data is not saved
  function changeRouteType(newType: RouteFormData['route_type']) {
    setForm(f => ({
      ...f,
      route_type: newType,
      // Clear all type-specific fields
      backend_url: '',
      backend_urls: [],
      managed_component_id: null,
      static_root: '',
      static_spa: false,
      redirect_url: '',
    }))
    setErrors({})
  }

  function fieldError(k: keyof RouteFormData) {
    return errors[k]
  }

  async function handleSave() {
    const newErrors: Partial<Record<keyof RouteFormData, string>> = {}

    if (!form.path_prefix) {
      newErrors.path_prefix = 'Path prefix is required'
    } else if (!form.path_prefix.startsWith('/')) {
      newErrors.path_prefix = 'Path prefix must start with /'
    }

    if (form.route_type === 'proxy') {
      const hasBackend = form.managed_component_id !== null || form.backend_url || form.backend_urls.length > 0
      if (!hasBackend) newErrors.backend_url = 'Backend URL or managed component is required'
    }
    if (form.route_type === 'static' && !form.static_root) {
      newErrors.static_root = 'Static root directory is required'
    }
    if (form.route_type === 'redirect' && !form.redirect_url) {
      newErrors.redirect_url = 'Redirect URL is required'
    }
    if (form.rewrite_pattern && !form.rewrite_to) {
      newErrors.rewrite_to = 'Rewrite destination is required when pattern is set'
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      return
    }

    setSaving(true)
    try {
      const payload: Partial<Omit<Route, 'id' | 'host_id' | 'created_at' | 'updated_at'>> = {
        path_prefix: form.path_prefix,
        route_type: form.route_type,
        // proxy fields
        backend_url: form.route_type === 'proxy' && form.managed_component_id === null
          ? (form.backend_url || undefined)
          : undefined,
        backend_urls: form.route_type === 'proxy' && form.managed_component_id === null && form.backend_urls.length > 0
          ? form.backend_urls
          : undefined,
        managed_component_id: form.route_type === 'proxy' && form.managed_component_id !== null
          ? form.managed_component_id
          : undefined,
        // static fields
        static_root: form.route_type === 'static' ? form.static_root : undefined,
        static_spa: form.route_type === 'static' ? form.static_spa : undefined,
        // redirect fields
        redirect_url: form.route_type === 'redirect' ? form.redirect_url : undefined,
        // proxy + static
        strip_prefix: form.route_type !== 'redirect' ? form.strip_prefix : undefined,
        rewrite_pattern: form.route_type !== 'redirect' ? (form.rewrite_pattern || undefined) : undefined,
        rewrite_to: form.route_type !== 'redirect' ? (form.rewrite_to || undefined) : undefined,
        // proxy only
        rate_limit_rps: form.route_type === 'proxy' ? (form.rate_limit_rps > 0 ? form.rate_limit_rps : 0) : undefined,
        rate_limit_burst: form.route_type === 'proxy' ? (form.rate_limit_burst > 0 ? form.rate_limit_burst : 0) : undefined,
        max_body_bytes: form.route_type === 'proxy' ? (form.max_body_bytes > 0 ? form.max_body_bytes : 0) : undefined,
        timeout_seconds: form.route_type === 'proxy' ? (form.timeout_seconds > 0 ? form.timeout_seconds : 0) : undefined,
        accel_root: form.route_type === 'proxy' ? (form.accel_root || undefined) : undefined,
        accel_signed_secret: form.route_type === 'proxy' ? (form.accel_signed_secret || undefined) : undefined,
        // general
        priority: form.priority,
        is_active: form.is_active,
        log_enabled: form.log_enabled,
        waf_enabled: form.waf_enabled,
        waf_exclude_paths: form.waf_exclude_paths.length > 0 ? form.waf_exclude_paths : undefined,
        waf_detection_only: form.waf_detection_only,
        // Empty string round-trips as null on the wire so "Stop soak" can
        // clear the soak window. Any non-empty string is forwarded as-is
        // (the only mutation paths we expose set this to '' to clear).
        waf_detection_only_until: form.waf_detection_only_until === '' ? null : form.waf_detection_only_until,
        // cors — proxy + static only
        cors_enabled: form.route_type !== 'redirect' ? form.cors_enabled : undefined,
        cors_origins: (form.route_type !== 'redirect' && form.cors_enabled) ? (form.cors_origins || '*') : undefined,
        cors_methods: (form.route_type !== 'redirect' && form.cors_enabled) ? (form.cors_methods || 'GET,POST,PUT,DELETE,OPTIONS,PATCH') : undefined,
        cors_headers: (form.route_type !== 'redirect' && form.cors_enabled) ? (form.cors_headers || '*') : undefined,
        cors_max_age: (form.route_type !== 'redirect' && form.cors_enabled) ? form.cors_max_age : undefined,
        cors_credentials: (form.route_type !== 'redirect' && form.cors_enabled) ? form.cors_credentials : undefined,
        // error pages — proxy + static only
        error_page_4xx: form.route_type !== 'redirect' ? (form.error_page_4xx || undefined) : undefined,
        error_page_5xx: form.route_type !== 'redirect' ? (form.error_page_5xx || undefined) : undefined,
        // headers — proxy + static only
        req_headers_add: form.route_type !== 'redirect' && Object.keys(form.req_headers_add).length > 0
          ? form.req_headers_add : undefined,
        req_headers_del: form.route_type !== 'redirect' && form.req_headers_del.length > 0
          ? form.req_headers_del : undefined,
        resp_headers_add: form.route_type !== 'redirect' && Object.keys(form.resp_headers_add).length > 0
          ? form.resp_headers_add : undefined,
        resp_headers_del: form.route_type !== 'redirect' && form.resp_headers_del.length > 0
          ? form.resp_headers_del : undefined,
      }
      if (route) {
        await api.updateRoute(route.id, payload)
        toast.success('Route updated')
      } else {
        await api.createRoute(hostId, payload as Omit<Route, 'id' | 'host_id' | 'created_at' | 'updated_at'>)
        toast.success('Route created')
      }
      onSaved()
      onClose()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const isProxyDirect = form.route_type === 'proxy' && form.managed_component_id === null
  const isProxyManaged = form.route_type === 'proxy' && form.managed_component_id !== null

  return (
    <Dialog open={open} onOpenChange={v => !v && onClose()}>
      <DialogContent className="bg-card border-border max-w-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{route ? 'Edit Route' : 'Add Route'}</DialogTitle>
          <DialogDescription>Configure how traffic is routed for this host</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">

          {/* ── Path prefix + Route type + Priority ── */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5 col-span-2">
              <Label>
                Path Prefix <span className="text-destructive">*</span>
              </Label>
              <Input
                placeholder="/api"
                className={`bg-background border-border font-mono ${fieldError('path_prefix') ? 'border-destructive' : ''}`}
                value={form.path_prefix}
                onChange={e => set('path_prefix', e.target.value)}
              />
              <FieldError msg={fieldError('path_prefix')} />
            </div>
            <div className="space-y-1.5">
              <Label>Route Type <span className="text-destructive">*</span></Label>
              <Select value={form.route_type} onValueChange={v => changeRouteType(v as RouteFormData['route_type'])}>
                <SelectTrigger className="bg-background border-border cursor-pointer">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-card border-border">
                  <SelectItem value="proxy" className="cursor-pointer">Proxy</SelectItem>
                  <SelectItem value="static" className="cursor-pointer">Static Files</SelectItem>
                  <SelectItem value="redirect" className="cursor-pointer">Redirect</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label title="Higher number = evaluated first when multiple routes share the same prefix">
                Priority <span className="text-xs text-muted-foreground font-normal">(higher = first)</span>
              </Label>
              <Input
                type="number"
                className="bg-background border-border"
                value={form.priority}
                onChange={e => set('priority', Number(e.target.value))}
              />
            </div>
          </div>

          {/* ── Proxy backend ── */}
          {form.route_type === 'proxy' && (
            <div className="space-y-3">
              {/* Toggle: direct URL vs managed component */}
              {components.length > 0 && (
                <div className="flex gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant={isProxyDirect ? 'default' : 'outline'}
                    className="flex-1 cursor-pointer"
                    onClick={() => set('managed_component_id', null)}
                  >
                    Direct URL
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant={isProxyManaged ? 'default' : 'outline'}
                    className="flex-1 cursor-pointer"
                    onClick={() => set('managed_component_id', components[0].id)}
                  >
                    <Server className="h-3.5 w-3.5 mr-1.5" />
                    Managed Component
                  </Button>
                </div>
              )}

              {/* Direct URL inputs */}
              {isProxyDirect && (
                <>
                  <div className="space-y-1.5">
                    <Label>
                      Primary Backend URL <span className="text-destructive">*</span>
                    </Label>
                    <Input
                      placeholder="http://localhost:8080"
                      className={`bg-background border-border font-mono ${fieldError('backend_url') ? 'border-destructive' : ''}`}
                      value={form.backend_url}
                      onChange={e => set('backend_url', e.target.value)}
                    />
                    <FieldError msg={fieldError('backend_url')} />
                    <p className="text-xs text-muted-foreground">
                      Add additional backends below for round-robin load balancing.
                    </p>
                  </div>
                  <TagInput
                    label="Additional Backends (round-robin)"
                    values={form.backend_urls}
                    onChange={v => set('backend_urls', v)}
                    placeholder="http://backend2:8080"
                  />
                </>
              )}

              {/* Managed component selector */}
              {isProxyManaged && (
                <div className="space-y-1.5">
                  <Label>Component</Label>
                  <Select
                    value={String(form.managed_component_id ?? '')}
                    onValueChange={v => set('managed_component_id', Number(v))}
                  >
                    <SelectTrigger className="bg-background border-border cursor-pointer">
                      <SelectValue placeholder="Select a component" />
                    </SelectTrigger>
                    <SelectContent className="bg-card border-border">
                      {components.map(c => (
                        <SelectItem key={c.id} value={String(c.id)} className="cursor-pointer">
                          <span className="font-mono text-xs">{c.projectSlug}/{c.slug}</span>
                          <span className="ml-2 text-muted-foreground text-xs">:{c.internal_port}</span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Traffic will be forwarded to the active instance of this component.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* ── Static root ── */}
          {form.route_type === 'static' && (
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label>Static Root Directory <span className="text-destructive">*</span></Label>
                <Input
                  placeholder="/var/www/html"
                  className={`bg-background border-border font-mono ${fieldError('static_root') ? 'border-destructive' : ''}`}
                  value={form.static_root}
                  onChange={e => set('static_root', e.target.value)}
                />
                <FieldError msg={fieldError('static_root')} />
              </div>
              <div className="flex items-center justify-between rounded-md border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">SPA Mode</p>
                  <p className="text-xs text-muted-foreground">Fall back to index.html for unknown paths — required for React/Vue/Angular client-side routing</p>
                </div>
                <Switch checked={form.static_spa} onCheckedChange={v => set('static_spa', v)} />
              </div>
            </div>
          )}

          {/* ── Redirect URL ── */}
          {form.route_type === 'redirect' && (
            <div className="space-y-1.5">
              <Label>Redirect URL <span className="text-destructive">*</span></Label>
              <Input
                placeholder="https://example.com"
                className={`bg-background border-border font-mono ${fieldError('redirect_url') ? 'border-destructive' : ''}`}
                value={form.redirect_url}
                onChange={e => set('redirect_url', e.target.value)}
              />
              <FieldError msg={fieldError('redirect_url')} />
            </div>
          )}

          <Separator className="bg-border" />

          {/* ── Strip prefix + Rewrite — only proxy and static ── */}
          {form.route_type !== 'redirect' && (
            <>
              <div className="flex items-center justify-between rounded-md border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">Strip Prefix</p>
                  <p className="text-xs text-muted-foreground">Remove path prefix before forwarding to backend</p>
                </div>
                <Switch checked={form.strip_prefix} onCheckedChange={v => set('strip_prefix', v)} className="cursor-pointer" />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label className="text-sm">
                    Rewrite Pattern
                    <span className="ml-1 text-xs text-muted-foreground font-normal">(regex)</span>
                  </Label>
                  <Input
                    placeholder="^/old/(.*)"
                    className={`bg-background border-border font-mono text-xs ${fieldError('rewrite_pattern') ? 'border-destructive' : ''}`}
                    value={form.rewrite_pattern}
                    onChange={e => set('rewrite_pattern', e.target.value)}
                  />
                  <FieldError msg={fieldError('rewrite_pattern')} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-sm">
                    Rewrite To
                    <span className="ml-1 text-xs text-muted-foreground font-normal">(use $1, $2 …)</span>
                  </Label>
                  <Input
                    placeholder="/new/$1"
                    className={`bg-background border-border font-mono text-xs ${fieldError('rewrite_to') ? 'border-destructive' : ''}`}
                    value={form.rewrite_to}
                    onChange={e => set('rewrite_to', e.target.value)}
                  />
                  <FieldError msg={fieldError('rewrite_to')} />
                </div>
                {(form.rewrite_pattern || form.rewrite_to) && (
                  <p className="col-span-2 text-xs text-muted-foreground -mt-2">
                    Applied after strip prefix. Strip prefix runs first, then pattern is matched against the remaining path.
                  </p>
                )}
              </div>
            </>
          )}

          {/* ── Proxy-only: rate limit / timeout / max body ── */}
          {form.route_type === 'proxy' && (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Rate Limit (req/s, 0 = off)</Label>
                <Input type="number" min={0} className="h-8 bg-background border-border text-xs"
                  value={form.rate_limit_rps}
                  onChange={e => set('rate_limit_rps', Number(e.target.value))} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">
                  Burst
                  <span className="ml-1 text-muted-foreground font-normal">(extra allowed above RPS)</span>
                </Label>
                <Input
                  type="number" min={0}
                  className="h-8 bg-background border-border text-xs"
                  value={form.rate_limit_burst}
                  disabled={form.rate_limit_rps === 0}
                  onChange={e => set('rate_limit_burst', Number(e.target.value))}
                />
                {form.rate_limit_rps === 0 && (
                  <p className="text-xs text-muted-foreground">Enable rate limit first</p>
                )}
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Timeout (seconds, 0 = off)</Label>
                <Input type="number" min={0} className="h-8 bg-background border-border text-xs"
                  value={form.timeout_seconds} onChange={e => set('timeout_seconds', Number(e.target.value))} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Max Body (bytes, 0 = off)</Label>
                <Input type="number" min={0} className="h-8 bg-background border-border text-xs"
                  value={form.max_body_bytes} onChange={e => set('max_body_bytes', Number(e.target.value))} />
              </div>
            </div>
          )}

          {/* ── Active / Log / WAF ── */}
          <div className="flex items-center justify-between rounded-md border border-border px-4 py-3">
            <div>
              <p className="text-sm font-medium">Active</p>
              <p className="text-xs text-muted-foreground">Enable this route</p>
            </div>
            <Switch checked={form.is_active} onCheckedChange={v => set('is_active', v)} className="cursor-pointer" />
          </div>
          <div className="flex items-center justify-between rounded-md border border-border px-4 py-3">
            <div>
              <p className="text-sm font-medium">Log Enabled</p>
              <p className="text-xs text-muted-foreground">Record requests in SIEM logs</p>
            </div>
            <Switch checked={form.log_enabled} onCheckedChange={v => set('log_enabled', v)} className="cursor-pointer" />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between rounded-md border border-border px-4 py-3">
              <div>
                <p className="text-sm font-medium">WAF Inspection</p>
                <p className="text-xs text-muted-foreground">Pre-screen requests via muWAF</p>
              </div>
              <Switch checked={form.waf_enabled} onCheckedChange={v => set('waf_enabled', v)} className="cursor-pointer" />
            </div>
            {form.waf_enabled && (
              <div className="pl-2 space-y-3">
                <TagInput
                  label="WAF Excluded Paths"
                  values={form.waf_exclude_paths}
                  onChange={v => set('waf_exclude_paths', v)}
                  placeholder="/health"
                  hint="Glob patterns, e.g. /health, /api/public/*, /static/**"
                />
                <div className="flex items-center justify-between rounded-md border border-border px-4 py-2.5">
                  <div>
                    <p className="text-xs font-medium">Detection Only</p>
                    <p className="text-xs text-muted-foreground">Log threats but don't block requests</p>
                  </div>
                  <Switch checked={form.waf_detection_only} onCheckedChange={v => set('waf_detection_only', v)} className="cursor-pointer" />
                </div>
                {(() => {
                  const until = form.waf_detection_only_until ? new Date(form.waf_detection_only_until) : null
                  if (!until || until.getTime() <= Date.now()) return null
                  const days = Math.max(1, Math.ceil((until.getTime() - Date.now()) / (24 * 60 * 60 * 1000)))
                  return (
                    <div className="flex items-center justify-between rounded-md border border-amber-400/40 bg-amber-400/5 px-4 py-2.5">
                      <div>
                        <p className="text-xs font-medium text-amber-300">Soak window active · {days} day{days === 1 ? '' : 's'} left</p>
                        <p className="text-xs text-amber-300/80">
                          Blocks are downgraded to logs until {until.toLocaleString()}. End early once you've reviewed false positives.
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => set('waf_detection_only_until', '')}
                        className="text-xs px-2 py-1 rounded border border-amber-400/40 text-amber-300 hover:bg-amber-400/10 cursor-pointer"
                      >
                        Stop soak
                      </button>
                    </div>
                  )
                })()}
              </div>
            )}
          </div>

          {/* ── Header Manipulation — proxy + static only ── */}
          {form.route_type !== 'redirect' && (
            <CollapsibleSection title="Header Manipulation" open={showHeaders} onToggle={() => setShowHeaders(v => !v)}>
              <HeaderKVEditor label="Add Request Headers" value={form.req_headers_add} onChange={v => set('req_headers_add', v)} />
              <TagInput label="Remove Request Headers" values={form.req_headers_del} onChange={v => set('req_headers_del', v)} placeholder="X-Forwarded-For" />
              <HeaderKVEditor label="Add Response Headers" value={form.resp_headers_add} onChange={v => set('resp_headers_add', v)} />
              <TagInput label="Remove Response Headers" values={form.resp_headers_del} onChange={v => set('resp_headers_del', v)} placeholder="Server" />
            </CollapsibleSection>
          )}

          {/* ── CORS — proxy + static only ── */}
          {form.route_type !== 'redirect' && (
            <CollapsibleSection title="CORS" open={showCORS} onToggle={() => setShowCORS(v => !v)}>
              <div className="flex items-center justify-between rounded-md border border-border px-4 py-2.5">
                <div>
                  <p className="text-xs font-medium">Enable CORS</p>
                  <p className="text-xs text-muted-foreground">Cross-Origin Resource Sharing headers</p>
                </div>
                <Switch checked={form.cors_enabled} onCheckedChange={v => set('cors_enabled', v)} className="cursor-pointer" />
              </div>
              {form.cors_enabled && (
                <div className="space-y-3 pl-1">
                  <div className="space-y-1.5">
                    <Label className="text-xs">Allowed Origins <span className="text-destructive">*</span></Label>
                    <Input
                      className="h-8 bg-background border-border font-mono text-xs"
                      placeholder="https://app.example.com,https://dev.example.com"
                      value={form.cors_origins}
                      onChange={e => set('cors_origins', e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground">
                      Comma-separated origins. Use <code className="font-mono">*</code> to allow any (not recommended for credentialed requests).
                    </p>
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Allowed Methods</Label>
                    <Input className="h-8 bg-background border-border font-mono text-xs"
                      value={form.cors_methods} onChange={e => set('cors_methods', e.target.value)} />
                    <p className="text-xs text-muted-foreground">Comma-separated, e.g. GET,POST,OPTIONS</p>
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Allowed Headers</Label>
                    <Input className="h-8 bg-background border-border font-mono text-xs"
                      value={form.cors_headers} onChange={e => set('cors_headers', e.target.value)} />
                    <p className="text-xs text-muted-foreground">Comma-separated header names, or <code className="font-mono">*</code></p>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <Label className="text-xs">Max Age (seconds)</Label>
                      <Input type="number" min={0} className="h-8 bg-background border-border text-xs"
                        value={form.cors_max_age} onChange={e => set('cors_max_age', Number(e.target.value))} />
                    </div>
                    <div className="flex items-end pb-1">
                      <div className="flex items-center justify-between rounded-md border border-border px-3 py-2 w-full">
                        <p className="text-xs font-medium">Allow Credentials</p>
                        <Switch checked={form.cors_credentials} onCheckedChange={v => set('cors_credentials', v)} className="cursor-pointer" />
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </CollapsibleSection>
          )}

          {/* ── File Serving (X-Accel-Redirect) — proxy only ── */}
          {form.route_type === 'proxy' && (
            <CollapsibleSection title="File Serving (X-Accel-Redirect)" open={showFileServing} onToggle={() => setShowFileServing(v => !v)}>
              <div className="space-y-1.5">
                <Label className="text-xs">Accel Root Directory</Label>
                <Input className="h-8 bg-background border-border font-mono text-xs"
                  placeholder="/var/files"
                  value={form.accel_root} onChange={e => set('accel_root', e.target.value)} />
                <p className="text-xs text-muted-foreground">
                  Backend responds with <code className="font-mono text-xs">X-Accel-Redirect: /relative/path</code>; muvon serves the file from this root directory.
                </p>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Signed URL Secret</Label>
                <div className="relative">
                  <Input
                    type={showSecret ? 'text' : 'password'}
                    className="h-8 bg-background border-border font-mono text-xs pr-9"
                    placeholder="Leave empty to disable signed URLs"
                    value={form.accel_signed_secret}
                    onChange={e => set('accel_signed_secret', e.target.value)}
                  />
                  <button
                    type="button"
                    onClick={() => setShowSecret(v => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground cursor-pointer"
                  >
                    {showSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                  </button>
                </div>
                <p className="text-xs text-muted-foreground">
                  HMAC-SHA256 key. Token = <code className="font-mono text-xs">HMAC(secret, path+&quot;:&quot;+expires)</code>
                </p>
              </div>
            </CollapsibleSection>
          )}

          {/* ── Custom Error Pages — proxy + static only ── */}
          {form.route_type !== 'redirect' && (
            <CollapsibleSection title="Custom Error Pages" open={showErrorPages} onToggle={() => setShowErrorPages(v => !v)}>
              <div className="space-y-1.5">
                <Label className="text-xs">4xx Error Page (HTML)</Label>
                <Textarea
                  className="bg-background border-border font-mono text-xs min-h-[80px] resize-y"
                  placeholder={'<h1>Not Found</h1>\n<p>The requested resource could not be found.</p>'}
                  value={form.error_page_4xx}
                  onChange={e => set('error_page_4xx', e.target.value)}
                />
                <p className="text-xs text-muted-foreground">HTML content served for 4xx responses. Leave empty to use the default error page.</p>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">5xx Error Page (HTML)</Label>
                <Textarea
                  className="bg-background border-border font-mono text-xs min-h-[80px] resize-y"
                  placeholder={'<h1>Service Unavailable</h1>\n<p>Please try again later.</p>'}
                  value={form.error_page_5xx}
                  onChange={e => set('error_page_5xx', e.target.value)}
                />
                <p className="text-xs text-muted-foreground">HTML content served for 5xx responses. Leave empty to use the default error page.</p>
              </div>
            </CollapsibleSection>
          )}

        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} className="cursor-pointer border-border">Cancel</Button>
          <Button onClick={handleSave} disabled={saving} className="cursor-pointer">
            {saving && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
            {route ? 'Update Route' : 'Create Route'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
