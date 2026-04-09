import { useState, useEffect } from 'react'
import {
  ChevronDown, ChevronRight, X, Eye, EyeOff, Loader2, Plus,
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
import type { Route } from '@/types'

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
  label, values, onChange, placeholder,
}: {
  label: string
  values: string[]
  onChange: (v: string[]) => void
  placeholder?: string
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

// ─── Route Form Data ───────────────────────────────────────────────────────────

export type RouteFormData = {
  path_prefix: string
  route_type: 'proxy' | 'static' | 'redirect'
  backend_url: string
  backend_urls: string[]
  static_root: string
  redirect_url: string
  strip_prefix: boolean
  rewrite_pattern: string
  rewrite_to: string
  priority: number
  is_active: boolean
  log_enabled: boolean
  waf_enabled: boolean
  waf_exclude_paths: string[]
  waf_detection_only: boolean
  rate_limit_rps: number
  rate_limit_burst: number
  max_body_bytes: number
  timeout_seconds: number
  cors_enabled: boolean
  cors_origins: string
  cors_methods: string
  cors_headers: string
  cors_max_age: number
  cors_credentials: boolean
  error_page_4xx: string
  error_page_5xx: string
  accel_root: string
  accel_signed_secret: string
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
  static_root: '',
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
  rate_limit_rps: 0,
  rate_limit_burst: 0,
  max_body_bytes: 0,
  timeout_seconds: 0,
  cors_enabled: false,
  cors_origins: '*',
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
  const [saving, setSaving] = useState(false)
  const [showHeaders, setShowHeaders] = useState(false)
  const [showCORS, setShowCORS] = useState(false)
  const [showFileServing, setShowFileServing] = useState(false)
  const [showErrorPages, setShowErrorPages] = useState(false)
  const [showSecret, setShowSecret] = useState(false)

  useEffect(() => {
    if (route) {
      setForm({
        path_prefix: route.path_prefix,
        route_type: route.route_type,
        backend_url: route.backend_url ?? '',
        backend_urls: route.backend_urls ?? [],
        static_root: route.static_root ?? '',
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
        rate_limit_rps: route.rate_limit_rps ?? 0,
        rate_limit_burst: route.rate_limit_burst ?? 0,
        max_body_bytes: route.max_body_bytes ?? 0,
        timeout_seconds: route.timeout_seconds ?? 0,
        cors_enabled: route.cors_enabled ?? false,
        cors_origins: route.cors_origins ?? '*',
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
    setShowHeaders(false)
    setShowCORS(false)
    setShowFileServing(false)
    setShowErrorPages(false)
    setShowSecret(false)
  }, [route, open])

  function set<K extends keyof RouteFormData>(k: K, v: RouteFormData[K]) {
    setForm(f => ({ ...f, [k]: v }))
  }

  async function handleSave() {
    if (!form.path_prefix) { toast.error('Path prefix is required'); return }
    const hasBackend = form.backend_url || form.backend_urls.length > 0
    if (form.route_type === 'proxy' && !hasBackend) {
      toast.error('Backend URL is required for proxy routes')
      return
    }
    if (form.route_type === 'static' && !form.static_root) { toast.error('Static root is required'); return }
    if (form.route_type === 'redirect' && !form.redirect_url) { toast.error('Redirect URL is required'); return }

    setSaving(true)
    try {
      const payload: Partial<Omit<Route, 'id' | 'host_id' | 'created_at' | 'updated_at'>> = {
        path_prefix: form.path_prefix,
        route_type: form.route_type,
        backend_url: form.route_type === 'proxy' ? (form.backend_url || undefined) : undefined,
        backend_urls: form.route_type === 'proxy' && form.backend_urls.length > 0 ? form.backend_urls : undefined,
        static_root: form.route_type === 'static' ? form.static_root : undefined,
        redirect_url: form.route_type === 'redirect' ? form.redirect_url : undefined,
        strip_prefix: form.strip_prefix,
        rewrite_pattern: form.rewrite_pattern || undefined,
        rewrite_to: form.rewrite_to || undefined,
        priority: form.priority,
        is_active: form.is_active,
        log_enabled: form.log_enabled,
        waf_enabled: form.waf_enabled,
        waf_exclude_paths: form.waf_exclude_paths.length > 0 ? form.waf_exclude_paths : undefined,
        waf_detection_only: form.waf_detection_only,
        rate_limit_rps: form.rate_limit_rps > 0 ? form.rate_limit_rps : 0,
        rate_limit_burst: form.rate_limit_burst > 0 ? form.rate_limit_burst : 0,
        max_body_bytes: form.max_body_bytes > 0 ? form.max_body_bytes : 0,
        timeout_seconds: form.timeout_seconds > 0 ? form.timeout_seconds : 0,
        cors_enabled: form.cors_enabled,
        cors_origins: form.cors_enabled ? (form.cors_origins || '*') : undefined,
        cors_methods: form.cors_enabled ? (form.cors_methods || 'GET,POST,PUT,DELETE,OPTIONS,PATCH') : undefined,
        cors_headers: form.cors_enabled ? (form.cors_headers || '*') : undefined,
        cors_max_age: form.cors_enabled ? form.cors_max_age : undefined,
        cors_credentials: form.cors_enabled ? form.cors_credentials : undefined,
        error_page_4xx: form.error_page_4xx || undefined,
        error_page_5xx: form.error_page_5xx || undefined,
        accel_root: form.accel_root || undefined,
        accel_signed_secret: form.accel_signed_secret || undefined,
        req_headers_add: Object.keys(form.req_headers_add).length > 0 ? form.req_headers_add : undefined,
        req_headers_del: form.req_headers_del.length > 0 ? form.req_headers_del : undefined,
        resp_headers_add: Object.keys(form.resp_headers_add).length > 0 ? form.resp_headers_add : undefined,
        resp_headers_del: form.resp_headers_del.length > 0 ? form.resp_headers_del : undefined,
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

  return (
    <Dialog open={open} onOpenChange={v => !v && onClose()}>
      <DialogContent className="bg-card border-border max-w-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{route ? 'Edit Route' : 'Add Route'}</DialogTitle>
          <DialogDescription>Configure how traffic is routed for this host</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2 col-span-2">
              <Label>Path Prefix</Label>
              <Input
                placeholder="/api"
                className="bg-background border-border font-mono"
                value={form.path_prefix}
                onChange={e => set('path_prefix', e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Route Type</Label>
              <Select value={form.route_type} onValueChange={v => set('route_type', v as RouteFormData['route_type'])}>
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
            <div className="space-y-2">
              <Label>Priority</Label>
              <Input
                type="number"
                className="bg-background border-border"
                value={form.priority}
                onChange={e => set('priority', Number(e.target.value))}
              />
            </div>
          </div>

          {form.route_type === 'proxy' && (
            <div className="space-y-3">
              <div className="space-y-2">
                <Label>Primary Backend URL</Label>
                <Input
                  placeholder="http://localhost:8080"
                  className="bg-background border-border font-mono"
                  value={form.backend_url}
                  onChange={e => set('backend_url', e.target.value)}
                />
              </div>
              <TagInput
                label="Additional Backends (round-robin)"
                values={form.backend_urls}
                onChange={v => set('backend_urls', v)}
                placeholder="http://backend2:8080"
              />
            </div>
          )}
          {form.route_type === 'static' && (
            <div className="space-y-2">
              <Label>Static Root Directory</Label>
              <Input
                placeholder="/var/www/html"
                className="bg-background border-border font-mono"
                value={form.static_root}
                onChange={e => set('static_root', e.target.value)}
              />
            </div>
          )}
          {form.route_type === 'redirect' && (
            <div className="space-y-2">
              <Label>Redirect URL</Label>
              <Input
                placeholder="https://example.com"
                className="bg-background border-border font-mono"
                value={form.redirect_url}
                onChange={e => set('redirect_url', e.target.value)}
              />
            </div>
          )}

          <Separator className="bg-border" />

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Rewrite Pattern (regex)</Label>
              <Input
                placeholder="^/old/(.*)"
                className="bg-background border-border font-mono text-xs"
                value={form.rewrite_pattern}
                onChange={e => set('rewrite_pattern', e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Rewrite To</Label>
              <Input
                placeholder="/new/$1"
                className="bg-background border-border font-mono text-xs"
                value={form.rewrite_to}
                onChange={e => set('rewrite_to', e.target.value)}
              />
            </div>
          </div>

          {form.route_type === 'proxy' && (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Rate Limit (req/s, 0=off)</Label>
                <Input type="number" min={0} className="h-8 bg-background border-border text-xs"
                  value={form.rate_limit_rps} onChange={e => set('rate_limit_rps', Number(e.target.value))} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Burst</Label>
                <Input type="number" min={0} className="h-8 bg-background border-border text-xs"
                  value={form.rate_limit_burst} onChange={e => set('rate_limit_burst', Number(e.target.value))} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Timeout (seconds, 0=off)</Label>
                <Input type="number" min={0} className="h-8 bg-background border-border text-xs"
                  value={form.timeout_seconds} onChange={e => set('timeout_seconds', Number(e.target.value))} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Max Body (bytes, 0=off)</Label>
                <Input type="number" min={0} className="h-8 bg-background border-border text-xs"
                  value={form.max_body_bytes} onChange={e => set('max_body_bytes', Number(e.target.value))} />
              </div>
            </div>
          )}

          <div className="flex items-center justify-between rounded-md border border-border px-4 py-3">
            <div>
              <p className="text-sm font-medium">Strip Prefix</p>
              <p className="text-xs text-muted-foreground">Remove path prefix before forwarding</p>
            </div>
            <Switch checked={form.strip_prefix} onCheckedChange={v => set('strip_prefix', v)} className="cursor-pointer" />
          </div>
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
                <TagInput label="WAF Excluded Paths (glob)" values={form.waf_exclude_paths}
                  onChange={v => set('waf_exclude_paths', v)} placeholder="/health" />
                <div className="flex items-center justify-between rounded-md border border-border px-4 py-2.5">
                  <div>
                    <p className="text-xs font-medium">Detection Only</p>
                    <p className="text-xs text-muted-foreground">Log threats but don't block</p>
                  </div>
                  <Switch checked={form.waf_detection_only} onCheckedChange={v => set('waf_detection_only', v)} className="cursor-pointer" />
                </div>
              </div>
            )}
          </div>

          <CollapsibleSection title="Header Manipulation" open={showHeaders} onToggle={() => setShowHeaders(v => !v)}>
            <HeaderKVEditor label="Add Request Headers" value={form.req_headers_add} onChange={v => set('req_headers_add', v)} />
            <TagInput label="Remove Request Headers" values={form.req_headers_del} onChange={v => set('req_headers_del', v)} placeholder="X-Forwarded-For" />
            <HeaderKVEditor label="Add Response Headers" value={form.resp_headers_add} onChange={v => set('resp_headers_add', v)} />
            <TagInput label="Remove Response Headers" values={form.resp_headers_del} onChange={v => set('resp_headers_del', v)} placeholder="Server" />
          </CollapsibleSection>

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
                  <Label className="text-xs">Allowed Origins</Label>
                  <Input className="h-8 bg-background border-border font-mono text-xs"
                    placeholder="* or https://app.example.com,https://dev.example.com"
                    value={form.cors_origins} onChange={e => set('cors_origins', e.target.value)} />
                  <p className="text-xs text-muted-foreground">Use <code className="font-mono">*</code> for any, or comma-separated list</p>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Allowed Methods</Label>
                  <Input className="h-8 bg-background border-border font-mono text-xs"
                    value={form.cors_methods} onChange={e => set('cors_methods', e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Allowed Headers</Label>
                  <Input className="h-8 bg-background border-border font-mono text-xs"
                    value={form.cors_headers} onChange={e => set('cors_headers', e.target.value)} />
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

          {form.route_type === 'proxy' && (
            <CollapsibleSection title="File Serving (X-Accel-Redirect)" open={showFileServing} onToggle={() => setShowFileServing(v => !v)}>
              <div className="space-y-1.5">
                <Label className="text-xs">Accel Root Directory</Label>
                <Input className="h-8 bg-background border-border font-mono text-xs"
                  placeholder="/var/files"
                  value={form.accel_root} onChange={e => set('accel_root', e.target.value)} />
                <p className="text-xs text-muted-foreground">Backend sets <code className="font-mono text-xs">X-Accel-Redirect</code> header; muvon serves the local file</p>
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
                <p className="text-xs text-muted-foreground">HMAC-SHA256 key. Token = <code className="font-mono text-xs">HMAC(secret, path+":"+expires)</code></p>
              </div>
            </CollapsibleSection>
          )}

          <CollapsibleSection title="Custom Error Pages" open={showErrorPages} onToggle={() => setShowErrorPages(v => !v)}>
            <div className="space-y-1.5">
              <Label className="text-xs">4xx Error Page (HTML)</Label>
              <Textarea
                className="bg-background border-border font-mono text-xs min-h-[80px] resize-y"
                placeholder="<h1>Not Found</h1>"
                value={form.error_page_4xx}
                onChange={e => set('error_page_4xx', e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">5xx Error Page (HTML)</Label>
              <Textarea
                className="bg-background border-border font-mono text-xs min-h-[80px] resize-y"
                placeholder="<h1>Service Unavailable</h1>"
                value={form.error_page_5xx}
                onChange={e => set('error_page_5xx', e.target.value)}
              />
            </div>
          </CollapsibleSection>
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
