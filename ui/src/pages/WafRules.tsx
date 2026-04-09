import { useState, useEffect, useCallback, useRef } from 'react'
import {
  ShieldAlert, Plus, Trash2, Pencil, Search, Upload,
  ToggleLeft, ToggleRight, Check,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { cn } from '@/lib/utils'
import { EmptyState } from '@/components/EmptyState'
import * as api from '@/api'
import type { WafRule } from '@/types'

const CATEGORIES = [
  'xss', 'sqli', 'rce', 'lfi', 'rfi', 'ssrf', 'nosqli',
  'ssti', 'log4shell', 'prototype_pollution', 'session_fixation',
  'path_traversal', 'command_injection', 'custom',
]

function severityColor(s: number): string {
  if (s >= 80) return 'text-red-400 bg-red-400/10 border-red-400/30'
  if (s >= 50) return 'text-amber-400 bg-amber-400/10 border-amber-400/30'
  if (s >= 20) return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30'
  return 'text-blue-400 bg-blue-400/10 border-blue-400/30'
}

function categoryBadge(cat: string) {
  const colors: Record<string, string> = {
    xss: 'bg-red-500/10 text-red-400 border-red-500/20',
    sqli: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    rce: 'bg-red-600/10 text-red-500 border-red-600/20',
    lfi: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    rfi: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    ssrf: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    command_injection: 'bg-red-500/10 text-red-400 border-red-500/20',
    path_traversal: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    custom: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
  }
  return colors[cat] ?? 'bg-muted text-muted-foreground border-border'
}

interface RuleForm {
  pattern: string
  is_regex: boolean
  category: string
  severity: number
  description: string
  is_active: boolean
}

const emptyForm = (): RuleForm => ({
  pattern: '', is_regex: false, category: 'custom', severity: 5, description: '', is_active: true,
})

export default function WafRules() {
  const [rules, setRules] = useState<WafRule[]>([])
  const [loading, setLoading] = useState(true)
  const [serviceDown, setServiceDown] = useState(false)
  const [search, setSearch] = useState('')
  const [catFilter, setCatFilter] = useState('')
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<WafRule | null>(null)
  const [form, setForm] = useState<RuleForm>(emptyForm())
  const [saving, setSaving] = useState(false)
  const importRef = useRef<HTMLInputElement>(null)

  const load = useCallback(async () => {
    try {
      setServiceDown(false)
      const data = await api.listWafRules()
      setRules(data)
    } catch (err) {
      if (api.isServiceUnavailable(err)) {
        setServiceDown(true)
      } else {
        toast.error(err instanceof api.ApiError ? err.message : 'Failed to load WAF rules')
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function openCreate() {
    setEditingRule(null)
    setForm(emptyForm())
    setDialogOpen(true)
  }

  function openEdit(rule: WafRule) {
    setEditingRule(rule)
    setForm({
      pattern: rule.pattern,
      is_regex: rule.is_regex,
      category: rule.category,
      severity: rule.severity,
      description: rule.description,
      is_active: rule.is_active,
    })
    setDialogOpen(true)
  }

  async function handleSave() {
    if (!form.pattern || !form.category) {
      toast.error('Pattern and category are required')
      return
    }
    setSaving(true)
    try {
      if (editingRule) {
        await api.updateWafRule(editingRule.id, form)
        toast.success('Rule updated')
      } else {
        await api.createWafRule(form)
        toast.success('Rule created')
      }
      setDialogOpen(false)
      load()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(id: number) {
    try {
      await api.deleteWafRule(id)
      toast.success('Rule deleted')
      setRules(prev => prev.filter(r => r.id !== id))
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Delete failed')
    }
  }

  async function handleToggle(rule: WafRule) {
    try {
      await api.updateWafRule(rule.id, { is_active: !rule.is_active })
      setRules(prev => prev.map(r => r.id === rule.id ? { ...r, is_active: !r.is_active } : r))
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Toggle failed')
    }
  }

  async function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      const text = await file.text()
      const data = JSON.parse(text)
      const result = await api.importWafRules(Array.isArray(data) ? data : [data])
      toast.success(`Imported ${result.imported} of ${result.total} rules`)
      load()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Import failed')
    } finally {
      // import complete
      if (importRef.current) importRef.current.value = ''
    }
  }

  const filtered = rules.filter(r => {
    if (catFilter && r.category !== catFilter) return false
    if (search) {
      const s = search.toLowerCase()
      return r.pattern.toLowerCase().includes(s) || r.description.toLowerCase().includes(s) || r.category.toLowerCase().includes(s)
    }
    return true
  })

  if (serviceDown) {
    return (
      <div className="p-6">
        <h1 className="text-xl font-bold text-foreground tracking-tight mb-6">WAF Rules</h1>
        <EmptyState
          variant="service-offline"
          title="muWAF Servisi Cevrimdisi"
          description="WAF kural yonetimi icin muWAF servisinin calisiyor olmasi gerekiyor. Servis baslat&inodot;ld&inodot;g&inodot;nda bu sayfa otomatik olarak yuklenecektir."
        />
      </div>
    )
  }

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">WAF Rules</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            {rules.length} rule{rules.length !== 1 ? 's' : ''} configured
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            ref={importRef}
            type="file"
            accept=".json"
            className="hidden"
            onChange={handleImport}
          />
          <Button
            variant="outline"
            size="sm"
            className="gap-2 cursor-pointer border-border"
            onClick={() => importRef.current?.click()}
          >
            <Upload className="h-3.5 w-3.5" />
            Import
          </Button>
          <Button size="sm" className="gap-2 cursor-pointer" onClick={openCreate}>
            <Plus className="h-3.5 w-3.5" />
            New Rule
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Search patterns, descriptions..."
            className="pl-9 bg-card border-border h-9"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <Select value={catFilter || '__all'} onValueChange={v => setCatFilter(v === '__all' ? '' : v)}>
          <SelectTrigger className="w-44 h-9 bg-card border-border cursor-pointer">
            <SelectValue placeholder="All Categories" />
          </SelectTrigger>
          <SelectContent className="bg-card border-border">
            <SelectItem value="__all" className="cursor-pointer">All Categories</SelectItem>
            {CATEGORIES.map(c => (
              <SelectItem key={c} value={c} className="cursor-pointer font-mono text-xs">{c}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      {loading ? (
        <div className="space-y-1">
          {Array.from({ length: 8 }, (_, i) => (
            <Skeleton key={i} className="h-12 w-full rounded-sm" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          title={search || catFilter ? 'No matching rules' : 'No WAF rules configured'}
          description={search || catFilter ? 'Try adjusting your filters' : 'Create your first rule to start protecting your services'}
          action={
            !search && !catFilter ? (
              <Button size="sm" className="gap-2 cursor-pointer" onClick={openCreate}>
                <Plus className="h-3.5 w-3.5" /> Create Rule
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="bg-card hover:bg-card border-border">
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-12">Active</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider">Pattern</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-28">Category</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-20 text-center">Severity</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-16 text-center">Type</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider">Description</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-24 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map(rule => (
                <TableRow
                  key={rule.id}
                  className={cn(
                    'border-border transition-colors cursor-pointer hover:bg-muted/10',
                    !rule.is_active && 'opacity-50',
                  )}
                >
                  <TableCell>
                    <button
                      onClick={() => handleToggle(rule)}
                      className="cursor-pointer"
                      title={rule.is_active ? 'Disable' : 'Enable'}
                    >
                      {rule.is_active
                        ? <ToggleRight className="h-5 w-5 text-primary" />
                        : <ToggleLeft className="h-5 w-5 text-muted-foreground" />
                      }
                    </button>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-foreground max-w-xs truncate" title={rule.pattern}>
                    {rule.pattern}
                  </TableCell>
                  <TableCell>
                    <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-mono font-medium', categoryBadge(rule.category))}>
                      {rule.category}
                    </span>
                  </TableCell>
                  <TableCell className="text-center">
                    <span className={cn('inline-flex h-7 w-7 items-center justify-center rounded-md border text-xs font-bold font-mono', severityColor(rule.severity))}>
                      {rule.severity}
                    </span>
                  </TableCell>
                  <TableCell className="text-center">
                    <Badge variant={rule.is_regex ? 'secondary' : 'outline'} className="text-[10px]">
                      {rule.is_regex ? 'regex' : 'string'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground max-w-xs truncate" title={rule.description}>
                    {rule.description || '—'}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 cursor-pointer text-muted-foreground hover:text-foreground"
                        onClick={() => openEdit(rule)}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 cursor-pointer text-muted-foreground hover:text-destructive"
                        onClick={() => handleDelete(rule.id)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Create / Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="bg-card border-border sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-foreground">
              <ShieldAlert className="h-5 w-5 text-primary" />
              {editingRule ? 'Edit Rule' : 'New WAF Rule'}
            </DialogTitle>
            <DialogDescription>
              {editingRule ? 'Update detection pattern and settings' : 'Define a new detection pattern'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Pattern</Label>
              <Input
                className="bg-background border-border font-mono text-sm"
                placeholder="e.g. <script> or (?i)union\s+select"
                value={form.pattern}
                onChange={e => setForm(f => ({ ...f, pattern: e.target.value }))}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Category</Label>
                <Select value={form.category} onValueChange={v => setForm(f => ({ ...f, category: v }))}>
                  <SelectTrigger className="bg-background border-border cursor-pointer">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-card border-border">
                    {CATEGORIES.map(c => (
                      <SelectItem key={c} value={c} className="cursor-pointer font-mono text-xs">{c}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Severity (1-100)</Label>
                <Input
                  type="number"
                  min={1}
                  max={100}
                  className="bg-background border-border font-mono"
                  value={form.severity}
                  onChange={e => setForm(f => ({ ...f, severity: Number(e.target.value) }))}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Description</Label>
              <Input
                className="bg-background border-border"
                placeholder="What does this rule detect?"
                value={form.description}
                onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              />
            </div>
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Switch
                  checked={form.is_regex}
                  onCheckedChange={v => setForm(f => ({ ...f, is_regex: v }))}
                />
                <Label className="text-xs text-muted-foreground">Regex Pattern</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  checked={form.is_active}
                  onCheckedChange={v => setForm(f => ({ ...f, is_active: v }))}
                />
                <Label className="text-xs text-muted-foreground">Active</Label>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" className="cursor-pointer border-border" onClick={() => setDialogOpen(false)}>
                Cancel
              </Button>
              <Button className="cursor-pointer gap-2" onClick={handleSave} disabled={saving}>
                {saving ? <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" /> : <Check className="h-3.5 w-3.5" />}
                {editingRule ? 'Update' : 'Create'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
