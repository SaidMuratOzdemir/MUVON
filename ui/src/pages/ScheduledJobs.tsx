import { useEffect, useMemo, useState, useCallback } from 'react'
import {
  Clock, Plus, Play, Pencil, Trash2, RefreshCw, ChevronDown, ChevronRight, History,
} from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import type { DeployProjectSummary, ScheduledJob, ScheduledJobRun } from '@/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { cn } from '@/lib/utils'

const statusTone: Record<string, string> = {
  pending:   'border-amber-400/40 text-amber-300 bg-amber-400/10',
  running:   'border-blue-400/40 text-blue-300 bg-blue-400/10',
  succeeded: 'border-emerald-400/40 text-emerald-300 bg-emerald-400/10',
  failed:    'border-red-400/40 text-red-300 bg-red-400/10',
  skipped:   'border-border text-muted-foreground bg-muted/20',
}

function fmt(ts?: string | null): string {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString()
}

function StatusBadge({ status }: { status: string }) {
  return (
    <Badge variant="outline" className={cn('font-mono text-xs', statusTone[status] ?? 'border-border text-muted-foreground')}>
      {status}
    </Badge>
  )
}

// ── Job editor (create / edit) ─────────────────────────────────────────────

const COMMON_TZ = ['UTC', 'Europe/Istanbul', 'Europe/Berlin', 'America/New_York', 'Asia/Dubai']

function JobEditor({
  projectSlug, components, job, open, onOpenChange, onSaved,
}: {
  projectSlug: string
  components: { slug: string; name: string }[]
  job: ScheduledJob | null
  open: boolean
  onOpenChange: (v: boolean) => void
  onSaved: () => void
}) {
  const editing = !!job
  const [componentSlug, setComponentSlug] = useState('')
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [schedule, setSchedule] = useState('0 3 * * *')
  const [timezone, setTimezone] = useState('UTC')
  const [execMode, setExecMode] = useState<'run' | 'exec'>('run')
  const [commandText, setCommandText] = useState('')
  const [concurrency, setConcurrency] = useState<'forbid' | 'allow'>('forbid')
  const [timeout, setTimeout] = useState(3600)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!open) return
    if (job) {
      setComponentSlug(job.component_slug ?? '')
      setName(job.name)
      setSlug(job.slug)
      setSchedule(job.schedule)
      setTimezone(job.timezone)
      setExecMode(job.exec_mode)
      setCommandText((job.command ?? []).join('\n'))
      setConcurrency(job.concurrency_policy)
      setTimeout(job.timeout_seconds)
    } else {
      setComponentSlug(components[0]?.slug ?? '')
      setName(''); setSlug(''); setSchedule('0 3 * * *'); setTimezone('UTC')
      setExecMode('run'); setCommandText(''); setConcurrency('forbid'); setTimeout(3600)
    }
  }, [open, job, components])

  async function save() {
    const command = commandText.split('\n').map((l) => l.trim()).filter(Boolean)
    const payload: api.ScheduledJobInput = {
      name, schedule, timezone, command, exec_mode: execMode,
      concurrency_policy: concurrency, timeout_seconds: timeout,
    }
    setSaving(true)
    try {
      if (editing && job) {
        await api.updateScheduledJob(projectSlug, job.slug, payload)
        toast.success('İş güncellendi')
      } else {
        await api.createScheduledJob(projectSlug, { ...payload, component_slug: componentSlug, slug })
        toast.success('İş oluşturuldu')
      }
      onOpenChange(false)
      onSaved()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Kaydedilemedi')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{editing ? 'İşi Düzenle' : 'Yeni Zamanlanmış İş'}</DialogTitle>
          <DialogDescription>
            Bir component'in image'ini cron zamanında one-off container olarak çalıştırır.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          {!editing && (
            <div className="space-y-1.5">
              <Label>Component</Label>
              <Select value={componentSlug} onValueChange={setComponentSlug}>
                <SelectTrigger className="bg-background border-border"><SelectValue placeholder="Component seç" /></SelectTrigger>
                <SelectContent>
                  {components.map((c) => <SelectItem key={c.slug} value={c.slug}>{c.name} ({c.slug})</SelectItem>)}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">İş bu component'in image / env / secret / network'ünü miras alır.</p>
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>İsim</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Nightly scrape" />
            </div>
            {!editing && (
              <div className="space-y-1.5">
                <Label>Slug (opsiyonel)</Label>
                <Input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="nightly-scrape" />
              </div>
            )}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Cron</Label>
              <Input value={schedule} onChange={(e) => setSchedule(e.target.value)} placeholder="0 3 * * *" className="font-mono" />
            </div>
            <div className="space-y-1.5">
              <Label>Timezone</Label>
              <Select value={timezone} onValueChange={setTimezone}>
                <SelectTrigger className="bg-background border-border"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {COMMON_TZ.map((tz) => <SelectItem key={tz} value={tz}>{tz}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Çalışma modu</Label>
              <Select value={execMode} onValueChange={(v) => setExecMode(v as 'run' | 'exec')}>
                <SelectTrigger className="bg-background border-border"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="run">run — yeni container</SelectItem>
                  <SelectItem value="exec">exec — aktif container içinde</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Eşzamanlılık</Label>
              <Select value={concurrency} onValueChange={(v) => setConcurrency(v as 'forbid' | 'allow')}>
                <SelectTrigger className="bg-background border-border"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="forbid">forbid — üst üste bindirme</SelectItem>
                  <SelectItem value="allow">allow — paralel çalışabilir</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label>Komut (her satır bir argüman)</Label>
            <Textarea
              value={commandText}
              onChange={(e) => setCommandText(e.target.value)}
              placeholder={'python\nmanage.py\nscrape'}
              rows={3}
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">Boş bırakılırsa image'in varsayılan CMD'i çalışır.</p>
          </div>
          <div className="space-y-1.5">
            <Label>Zaman aşımı (saniye)</Label>
            <Input type="number" value={timeout} onChange={(e) => setTimeout(Number(e.target.value) || 0)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>İptal</Button>
          <Button onClick={save} disabled={saving || (!editing && !componentSlug) || !name || !schedule}>
            {saving ? 'Kaydediliyor…' : editing ? 'Güncelle' : 'Oluştur'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Run history (expandable) ───────────────────────────────────────────────

function RunHistory({ projectSlug, jobSlug }: { projectSlug: string; jobSlug: string }) {
  const [runs, setRuns] = useState<ScheduledJobRun[]>([])
  const [loading, setLoading] = useState(true)
  const [openRun, setOpenRun] = useState<number | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    api.listJobRuns(projectSlug, jobSlug, 20)
      .then(setRuns)
      .catch(() => setRuns([]))
      .finally(() => setLoading(false))
  }, [projectSlug, jobSlug])

  useEffect(() => { load() }, [load])

  if (loading) return <p className="text-xs text-muted-foreground px-4 py-3">Yükleniyor…</p>
  if (!runs.length) return <p className="text-xs text-muted-foreground px-4 py-3">Henüz çalışma yok.</p>

  return (
    <div className="divide-y divide-border">
      {runs.map((run) => (
        <div key={run.id}>
          <button
            className="flex w-full items-center gap-3 px-4 py-2 text-left text-sm hover:bg-muted/30 cursor-pointer"
            onClick={() => setOpenRun(openRun === run.id ? null : run.id)}
          >
            {openRun === run.id ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            <StatusBadge status={run.status} />
            <span className="text-muted-foreground">{run.trigger}</span>
            <span className="text-muted-foreground">{fmt(run.started_at ?? run.created_at)}</span>
            {run.exit_code != null && <span className="font-mono text-xs text-muted-foreground">exit {run.exit_code}</span>}
          </button>
          {openRun === run.id && (
            <div className="bg-muted/20 px-4 py-3 space-y-2">
              {run.error && <p className="text-xs text-red-300">{run.error}</p>}
              <pre className="max-h-64 overflow-auto rounded bg-background/60 p-2 text-xs whitespace-pre-wrap">
                {run.output || '(çıktı yok)'}
              </pre>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ── Job row ────────────────────────────────────────────────────────────────

function JobRow({
  projectSlug, job, onChanged, onEdit,
}: {
  projectSlug: string
  job: ScheduledJob
  onChanged: () => void
  onEdit: (j: ScheduledJob) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [busy, setBusy] = useState(false)

  async function toggle(enabled: boolean) {
    setBusy(true)
    try {
      await api.setScheduledJobEnabled(projectSlug, job.slug, enabled)
      onChanged()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Değiştirilemedi')
    } finally { setBusy(false) }
  }

  async function runNow() {
    setBusy(true)
    try {
      await api.triggerJobRun(projectSlug, job.slug)
      toast.success('Çalışma kuyruğa alındı')
      setExpanded(true)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Tetiklenemedi')
    } finally { setBusy(false) }
  }

  async function remove() {
    try {
      await api.deleteScheduledJob(projectSlug, job.slug)
      toast.success('İş silindi')
      onChanged()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Silinemedi')
    }
  }

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 px-4 py-3">
        <button className="cursor-pointer text-muted-foreground" onClick={() => setExpanded(!expanded)}>
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-medium truncate">{job.name}</span>
            <Badge variant="outline" className="font-mono text-xs">{job.component_slug}</Badge>
            {job.exec_mode === 'exec' && <Badge variant="outline" className="text-xs">exec</Badge>}
          </div>
          <div className="mt-0.5 flex items-center gap-3 text-xs text-muted-foreground">
            <span className="font-mono">{job.schedule} ({job.timezone})</span>
            <span>sonraki: {fmt(job.next_run_at)}</span>
          </div>
        </div>
        <Switch checked={job.enabled} disabled={busy} onCheckedChange={toggle} />
        <Button size="sm" variant="outline" disabled={busy} onClick={runNow}><Play className="h-3.5 w-3.5" /></Button>
        <Button size="sm" variant="outline" onClick={() => onEdit(job)}><Pencil className="h-3.5 w-3.5" /></Button>
        <Button size="sm" variant="outline" onClick={() => setConfirmDelete(true)}><Trash2 className="h-3.5 w-3.5" /></Button>
      </div>
      {expanded && (
        <div className="border-t border-border">
          <div className="flex items-center gap-2 px-4 pt-3 text-xs font-medium text-muted-foreground">
            <History className="h-3.5 w-3.5" /> Çalışma geçmişi
          </div>
          <RunHistory projectSlug={projectSlug} jobSlug={job.slug} />
        </div>
      )}

      <AlertDialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>İşi sil?</AlertDialogTitle>
            <AlertDialogDescription>
              "{job.name}" işi ve çalışma geçmişi kalıcı olarak silinecek.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>İptal</AlertDialogCancel>
            <AlertDialogAction onClick={remove}>Sil</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────

export default function ScheduledJobs() {
  const [projects, setProjects] = useState<DeployProjectSummary[]>([])
  const [selected, setSelected] = useState('')
  const [jobs, setJobs] = useState<ScheduledJob[]>([])
  const [loading, setLoading] = useState(false)
  const [editorOpen, setEditorOpen] = useState(false)
  const [editing, setEditing] = useState<ScheduledJob | null>(null)

  useEffect(() => {
    api.listDeployProjects()
      .then((p) => {
        setProjects(p)
        setSelected((cur) => cur || p[0]?.project.slug || '')
      })
      .catch((e) => toast.error(e instanceof Error ? e.message : 'Projeler yüklenemedi'))
  }, [])

  const loadJobs = useCallback(() => {
    if (!selected) { setJobs([]); return }
    setLoading(true)
    api.listScheduledJobs(selected)
      .then(setJobs)
      .catch((e) => toast.error(e instanceof Error ? e.message : 'İşler yüklenemedi'))
      .finally(() => setLoading(false))
  }, [selected])

  useEffect(() => { loadJobs() }, [loadJobs])

  const components = useMemo(() => {
    const proj = projects.find((p) => p.project.slug === selected)
    return (proj?.components ?? []).map((c) => ({ slug: c.slug, name: c.name }))
  }, [projects, selected])

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 border border-primary/30">
          <Clock className="h-4 w-4 text-primary" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-semibold tracking-tight">Zamanlanmış İşler</h1>
          <p className="text-sm text-muted-foreground">Cron tabanlı periyodik component çalıştırmaları</p>
        </div>
        <Button variant="outline" size="sm" onClick={loadJobs}><RefreshCw className="h-3.5 w-3.5" /></Button>
        <Button size="sm" disabled={!selected || !components.length} onClick={() => { setEditing(null); setEditorOpen(true) }}>
          <Plus className="h-3.5 w-3.5 mr-1" /> Yeni İş
        </Button>
      </div>

      <div className="flex items-center gap-3">
        <Label className="text-sm text-muted-foreground">Proje</Label>
        <Select value={selected} onValueChange={setSelected}>
          <SelectTrigger className="w-[260px] bg-background border-border"><SelectValue placeholder="Proje seç" /></SelectTrigger>
          <SelectContent>
            {projects.map((p) => <SelectItem key={p.project.slug} value={p.project.slug}>{p.project.name}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>

      {loading ? (
        <p className="text-sm text-muted-foreground">Yükleniyor…</p>
      ) : jobs.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border p-10 text-center">
          <Clock className="mx-auto h-8 w-8 text-muted-foreground/50" />
          <p className="mt-3 text-sm text-muted-foreground">
            {components.length ? 'Bu projede henüz zamanlanmış iş yok.' : 'Önce bu projeye bir component ekleyin.'}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {jobs.map((job) => (
            <JobRow key={job.id} projectSlug={selected} job={job} onChanged={loadJobs} onEdit={(j) => { setEditing(j); setEditorOpen(true) }} />
          ))}
        </div>
      )}

      <JobEditor
        projectSlug={selected}
        components={components}
        job={editing}
        open={editorOpen}
        onOpenChange={setEditorOpen}
        onSaved={loadJobs}
      />
    </div>
  )
}
