import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Rocket, RefreshCw, GitBranch, Clock, RotateCcw,
  GitCommit, Tag, Eye, EyeOff, Copy, Settings, Server, Play,
} from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import type { DeployComponent, DeployProjectSummary, Deployment, DeploymentEvent } from '@/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import {
  Dialog, DialogContent, DialogDescription,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { cn } from '@/lib/utils'

// ── Status colours ────────────────────────────────────────────────────────────

const statusTone: Record<string, string> = {
  pending:     'border-amber-400/40 text-amber-300 bg-amber-400/10',
  running:     'border-blue-400/40 text-blue-300 bg-blue-400/10',
  succeeded:   'border-emerald-400/40 text-emerald-300 bg-emerald-400/10',
  failed:      'border-red-400/40 text-red-300 bg-red-400/10',
  rolled_back: 'border-purple-400/40 text-purple-300 bg-purple-400/10',
  active:      'border-emerald-400/40 text-emerald-300 bg-emerald-400/10',
  warming:     'border-blue-400/40 text-blue-300 bg-blue-400/10',
  draining:    'border-amber-400/40 text-amber-300 bg-amber-400/10',
  unhealthy:   'border-red-400/40 text-red-300 bg-red-400/10',
  stopped:     'border-border text-muted-foreground bg-muted/20',
}

const eventDot: Record<string, string> = {
  started:   'bg-blue-400',
  succeeded: 'bg-emerald-400',
  failed:    'bg-red-400',
  put:       'bg-violet-400',
  queued:    'bg-amber-400',
}

// ── Manual Deploy Form ────────────────────────────────────────────────────────

function ManualDeployForm({
  project, onDeployed,
}: {
  project: DeployProjectSummary
  onDeployed: () => void
}) {
  const [releaseId, setReleaseId] = useState('')
  const [branch, setBranch] = useState('')
  const [commitSha, setCommitSha] = useState('')
  const [imageRefs, setImageRefs] = useState<Record<string, string>>(
    Object.fromEntries(project.components.map(c => [c.slug, '']))
  )
  const [deploying, setDeploying] = useState(false)

  async function handleDeploy() {
    if (!releaseId.trim()) { toast.error('Release ID is required'); return }
    const components: Record<string, { image_ref: string }> = {}
    for (const c of project.components) {
      const ref = imageRefs[c.slug]?.trim()
      if (!ref) { toast.error(`Image ref is required for component "${c.slug}"`); return }
      components[c.slug] = { image_ref: ref }
    }
    setDeploying(true)
    try {
      const result = await api.manualDeploy(project.project.slug, {
        release_id: releaseId.trim(),
        branch: branch.trim() || undefined,
        commit_sha: commitSha.trim() || undefined,
        components,
      })
      toast.success(result.idempotent ? 'Already queued' : 'Deployment queued successfully')
      onDeployed()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Deploy failed')
    } finally {
      setDeploying(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5 col-span-2">
          <Label className="text-xs">Release ID <span className="text-destructive">*</span></Label>
          <Input
            placeholder="v1.2.3 or git sha"
            className="font-mono text-sm"
            value={releaseId}
            onChange={e => setReleaseId(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Branch</Label>
          <Input placeholder="main" className="font-mono text-sm" value={branch} onChange={e => setBranch(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Commit SHA</Label>
          <Input placeholder="abc123..." className="font-mono text-sm" value={commitSha} onChange={e => setCommitSha(e.target.value)} />
        </div>
      </div>

      <div className="space-y-2">
        <Label className="text-xs font-semibold">Component Image Refs</Label>
        {project.components.map(c => (
          <div key={c.slug} className="space-y-1">
            <Label className="text-xs text-muted-foreground font-mono">{c.slug}</Label>
            <Input
              placeholder={`${c.image_repo}:latest`}
              className="font-mono text-xs"
              value={imageRefs[c.slug] ?? ''}
              onChange={e => setImageRefs(r => ({ ...r, [c.slug]: e.target.value }))}
            />
          </div>
        ))}
      </div>

      <Button onClick={handleDeploy} disabled={deploying} className="w-full gap-2 cursor-pointer">
        {deploying
          ? <RefreshCw className="h-3.5 w-3.5 animate-spin" />
          : <Play className="h-3.5 w-3.5" />}
        {deploying ? 'Deploying…' : 'Deploy'}
      </Button>
    </div>
  )
}

// ── Project Settings Dialog ───────────────────────────────────────────────────

function ProjectSettingsDialog({
  project, open, onClose, onSaved,
}: {
  project: DeployProjectSummary | null
  open: boolean
  onClose: () => void
  onSaved: () => void
}) {
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null)
  const [showSecret, setShowSecret]         = useState(false)
  const [loadingSecret, setLoadingSecret]   = useState(false)
  const [newSecret, setNewSecret]           = useState('')
  const [saving, setSaving]                 = useState(false)
  const [tab, setTab]                       = useState<'info' | 'deploy'>('info')

  useEffect(() => {
    if (!open) {
      setRevealedSecret(null)
      setShowSecret(false)
      setNewSecret('')
      setTab('info')
    }
  }, [open])

  if (!project) return null

  async function revealSecret() {
    if (!project) return
    setLoadingSecret(true)
    try {
      const res = await api.getDeployProjectSecret(project.project.slug)
      setRevealedSecret(res.secret)
      setShowSecret(true)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not load secret')
    } finally {
      setLoadingSecret(false)
    }
  }

  async function saveSecret() {
    if (!project) return
    if (!newSecret.trim()) { toast.error('Secret cannot be empty'); return }
    setSaving(true)
    try {
      await api.updateDeployProject(project.project.slug, { webhook_secret: newSecret })
      toast.success('Webhook secret updated')
      setNewSecret('')
      setRevealedSecret(null)
      setShowSecret(false)
      onSaved()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save secret')
    } finally {
      setSaving(false)
    }
  }

  function copySecret() {
    if (!revealedSecret) return
    navigator.clipboard.writeText(revealedSecret)
    toast.success('Copied to clipboard')
  }

  return (
    <Dialog open={open} onOpenChange={v => !v && onClose()}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Rocket className="h-4 w-4 text-primary" />
            {project.project.name}
            <span className="text-sm font-mono text-muted-foreground font-normal">{project.project.slug}</span>
          </DialogTitle>
          <DialogDescription>
            Webhook configuration, component status, and manual deploys
          </DialogDescription>
        </DialogHeader>

        {/* Tab switcher */}
        <div className="flex gap-1 rounded-md border border-border p-1 bg-muted/10">
          <button
            onClick={() => setTab('info')}
            className={cn(
              'flex-1 rounded px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer',
              tab === 'info' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
            )}
          >
            Info &amp; Secret
          </button>
          <button
            onClick={() => setTab('deploy')}
            className={cn(
              'flex-1 rounded px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer',
              tab === 'deploy' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
            )}
          >
            Manual Deploy
          </button>
        </div>

        {tab === 'info' && (
          <div className="space-y-5 pt-1">

            {/* ── Webhook secret ───────────────────────────────────── */}
            <div className="space-y-2">
              <Label className="text-sm font-medium">Webhook Secret</Label>
              <div className="flex items-center gap-1 rounded-md border border-border bg-muted/40 px-3 py-2">
                <code className="flex-1 font-mono text-xs break-all select-all min-w-0">
                  {revealedSecret !== null && showSecret
                    ? revealedSecret
                    : '••••••••••••••••••••••••'}
                </code>
                <Button
                  variant="ghost" size="icon" className="h-7 w-7 shrink-0 text-muted-foreground hover:text-foreground"
                  onClick={() => {
                    if (revealedSecret === null) revealSecret()
                    else setShowSecret(v => !v)
                  }}
                  disabled={loadingSecret}
                  title={showSecret ? 'Hide' : 'Reveal'}
                >
                  {loadingSecret
                    ? <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    : showSecret
                      ? <EyeOff className="h-3.5 w-3.5" />
                      : <Eye className="h-3.5 w-3.5" />}
                </Button>
                <Button
                  variant="ghost" size="icon" className="h-7 w-7 shrink-0 text-muted-foreground hover:text-foreground"
                  onClick={copySecret}
                  disabled={revealedSecret === null}
                  title="Copy to clipboard"
                >
                  <Copy className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>

            {/* ── Set new secret ───────────────────────────────────── */}
            <div className="space-y-2">
              <Label className="text-sm font-medium">Set New Secret</Label>
              <div className="flex gap-2">
                <Input
                  placeholder="New webhook secret"
                  value={newSecret}
                  onChange={e => setNewSecret(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && saveSecret()}
                  className="font-mono text-sm"
                />
                <Button onClick={saveSecret} disabled={saving || !newSecret.trim()} className="shrink-0">
                  {saving ? 'Saving…' : 'Save'}
                </Button>
              </div>
            </div>

            <Separator />

            {/* ── Components ───────────────────────────────────────── */}
            <div className="space-y-2">
              <Label className="text-sm font-medium">Components</Label>
              <div className="space-y-2">
                {project.components.map((c: DeployComponent) => {
                  const inst = project.instances.find(i => i.component_id === c.id && i.state === 'active')
                  return (
                    <div key={c.id} className="rounded-md border border-border bg-muted/10 p-3 space-y-1.5">
                      <div className="flex items-center gap-2">
                        <Server className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                        <span className="text-sm font-medium">{c.slug}</span>
                        <Badge variant="outline" className={cn('ml-auto text-[10px] px-1.5 py-0', statusTone[inst?.state ?? 'stopped'])}>
                          {inst?.state ?? 'stopped'}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground font-mono break-all pl-5">{c.image_repo}</p>
                      <p className="text-xs text-muted-foreground pl-5">
                        Port <span className="font-mono">{c.internal_port}</span>
                        {' · '}Health <span className="font-mono">{c.health_path}</span>
                        {' · '}Retries {c.restart_retries}
                      </p>
                      {inst && (
                        <p className="text-xs pl-5">
                          <span className="text-muted-foreground">Release </span>
                          <span className="font-mono">{inst.release_id || inst.release_uuid?.slice(0, 8)}</span>
                          <span className="text-muted-foreground"> · In-flight {inst.in_flight}</span>
                        </p>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

          </div>
        )}

        {tab === 'deploy' && (
          <div className="pt-1">
            <ManualDeployForm project={project} onDeployed={() => { onSaved(); setTab('info') }} />
          </div>
        )}

      </DialogContent>
    </Dialog>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Apps() {
  const [projects, setProjects]         = useState<DeployProjectSummary[]>([])
  const [deployments, setDeployments]   = useState<Deployment[]>([])
  const [events, setEvents]             = useState<DeploymentEvent[]>([])
  const [selectedId, setSelectedId]     = useState<string>('')
  const [loading, setLoading]           = useState(true)
  const [rerunning, setRerunning]       = useState(false)
  const [rerunConfirmOpen, setRerunConfirmOpen] = useState(false)
  const [settingsProject, setSettingsProject] = useState<DeployProjectSummary | null>(null)

  // Ref to avoid stale closure in setInterval
  const selectedIdRef = useRef<string>('')

  function applySelection(id: string) {
    selectedIdRef.current = id
    setSelectedId(id)
  }

  async function load(silent = false) {
    if (!silent) setLoading(true)
    try {
      const [projectData, deploymentData] = await Promise.all([
        api.listDeployProjects(),
        api.listDeployments(50),
      ])
      setProjects(projectData)
      setDeployments(deploymentData)

      const current = selectedIdRef.current || deploymentData[0]?.id || ''
      if (current) {
        selectedIdRef.current = current
        setSelectedId(current)
        setEvents(await api.listDeploymentEvents(current))
      } else {
        setEvents([])
      }
    } catch (err) {
      if (!silent) toast.error(err instanceof Error ? err.message : 'Could not load deployments')
    } finally {
      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const timer = window.setInterval(() => load(true), 10_000)
    return () => window.clearInterval(timer)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function selectDeployment(id: string) {
    applySelection(id)
    try {
      setEvents(await api.listDeploymentEvents(id))
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not load events')
    }
  }

  async function rerun() {
    if (!selectedIdRef.current) return
    setRerunning(true)
    try {
      const result = await api.rerunDeployment(selectedIdRef.current)
      toast.success(result.idempotent ? 'Already queued' : 'Re-queued successfully')
      await load(true)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not rerun')
    } finally {
      setRerunning(false)
    }
  }

  const selected = useMemo(
    () => deployments.find(d => d.id === selectedId),
    [deployments, selectedId],
  )

  return (
    <div className="h-full flex flex-col overflow-hidden">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="shrink-0 flex items-center justify-between px-6 py-3 border-b border-border">
        <div className="flex items-center gap-3">
          <Rocket className="h-4 w-4 text-primary" />
          <div>
            <h1 className="text-base font-semibold leading-none">Apps</h1>
            <p className="text-xs text-muted-foreground mt-0.5">Managed releases, active containers, deployment history</p>
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={() => load()} disabled={loading}>
          <RefreshCw className={cn('h-3.5 w-3.5 mr-1.5', loading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {/* ── Projects strip (compact, always visible) ────────────────────── */}
      <div className="shrink-0 px-6 py-3 border-b border-border bg-muted/5">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Projects</p>
        <div className="flex flex-wrap gap-2">
          {projects.map(proj => (
            <button
              key={proj.project.slug}
              onClick={() => setSettingsProject(proj)}
              className="group flex items-center gap-3 rounded-lg border border-border bg-card px-3 py-2 hover:bg-muted/40 hover:border-border/80 transition-colors text-left cursor-pointer"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium leading-none">{proj.project.name}</span>
                  <span className="text-[10px] font-mono text-muted-foreground">{proj.project.slug}</span>
                </div>
                <div className="flex gap-1.5 mt-1.5 flex-wrap">
                  {proj.components.map(c => {
                    const inst = proj.instances.find(i => i.component_id === c.id && i.state === 'active')
                    return (
                      <Badge
                        key={c.id}
                        variant="outline"
                        className={cn('text-[10px] px-1.5 py-0 leading-4', statusTone[inst?.state ?? 'stopped'])}
                      >
                        {c.slug}: {inst?.state ?? 'stopped'}
                      </Badge>
                    )
                  })}
                </div>
              </div>
              <Settings className="h-3.5 w-3.5 text-muted-foreground group-hover:text-foreground shrink-0 transition-colors" />
            </button>
          ))}
          {projects.length === 0 && !loading && (
            <p className="text-xs text-muted-foreground py-1">No projects configured.</p>
          )}
        </div>
      </div>

      {/* ── Deployments table + Timeline (fills remaining height) ───────── */}
      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* Deployments table */}
        <div className="flex flex-1 min-w-0 flex-col overflow-hidden">
          <div className="shrink-0 flex items-center gap-2 px-6 py-2.5 border-b border-border bg-muted/5">
            <GitBranch className="h-3.5 w-3.5 text-primary" />
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Deployments</span>
          </div>
          <div className="flex-1 overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 bg-background border-b border-border">
                <tr className="text-[11px] text-muted-foreground">
                  <th className="text-left px-6 py-2 font-medium">Project</th>
                  <th className="text-left px-4 py-2 font-medium">Release</th>
                  <th className="text-left px-4 py-2 font-medium">Status</th>
                  <th className="text-left px-4 py-2 font-medium">Trigger</th>
                  <th className="text-left px-4 py-2 font-medium">Created</th>
                </tr>
              </thead>
              <tbody>
                {deployments.map(dep => (
                  <tr
                    key={dep.id}
                    onClick={() => selectDeployment(dep.id)}
                    className={cn(
                      'border-b border-border/40 cursor-pointer transition-colors',
                      dep.id === selectedId
                        ? 'bg-primary/5 border-l-2 border-l-primary'
                        : 'hover:bg-muted/20',
                    )}
                  >
                    <td className="px-6 py-2.5 font-medium text-sm">{dep.project_slug}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">
                      {dep.release_id.slice(0, 12)}
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge variant="outline" className={cn('text-xs', statusTone[dep.status])}>
                        {dep.status}
                      </Badge>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{dep.trigger}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(dep.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
                {deployments.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-6 py-16 text-center text-muted-foreground text-sm">
                      No deployments yet
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Timeline panel */}
        <div className="w-80 xl:w-96 shrink-0 flex flex-col overflow-hidden border-l border-border">
          <div className="shrink-0 flex items-center gap-2 px-4 py-2.5 border-b border-border bg-muted/5">
            <Clock className="h-3.5 w-3.5 text-primary" />
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex-1">Timeline</span>
            {selected && (
              <Button
                size="sm" variant="outline"
                className="h-7 text-xs gap-1 px-2 cursor-pointer"
                onClick={() => setRerunConfirmOpen(true)}
                disabled={rerunning}
              >
                <RotateCcw className={cn('h-3 w-3', rerunning && 'animate-spin')} />
                Rerun
              </Button>
            )}
          </div>
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
            {selected ? (
              <>
                <div className="rounded-md border border-border bg-muted/20 p-3 space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant="outline" className={cn('text-xs', statusTone[selected.status])}>
                      {selected.status}
                    </Badge>
                    <span className="font-mono text-xs text-muted-foreground">
                      {selected.release_id.slice(0, 12)}
                    </span>
                  </div>
                  {selected.branch && (
                    <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <GitBranch className="h-3 w-3 shrink-0" />
                      <span>{selected.branch}</span>
                    </div>
                  )}
                  {selected.commit_sha && (
                    <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <GitCommit className="h-3 w-3 shrink-0" />
                      <span className="font-mono">{selected.commit_sha.slice(0, 12)}</span>
                    </div>
                  )}
                  {selected.repo && (
                    <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <Tag className="h-3 w-3 shrink-0" />
                      <span className="truncate">{selected.repo}</span>
                    </div>
                  )}
                  {selected.error && (
                    <p className="text-xs text-red-300 break-words">{selected.error}</p>
                  )}
                </div>

                <div className="space-y-0">
                  {events.map((ev, idx) => (
                    <div key={ev.id} className="flex gap-2.5">
                      <div className="flex flex-col items-center shrink-0 pt-1">
                        <span className={cn('h-2 w-2 rounded-full shrink-0', eventDot[ev.event_type] ?? 'bg-muted-foreground/50')} />
                        {idx < events.length - 1 && (
                          <span className="w-px flex-1 bg-border/60 mt-1 mb-0" />
                        )}
                      </div>
                      <div className="pb-3 min-w-0">
                        <div className="flex items-baseline gap-2">
                          <span className="text-xs font-medium">{ev.event_type}</span>
                          <span className="text-[10px] text-muted-foreground">
                            {new Date(ev.created_at).toLocaleTimeString()}
                          </span>
                        </div>
                        {ev.message && (
                          <p className="text-xs text-muted-foreground mt-0.5 break-words">{ev.message}</p>
                        )}
                      </div>
                    </div>
                  ))}
                  {events.length === 0 && (
                    <p className="text-xs text-muted-foreground">No events recorded yet.</p>
                  )}
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Select a deployment to see its timeline.</p>
            )}
          </div>
        </div>
      </div>

      {/* ── Rerun confirmation ───────────────────────────────────────────── */}
      <AlertDialog open={rerunConfirmOpen} onOpenChange={setRerunConfirmOpen}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle>Rerun Deployment</AlertDialogTitle>
            <AlertDialogDescription>
              Re-queue deployment{' '}
              <code className="font-mono text-foreground">{selected?.release_id.slice(0, 12)}</code>
              {' '}for project{' '}
              <code className="font-mono text-foreground">{selected?.project_slug}</code>?
              A new deployment will be created with the same payload.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer border-border">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="cursor-pointer"
              onClick={() => { setRerunConfirmOpen(false); rerun() }}
            >
              Rerun
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── Project settings dialog ──────────────────────────────────────── */}
      <ProjectSettingsDialog
        project={settingsProject}
        open={settingsProject !== null}
        onClose={() => setSettingsProject(null)}
        onSaved={() => { setSettingsProject(null); load(true) }}
      />
    </div>
  )
}
