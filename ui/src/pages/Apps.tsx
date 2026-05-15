import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Rocket, RefreshCw, GitBranch, Clock, RotateCcw,
  GitCommit, Tag, Eye, EyeOff, Copy, Settings, Server, Play, HardDrive,
  Terminal, Plus, Pencil, Trash2, Lock, Undo2, Pause, PlayCircle,
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
import { NewAppDialog } from '@/components/NewAppDialog'
import { ComponentEditorDialog } from '@/components/ComponentEditorDialog'

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
  onEditComponent, onAddComponent, onDeleteComponent, onDeleteProject,
  onTogglePause,
}: {
  project: DeployProjectSummary | null
  open: boolean
  onClose: () => void
  onSaved: () => void
  onEditComponent: (slug: string) => void
  onAddComponent: () => void
  onDeleteComponent: (slug: string) => void
  onDeleteProject: () => void
  onTogglePause: (slug: string, next: boolean) => void
}) {
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null)
  const [showSecret, setShowSecret]         = useState(false)
  const [loadingSecret, setLoadingSecret]   = useState(false)
  const [newSecret, setNewSecret]           = useState('')
  const [saving, setSaving]                 = useState(false)
  const [tab, setTab]                       = useState<'info' | 'deploy' | 'cicd'>('info')

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
          {([
            ['info', 'Bilgiler'],
            ['cicd', 'CI/CD'],
            ['deploy', 'Manuel Deploy'],
          ] as const).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={cn(
                'flex-1 rounded px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer',
                tab === key ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              {label}
            </button>
          ))}
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
              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium">Servisler</Label>
                <Button size="sm" variant="outline" className="h-7" onClick={onAddComponent}>
                  <Plus className="h-3 w-3 mr-1" /> Servis ekle
                </Button>
              </div>
              <div className="space-y-2">
                {(project.components ?? []).map((c: DeployComponent) => {
                  const inst = (project.instances ?? []).find(i => i.component_id === c.id && i.state === 'active')
                  const secretCount = (c.env_secret_keys ?? []).length
                  const envCount = Object.keys(c.env ?? {}).length
                  return (
                    <div key={c.id} className="rounded-md border border-border bg-muted/10 p-3 space-y-1.5">
                      <div className="flex items-center gap-2">
                        <Server className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                        <span className="text-sm font-medium">{c.slug}</span>
                        <Badge variant="outline" className={cn('text-[10px] px-1.5 py-0', statusTone[inst?.state ?? 'stopped'])}>
                          {inst?.state ?? 'stopped'}
                        </Badge>
                        {c.paused && (
                          <Badge variant="outline" className="text-[10px] text-amber-300 border-amber-400/40">
                            duraklatıldı
                          </Badge>
                        )}
                        <div className="ml-auto flex items-center gap-1">
                          <Button
                            size="icon" variant="ghost"
                            className={cn(
                              'h-7 w-7 cursor-pointer',
                              c.paused ? 'text-emerald-400 hover:text-emerald-300' : 'text-muted-foreground hover:text-amber-300',
                            )}
                            onClick={() => onTogglePause(c.slug, !c.paused)}
                            title={c.paused ? 'Devam ettir' : 'Duraklat'}
                          >
                            {c.paused
                              ? <PlayCircle className="h-3.5 w-3.5" />
                              : <Pause className="h-3.5 w-3.5" />}
                          </Button>
                          <Button
                            size="icon" variant="ghost"
                            className="h-7 w-7 text-muted-foreground hover:text-foreground cursor-pointer"
                            onClick={() => onEditComponent(c.slug)}
                            title="Düzenle"
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            size="icon" variant="ghost"
                            className="h-7 w-7 text-muted-foreground hover:text-destructive cursor-pointer"
                            onClick={() => onDeleteComponent(c.slug)}
                            title="Sil"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground font-mono break-all pl-5">{c.image_repo}</p>
                      <p className="text-xs text-muted-foreground pl-5">
                        Port <span className="font-mono">{c.internal_port}</span>
                        {' · '}Health <span className="font-mono">{c.health_path}</span>
                        {' · '}Retries {c.restart_retries}
                      </p>
                      {envCount > 0 && (
                        <p className="text-xs text-muted-foreground pl-5 flex items-center gap-1.5">
                          <span>{envCount} env değişkeni</span>
                          {secretCount > 0 && (
                            <span className="inline-flex items-center gap-0.5 text-amber-300">
                              <Lock className="h-3 w-3" /> {secretCount} gizli
                            </span>
                          )}
                        </p>
                      )}
                      {c.mounts && c.mounts.length > 0 && (
                        <div className="pl-5 space-y-0.5">
                          {c.mounts.map((m, idx) => (
                            <p key={idx} className="text-xs text-muted-foreground flex items-center gap-1.5">
                              <HardDrive className="h-3 w-3 shrink-0" />
                              <span className="font-mono break-all">
                                {m.type === 'tmpfs'
                                  ? `tmpfs → ${m.target}`
                                  : `${m.source ?? '(anon)'} → ${m.target}`}
                              </span>
                              <span className="text-[10px] uppercase opacity-70">{m.type}{m.read_only ? '·ro' : ''}</span>
                            </p>
                          ))}
                        </div>
                      )}
                      {inst && (
                        <div className="pl-5 flex items-center justify-between gap-2">
                          <p className="text-xs">
                            <span className="text-muted-foreground">Release </span>
                            <span className="font-mono">{inst.release_id || inst.release_uuid?.slice(0, 8)}</span>
                            <span className="text-muted-foreground"> · In-flight {inst.in_flight}</span>
                          </p>
                          {/* Edge component: agent'a "container restart"
                              komutu gönder. agent_id set olmayan central
                              component'lerde anlamı yok (muvon-deployer
                              zaten DB üstünden yönetiyor). */}
                          {c.agent_id && inst.container_id && (
                            <Button
                              size="sm" variant="ghost"
                              className="h-6 px-2 text-[11px] gap-1 text-muted-foreground hover:text-foreground"
                              title="Bu instance'ın container'ını restart et"
                              onClick={async () => {
                                try {
                                  await api.enqueueAgentCommand(c.agent_id, {
                                    kind: 'container.restart',
                                    payload: { container_id: inst.container_id, timeout: 10 },
                                  })
                                  toast.success('Restart komutu gönderildi')
                                } catch (err) {
                                  toast.error(err instanceof Error ? err.message : 'Komut gönderilemedi')
                                }
                              }}
                            >
                              <RotateCcw className="h-3 w-3" />
                              Restart
                            </Button>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
                {project.components.length === 0 && (
                  <p className="text-xs text-muted-foreground py-3 text-center">
                    Henüz servis eklenmemiş.
                  </p>
                )}
              </div>
            </div>

            <Separator />

            {/* ── Danger zone ──────────────────────────────────────── */}
            <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 flex items-center justify-between">
              <div className="min-w-0">
                <p className="text-sm font-medium text-destructive">Uygulamayı sil</p>
                <p className="text-xs text-muted-foreground">
                  Servisler, release geçmişi ve deployment kayıtları kalıcı olarak silinir. Container'lar drain edilir.
                </p>
              </div>
              <Button variant="destructive" size="sm" onClick={onDeleteProject} className="shrink-0">
                Sil
              </Button>
            </div>

          </div>
        )}

        {tab === 'cicd' && (
          <CICDPanel project={project} revealedSecret={revealedSecret} onRevealSecret={revealSecret} loadingSecret={loadingSecret} />
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

// ── CI/CD Panel ───────────────────────────────────────────────────────────────
//
// Shows the operator everything their pipeline needs: the webhook URL,
// the shared secret, and ready-to-copy snippets for GitHub Actions and
// generic curl. Snippets reference env vars (`MUVON_WEBHOOK_SECRET`)
// rather than embedding the secret directly — operators paste them
// straight into their CI config without leaking the value into source.

function CICDPanel({
  project, revealedSecret, onRevealSecret, loadingSecret,
}: {
  project: DeployProjectSummary
  revealedSecret: string | null
  onRevealSecret: () => void
  loadingSecret: boolean
}) {
  const [cicdTab, setCicdTab] = useState<'github' | 'gitlab' | 'curl'>('github')
  // Prefer the page's origin; in dev this is the Vite proxy host, in prod
  // it's the admin domain — both correct targets for the webhook.
  const webhookURL = `${window.location.origin}/api/deploy/webhook`
  const projectSlug = project.project.slug
  const firstComponent = project.components[0]?.slug ?? 'web'

  function copy(value: string) {
    navigator.clipboard.writeText(value)
    toast.success('Panoya kopyalandı')
  }

  const ghaSnippet = `name: Deploy

on:
  push:
    tags: ['v*']

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # build + push your image here, then notify MUVON:
      - name: MUVON deploy
        env:
          WEBHOOK_URL: ${webhookURL}
          WEBHOOK_SECRET: \${{ secrets.MUVON_WEBHOOK_SECRET }}
          IMAGE_TAG: \${{ github.ref_name }}
        run: |
          PAYLOAD=$(jq -nc \\
            --arg project "${projectSlug}" \\
            --arg release "$IMAGE_TAG" \\
            --arg commit "\${{ github.sha }}" \\
            --arg image "ghcr.io/\${{ github.repository }}:$IMAGE_TAG" \\
            '{project:$project, release_id:$release, commit_sha:$commit,
              components:{"${firstComponent}":{image_ref:$image}}}')
          SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $2}')
          curl -fsS -X POST "$WEBHOOK_URL" \\
            -H "Content-Type: application/json" \\
            -H "X-Muvon-Signature-256: sha256=$SIG" \\
            --data "$PAYLOAD"`

  const gitlabSnippet = `deploy:
  stage: deploy
  image: alpine:latest
  before_script:
    - apk add --no-cache curl jq openssl
  script:
    - |
      PAYLOAD=$(jq -nc \\
        --arg project "${projectSlug}" \\
        --arg release "$CI_COMMIT_TAG" \\
        --arg commit "$CI_COMMIT_SHA" \\
        --arg image "$CI_REGISTRY_IMAGE:$CI_COMMIT_TAG" \\
        '{project:$project, release_id:$release, commit_sha:$commit,
          components:{"${firstComponent}":{image_ref:$image}}}')
      SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$MUVON_WEBHOOK_SECRET" | awk '{print $2}')
      curl -fsS -X POST "${webhookURL}" \\
        -H "Content-Type: application/json" \\
        -H "X-Muvon-Signature-256: sha256=$SIG" \\
        --data "$PAYLOAD"
  rules:
    - if: $CI_COMMIT_TAG`

  const curlSnippet = `# Replace with your image tag, then run:
PAYLOAD='{"project":"${projectSlug}","release_id":"v1.0.0","components":{"${firstComponent}":{"image_ref":"ghcr.io/firma/uygulama:v1.0.0"}}}'
SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$MUVON_WEBHOOK_SECRET" | awk '{print $2}')
curl -fsS -X POST "${webhookURL}" \\
  -H "Content-Type: application/json" \\
  -H "X-Muvon-Signature-256: sha256=$SIG" \\
  --data "$PAYLOAD"`

  const snippet = cicdTab === 'github' ? ghaSnippet : cicdTab === 'gitlab' ? gitlabSnippet : curlSnippet

  return (
    <div className="space-y-4 pt-1">
      <div className="space-y-2">
        <Label className="text-sm font-medium">Webhook URL</Label>
        <div className="flex items-center gap-1 rounded-md border border-border bg-muted/40 px-3 py-2">
          <code className="flex-1 font-mono text-xs break-all select-all">{webhookURL}</code>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => copy(webhookURL)} title="Kopyala">
            <Copy className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      <div className="space-y-2">
        <Label className="text-sm font-medium">Webhook Secret</Label>
        <div className="flex items-center gap-2">
          <code className="flex-1 font-mono text-xs px-3 py-2 rounded-md border border-border bg-muted/40 break-all select-all">
            {revealedSecret ?? '••••••••••••••••'}
          </code>
          <Button variant="outline" size="sm" onClick={onRevealSecret} disabled={loadingSecret}>
            {loadingSecret ? 'Yükleniyor…' : revealedSecret ? 'Yenile' : 'Göster'}
          </Button>
          {revealedSecret && (
            <Button variant="ghost" size="icon" className="h-9 w-9" onClick={() => copy(revealedSecret)} title="Kopyala">
              <Copy className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
        <p className="text-[11px] text-muted-foreground">
          CI ortamında <code className="font-mono">MUVON_WEBHOOK_SECRET</code> olarak sakla. Snippet'ler bu isimle bekler.
        </p>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label className="text-sm font-medium">Hızlı başlangıç</Label>
          <Button variant="ghost" size="sm" onClick={() => copy(snippet)} className="h-7 text-xs">
            <Copy className="h-3 w-3 mr-1" /> Kopyala
          </Button>
        </div>
        <div className="flex gap-1 rounded-md border border-border p-1 bg-muted/10">
          {([
            ['github', 'GitHub Actions'],
            ['gitlab', 'GitLab CI'],
            ['curl', 'curl'],
          ] as const).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setCicdTab(key)}
              className={cn(
                'flex-1 rounded px-3 py-1 text-[11px] font-medium transition-colors cursor-pointer',
                cicdTab === key ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              {label}
            </button>
          ))}
        </div>
        <pre className="text-[11px] font-mono bg-muted/20 border border-border rounded-md p-3 overflow-auto max-h-72 whitespace-pre">
{snippet}
        </pre>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

interface AppsProps {
  // When set, restricts the page to one host class:
  //   'central' — only projects whose every component runs on central
  //   'edge'    — only projects with at least one component on an agent
  // Undefined = show everything (kept so the page works without the
  // category routes, e.g. if a future settings link points here directly).
  hostFilter?: 'central' | 'edge'
}

export default function Apps({ hostFilter }: AppsProps = {}) {
  const [projects, setProjects]         = useState<DeployProjectSummary[]>([])
  const [deployments, setDeployments]   = useState<Deployment[]>([])
  const [events, setEvents]             = useState<DeploymentEvent[]>([])
  const [selectedId, setSelectedId]     = useState<string>('')
  const [loading, setLoading]           = useState(true)
  const [rerunning, setRerunning]       = useState(false)
  const [rerunConfirmOpen, setRerunConfirmOpen] = useState(false)
  const [settingsProject, setSettingsProject] = useState<DeployProjectSummary | null>(null)
  // New app + service editing + destructive confirmation state.
  const [newAppOpen, setNewAppOpen] = useState(false)
  const [editingComponent, setEditingComponent] = useState<{ project: string; component: string | null } | null>(null)
  const [deleteComponentTarget, setDeleteComponentTarget] = useState<{ project: string; component: string } | null>(null)
  const [deleteProjectTarget, setDeleteProjectTarget] = useState<string | null>(null)

  // Ref to avoid stale closure in setInterval
  const selectedIdRef = useRef<string>('')

  function applySelection(id: string) {
    selectedIdRef.current = id
    setSelectedId(id)
  }

  // Project belongs on the "edge" page when at least one of its services
  // is bound to an agent. Empty-projects (no components yet) fall on the
  // central page by default — that's where the operator just landed.
  function matchesHost(p: DeployProjectSummary): boolean {
    if (!hostFilter) return true
    const anyEdge = (p.components ?? []).some(c => (c.agent_id ?? '') !== '')
    return hostFilter === 'edge' ? anyEdge : !anyEdge
  }

  async function load(silent = false) {
    if (!silent) setLoading(true)
    try {
      const [projectData, deploymentData] = await Promise.all([
        api.listDeployProjects(),
        api.listDeployments(50),
      ])
      const filteredProjects = projectData.filter(matchesHost)
      const projectSlugs = new Set(filteredProjects.map(p => p.project.slug))
      // Deployments list shows only those whose project survived the
      // host filter — keeps the timeline pane focused on this page.
      const filteredDeployments = hostFilter
        ? deploymentData.filter(d => projectSlugs.has(d.project_slug ?? ''))
        : deploymentData
      setProjects(filteredProjects)
      setDeployments(filteredDeployments)

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
    // `load` reads `hostFilter` via closure on every render; we want a
    // single timer that latches the current filter at mount. Re-running
    // this effect on every render would churn the interval.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostFilter])

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

  async function confirmDeleteComponent() {
    if (!deleteComponentTarget) return
    const { project, component } = deleteComponentTarget
    try {
      await api.deleteDeployComponent(project, component)
      toast.success('Servis silindi')
      setDeleteComponentTarget(null)
      await load(true)
      // Refresh the open settings dialog if it points at this project.
      if (settingsProject?.project.slug === project) {
        const fresh = (await api.listDeployProjects()).find(p => p.project.slug === project)
        if (fresh) setSettingsProject(fresh)
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Servis silinemedi')
    }
  }

  async function confirmDeleteProject() {
    if (!deleteProjectTarget) return
    const slug = deleteProjectTarget
    try {
      await api.deleteDeployProject(slug)
      toast.success('Uygulama silindi')
      setDeleteProjectTarget(null)
      setSettingsProject(null)
      await load(true)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Uygulama silinemedi')
    }
  }

  async function refreshSettingsProject(slug: string) {
    const fresh = (await api.listDeployProjects()).find(p => p.project.slug === slug)
    if (fresh) setSettingsProject(fresh)
  }

  async function togglePause(projectSlug: string, componentSlug: string, next: boolean) {
    try {
      await api.updateDeployComponent(projectSlug, componentSlug, { paused: next })
      toast.success(next ? 'Servis duraklatıldı' : 'Servis devam ediyor')
      await load(true)
      if (settingsProject?.project.slug === projectSlug) {
        await refreshSettingsProject(projectSlug)
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Durum değiştirilemedi')
    }
  }

  async function rollbackProject(projectSlug: string, fromReleaseID: string) {
    try {
      const r = await api.rollbackProject(projectSlug, { from_release_id: fromReleaseID })
      toast.success(`Geri alma kuyruğa eklendi (hedef ${r.rolled_to})`)
      await load(true)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Rollback başarısız')
    }
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="shrink-0 flex items-center justify-between px-6 py-3 border-b border-border">
        <div className="flex items-center gap-3">
          <Rocket className="h-4 w-4 text-primary" />
          <div>
            <h1 className="text-base font-semibold leading-none">
              {hostFilter === 'edge' ? 'Uzak Uygulamalar' : 'Uygulamalar'}
            </h1>
            <p className="text-xs text-muted-foreground mt-0.5">
              {hostFilter === 'edge'
                ? "Müşterilerin kendi sunucularında, agent ile çalışan uygulamalar"
                : 'Bu MUVON sunucusunda yönetilen release\'ler, container\'lar, deploy geçmişi'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={() => setNewAppOpen(true)}>
            <Plus className="h-3.5 w-3.5 mr-1.5" />
            Yeni Uygulama
          </Button>
          <Button variant="outline" size="sm" onClick={() => load()} disabled={loading}>
            <RefreshCw className={cn('h-3.5 w-3.5 mr-1.5', loading && 'animate-spin')} />
            Yenile
          </Button>
        </div>
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
                  {(proj.components ?? []).map(c => {
                    const inst = (proj.instances ?? []).find(i => i.component_id === c.id && i.state === 'active')
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
            <button
              onClick={() => setNewAppOpen(true)}
              className="group flex items-center gap-2 rounded-lg border border-dashed border-border bg-muted/5 px-3 py-2 hover:bg-muted/20 hover:border-primary/40 transition-colors cursor-pointer"
            >
              <Plus className="h-3.5 w-3.5 text-muted-foreground group-hover:text-primary" />
              <span className="text-xs text-muted-foreground group-hover:text-foreground">İlk uygulamanı ekle</span>
            </button>
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
              <div className="flex items-center gap-1">
                <Button
                  size="sm" variant="outline"
                  className="h-7 text-xs gap-1 px-2 cursor-pointer"
                  onClick={() => setRerunConfirmOpen(true)}
                  disabled={rerunning}
                >
                  <RotateCcw className={cn('h-3 w-3', rerunning && 'animate-spin')} />
                  Rerun
                </Button>
                {selected.status === 'succeeded' && (
                  <Button
                    size="sm" variant="outline"
                    className="h-7 text-xs gap-1 px-2 cursor-pointer"
                    onClick={() => rollbackProject(selected.project_slug ?? '', selected.release_id)}
                    title="Bu release'den bir önceki başarılı release'e geri al"
                  >
                    <Undo2 className="h-3 w-3" />
                    Geri al
                  </Button>
                )}
              </div>
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
                  {/* Pivot to container logs filtered by this release.
                      A failed-but-promoted deploy with no apparent error
                      in events is exactly the case where stdout from the
                      container is the only place to look — one click. */}
                  <div className="pt-1">
                    <Link
                      to={`/container-logs?tab=history&release_id=${encodeURIComponent(selected.release_id)}`}
                      className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
                    >
                      <Terminal className="h-3 w-3" /> Container logs
                    </Link>
                  </div>
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
        onEditComponent={(slug) => {
          if (!settingsProject) return
          setEditingComponent({ project: settingsProject.project.slug, component: slug })
        }}
        onAddComponent={() => {
          if (!settingsProject) return
          setEditingComponent({ project: settingsProject.project.slug, component: null })
        }}
        onDeleteComponent={(slug) => {
          if (!settingsProject) return
          setDeleteComponentTarget({ project: settingsProject.project.slug, component: slug })
        }}
        onDeleteProject={() => {
          if (!settingsProject) return
          setDeleteProjectTarget(settingsProject.project.slug)
        }}
        onTogglePause={(slug, next) => {
          if (!settingsProject) return
          togglePause(settingsProject.project.slug, slug, next)
        }}
      />

      {/* ── New app wizard ───────────────────────────────────────────────── */}
      <NewAppDialog
        open={newAppOpen}
        onClose={() => setNewAppOpen(false)}
        onCreated={(slug) => { load(true); /* open new project's settings so the operator can verify */
          setTimeout(() => {
            api.listDeployProjects().then(list => {
              const proj = list.find(p => p.project.slug === slug)
              if (proj) setSettingsProject(proj)
            }).catch(() => {})
          }, 200)
        }}
      />

      {/* ── Component editor (create/edit) ───────────────────────────────── */}
      <ComponentEditorDialog
        open={editingComponent !== null}
        projectSlug={editingComponent?.project ?? ''}
        componentSlug={editingComponent?.component ?? null}
        onClose={() => setEditingComponent(null)}
        onSaved={() => {
          if (settingsProject) refreshSettingsProject(settingsProject.project.slug)
          load(true)
        }}
      />

      {/* ── Delete component confirm ─────────────────────────────────────── */}
      <AlertDialog
        open={deleteComponentTarget !== null}
        onOpenChange={(v) => !v && setDeleteComponentTarget(null)}
      >
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle>Servisi sil</AlertDialogTitle>
            <AlertDialogDescription>
              <code className="font-mono text-foreground">{deleteComponentTarget?.component}</code>
              {' '}servisini silmek istediğinden emin misin? Aktif container'lar drain edilir.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer border-border">Vazgeç</AlertDialogCancel>
            <AlertDialogAction
              className="cursor-pointer bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={confirmDeleteComponent}
            >
              Sil
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── Delete project confirm ───────────────────────────────────────── */}
      <AlertDialog
        open={deleteProjectTarget !== null}
        onOpenChange={(v) => !v && setDeleteProjectTarget(null)}
      >
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle>Uygulamayı sil</AlertDialogTitle>
            <AlertDialogDescription>
              <code className="font-mono text-foreground">{deleteProjectTarget}</code>
              {' '}uygulamasını silmek üzeresin. Bu işlem servisleri, release'leri ve
              deployment kayıtlarını kalıcı olarak siler. Geri alınamaz.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer border-border">Vazgeç</AlertDialogCancel>
            <AlertDialogAction
              className="cursor-pointer bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={confirmDeleteProject}
            >
              Kalıcı olarak sil
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
