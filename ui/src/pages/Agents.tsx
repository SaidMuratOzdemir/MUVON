import { useEffect, useState, useCallback } from 'react'
import {
  Plus, Trash2, Copy, Check, Server, KeyRound,
  RefreshCw, Terminal, ChevronDown, ChevronRight, Wifi, WifiOff,
  Save, Loader2, FolderTree,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription, AlertDialogFooter,
  AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { cn } from '@/lib/utils'
import * as api from '@/api'
import type { Agent } from '@/types'
import { AgentActionMenu } from '@/components/AgentActionMenu'
import { AgentCommandHistory } from '@/components/AgentCommandHistory'

const ONLINE_THRESHOLD_MS = 5 * 60 * 1000 // 5 dakika

function agentOnlineStatus(lastSeenAt?: string | null): { online: boolean; label: string } {
  if (!lastSeenAt) return { online: false, label: 'Never connected' }
  const diff = Date.now() - new Date(lastSeenAt).getTime()
  if (diff < ONLINE_THRESHOLD_MS) return { online: true, label: 'Online' }
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return { online: false, label: `${mins}m ago` }
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return { online: false, label: `${hrs}h ago` }
  return { online: false, label: `${Math.floor(hrs / 24)}d ago` }
}

function CopyButton({ text, className }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      onClick={copy}
      title="Copy"
      className={cn('text-muted-foreground hover:text-foreground transition-colors cursor-pointer', className)}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-primary" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  )
}

function DeployInstructions({ agent, apiKey }: { agent: Agent; apiKey: string }) {
  const [open, setOpen] = useState(false)

  const envBlock = `AGENT_CENTRAL_URL=https://<your-central-host>:9443
AGENT_API_KEY=${apiKey}
AGENT_HTTP_ADDR=:80
AGENT_HTTPS_ADDR=:443
# optional — log forwarding to diaLOG:
AGENT_LOG_ADDR=<your-central-host>:9001`

  return (
    <div className="mt-3 rounded-md border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium text-muted-foreground hover:text-foreground hover:bg-muted/10 transition-colors cursor-pointer"
      >
        <Terminal className="h-3.5 w-3.5" />
        Deploy instructions
        {open ? <ChevronDown className="h-3 w-3 ml-auto" /> : <ChevronRight className="h-3 w-3 ml-auto" />}
      </button>
      {open && (
        <div className="border-t border-border bg-muted/5 p-3 space-y-3">
          <p className="text-xs text-muted-foreground">
            On the tenant machine, run the agent binary with these environment variables:
          </p>
          <div className="relative group">
            <pre className="text-xs font-mono bg-background border border-border rounded p-3 overflow-x-auto whitespace-pre text-foreground">
              {envBlock}
            </pre>
            <div className="absolute top-2 right-2">
              <CopyButton text={envBlock} />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            Or pass as flags: <code className="font-mono text-foreground">./agent -central https://... -api-key {apiKey.slice(0, 8)}…</code>
            {' '}<span className="opacity-70">(agent: {agent.id.slice(0, 8)})</span>
          </p>
        </div>
      )}
    </div>
  )
}

// ExtraMountsEditor lets the operator pin host directories to the agent's
// container at run time. Edits the agents.extra_mounts column through the
// admin API; the agent picks the new list up on its next config pull and
// the next agent.self_upgrade fires the helper container that rewrites
// compose. UI shows a banner reminding the operator that save alone
// doesn't mount — they still need to fire self_upgrade from the action
// menu (or it happens implicitly during the next upgrade).
function ExtraMountsEditor({
  agentID, initial, onSaved,
}: {
  agentID: string
  initial: string[]
  onSaved: () => void
}) {
  const [text, setText] = useState(initial.join('\n'))
  const [saved, setSaved] = useState(initial.join('\n'))
  const [saving, setSaving] = useState(false)
  const [restarting, setRestarting] = useState(false)
  const isDirty = text !== saved

  async function handleSave() {
    setSaving(true)
    try {
      const mounts = text.split('\n').map(s => s.trim()).filter(Boolean)
      await api.updateAgentMounts(agentID, mounts)
      setSaved(mounts.join('\n'))
      setText(mounts.join('\n'))
      toast.success('Mount yolları kaydedildi')
      onSaved()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Kayıt başarısız')
    } finally {
      setSaving(false)
    }
  }

  async function handleSaveAndApply() {
    setSaving(true)
    try {
      const mounts = text.split('\n').map(s => s.trim()).filter(Boolean)
      await api.updateAgentMounts(agentID, mounts)
      setSaved(mounts.join('\n'))
      setText(mounts.join('\n'))
      setSaving(false)
      setRestarting(true)
      await api.enqueueAgentCommand(agentID, { kind: 'agent.self_upgrade' })
      toast.success('Mount yolları kaydedildi + agent recreate kuyruğa alındı')
      onSaved()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'İşlem başarısız')
    } finally {
      setSaving(false)
      setRestarting(false)
    }
  }

  return (
    <div className="space-y-2 rounded border border-border/60 bg-background/40 p-3">
      <div className="flex items-center gap-2">
        <FolderTree className="h-3.5 w-3.5 text-muted-foreground" />
        <Label className="text-xs font-medium">Ek host mount yolları</Label>
        {isDirty && <Badge variant="outline" className="text-[10px] text-yellow-400 border-yellow-400/40">unsaved</Badge>}
      </div>
      <Textarea
        placeholder={'/opt/tatilji\n/opt/another-app'}
        value={text}
        onChange={e => setText(e.target.value)}
        rows={3}
        className="font-mono text-xs resize-y bg-background/60"
      />
      <p className="text-[11px] text-muted-foreground">
        Her satır bir host yolu. Agent container'a <code className="font-mono">ro</code> mount edilir.
        Mevcut <code className="font-mono">/opt/envfiles</code> default mount'unun üstüne eklenir.
      </p>
      <div className="flex items-center gap-2">
        <Button size="sm" variant="outline" disabled={!isDirty || saving || restarting} onClick={handleSave}>
          {saving ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Save className="h-3.5 w-3.5 mr-1.5" />}
          Kaydet
        </Button>
        <Button size="sm" disabled={(!isDirty && saved === text) || saving || restarting} onClick={handleSaveAndApply}>
          {(saving || restarting) ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5 mr-1.5" />}
          Kaydet ve uygula (recreate)
        </Button>
      </div>
      {!isDirty && saved && (
        <p className="text-[11px] text-muted-foreground">
          Mount'lar canlıya almak için <code className="font-mono">agent.self_upgrade</code> komutu gerekli — yukarıdaki <strong>"Kaydet ve uygula"</strong> tuşu ikisini birlikte yapar.
        </p>
      )}
    </div>
  )
}

export default function Agents() {
  const [agents, setAgents] = useState<Agent[]>([])
  const [loading, setLoading] = useState(true)
  const [createOpen, setCreateOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)
  // The create response is the only place the plaintext API key flows
  // back. We keep both the row and the key together until the operator
  // dismisses the reveal banner.
  const [createdAgent, setCreatedAgent] = useState<{ agent: Agent; api_key: string } | null>(null)
  // Komut gönderildiğinde history bileşenlerini re-fetch ettirmek için
  // bumplanan counter.
  const [historyRefresh, setHistoryRefresh] = useState(0)
  const [deleteTarget, setDeleteTarget] = useState<Agent | null>(null)

  const load = useCallback(async () => {
    try {
      const list = await api.listAgents()
      setAgents(list)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Failed to load agents')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleCreate() {
    if (!newName.trim()) return
    setCreating(true)
    try {
      const res = await api.createAgent(newName.trim())
      setCreatedAgent(res)
      setAgents(prev => [res.agent, ...prev])
      setNewName('')
      setCreateOpen(false)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Create failed')
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    try {
      await api.deleteAgent(deleteTarget.id)
      setAgents(prev => prev.filter(a => a.id !== deleteTarget.id))
      toast.success(`Agent "${deleteTarget.name}" deleted`)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Delete failed')
    } finally {
      setDeleteTarget(null)
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">Agents</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Remote agent instances that pull config and forward traffic
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon" onClick={load} className="h-9 w-9 cursor-pointer border-border">
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </Button>
          <Button onClick={() => setCreateOpen(true)} className="gap-2 cursor-pointer">
            <Plus className="h-4 w-4" />
            New Agent
          </Button>
        </div>
      </div>

      {/* Newly created agent — show key prominently */}
      {createdAgent && (
        <div className="rounded-lg border border-primary/40 bg-primary/5 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Check className="h-4 w-4 text-primary" />
            <span className="text-sm font-semibold text-foreground">
              Agent "{createdAgent.agent.name}" oluşturuldu. API anahtarını şimdi kopyala (bir daha gösterilmeyecek)
            </span>
            <Button
              variant="ghost"
              size="sm"
              className="ml-auto text-xs text-muted-foreground cursor-pointer"
              onClick={() => setCreatedAgent(null)}
            >
              Kapat
            </Button>
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 font-mono text-sm bg-background border border-border rounded px-3 py-2 text-foreground break-all">
              {createdAgent.api_key}
            </code>
            <CopyButton text={createdAgent.api_key} className="shrink-0" />
          </div>
          <DeployInstructions agent={createdAgent.agent} apiKey={createdAgent.api_key} />
        </div>
      )}

      {/* Agent list */}
      {loading ? (
        <div className="space-y-3">
          {[1, 2].map(i => <Skeleton key={i} className="h-20 w-full" />)}
        </div>
      ) : agents.length === 0 ? (
        <div className="rounded-lg border border-border bg-card flex flex-col items-center justify-center py-16 gap-3">
          <Server className="h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm text-muted-foreground">No agents registered yet</p>
          <Button onClick={() => setCreateOpen(true)} variant="outline" size="sm" className="gap-2 cursor-pointer">
            <Plus className="h-4 w-4" />
            Create first agent
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          {agents.map(agent => (
            <div key={agent.id} className="rounded-lg border border-border bg-card p-4 space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
                    <Server className="h-4 w-4" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-foreground truncate">{agent.name}</p>
                    <p className="text-xs text-muted-foreground font-mono truncate">{agent.id}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {(() => {
                    const { online, label } = agentOnlineStatus(agent.last_seen_at)
                    return (
                      <span className={cn(
                        'inline-flex items-center gap-1 text-xs font-medium',
                        online ? 'text-emerald-500' : 'text-muted-foreground'
                      )} title={agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : 'Never connected'}>
                        {online
                          ? <Wifi className="h-3 w-3" />
                          : <WifiOff className="h-3 w-3" />}
                        {label}
                      </span>
                    )
                  })()}
                  <Badge variant={agent.is_active ? 'default' : 'secondary'} className="text-xs">
                    {agent.is_active ? 'Active' : 'Inactive'}
                  </Badge>
                  <AgentActionMenu
                    agentID={agent.id}
                    agentName={agent.name}
                    onCommandSent={() => setHistoryRefresh(n => n + 1)}
                  />
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10 cursor-pointer"
                    onClick={() => setDeleteTarget(agent)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>

              <div className="flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2">
                <KeyRound className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                <code className="flex-1 text-xs font-mono text-muted-foreground truncate">
                  api_key gizli · yalnızca oluşturma sırasında gösterilir
                </code>
              </div>

              {/* Observability strip — only render when we have any signal,
                  so freshly-registered agents that haven't pulled yet still
                  look clean. */}
              {(agent.last_config_pull_at || agent.config_version) && (
                <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                  <div className="rounded border border-border/60 bg-background/40 px-2.5 py-1.5">
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">Last config pull</p>
                    <p className="font-mono text-foreground/90 truncate" title={agent.last_config_pull_at ?? ''}>
                      {agent.last_config_pull_at
                        ? new Date(agent.last_config_pull_at).toLocaleString()
                        : '—'}
                    </p>
                  </div>
                  <div className="rounded border border-border/60 bg-background/40 px-2.5 py-1.5">
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">Applied version</p>
                    <p className="font-mono text-foreground/90 truncate" title={agent.config_version ?? ''}>
                      {agent.config_version || '—'}
                    </p>
                  </div>
                  {agent.last_remote_addr ? (
                    <div className="rounded border border-border/60 bg-background/40 px-2.5 py-1.5">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">Last seen from</p>
                      <p className="font-mono text-foreground/90 truncate" title={agent.last_user_agent ?? ''}>
                        {agent.last_remote_addr}
                      </p>
                    </div>
                  ) : null}
                  {agent.public_ip ? (
                    <div className="rounded border border-emerald-500/30 bg-emerald-500/5 px-2.5 py-1.5">
                      <p className="text-[10px] uppercase tracking-wider text-emerald-400/80">Public IP (DNS hedefi)</p>
                      <p className="font-mono text-foreground/90 truncate" title="Agent kendi public IP'sini bildiriyor — DNS verification bu IP'yi bekler">
                        {agent.public_ip}
                      </p>
                    </div>
                  ) : null}
                </div>
              )}

              <ExtraMountsEditor
                agentID={agent.id}
                initial={agent.extra_mounts ?? []}
                onSaved={() => { void load() }}
              />

              <AgentCommandHistory agentID={agent.id} refreshKey={historyRefresh} />

              {/* DeployInstructions is shown only on the create flow now,
                  where the plaintext API key is available. List rows no
                  longer reveal the key, so the snippet wouldn't be
                  usable anyway. */}
            </div>
          ))}
        </div>
      )}

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New Agent</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-1.5">
              <Label>Agent Name</Label>
              <Input
                placeholder="e.g. eu-west-1, prod-tenant-42"
                value={newName}
                onChange={e => setNewName(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleCreate()}
                autoFocus
              />
              <p className="text-xs text-muted-foreground">
                A unique label for this remote instance. The API key will be generated automatically.
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)} className="cursor-pointer">
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={creating || !newName.trim()} className="cursor-pointer">
              {creating ? 'Creating...' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm */}
      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete agent "{deleteTarget?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              The API key will be revoked immediately. Any running agent using this key will lose access.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer">Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} className="bg-destructive hover:bg-destructive/90 cursor-pointer">
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
