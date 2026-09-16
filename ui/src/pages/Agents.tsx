import { useEffect, useState, useCallback } from 'react'
import {
  Plus, Trash2, Copy, Check, Server, KeyRound,
  RefreshCw, Terminal, ChevronDown, ChevronRight, Wifi, WifiOff,
  Save, Loader2, FolderTree, Ban,
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
  if (!lastSeenAt) return { online: false, label: 'Hiç bağlanmadı' }
  const diff = Date.now() - new Date(lastSeenAt).getTime()
  if (diff < ONLINE_THRESHOLD_MS) return { online: true, label: 'Çevrimiçi' }
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return { online: false, label: `${mins} dk önce` }
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return { online: false, label: `${hrs} sa önce` }
  return { online: false, label: `${Math.floor(hrs / 24)} gün önce` }
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
      title="Kopyala"
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
# isteğe bağlı, diaLOG'a log gönderimi:
AGENT_LOG_ADDR=<your-central-host>:9001`

  return (
    <div className="mt-3 rounded-md border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium text-muted-foreground hover:text-foreground hover:bg-muted/10 transition-colors cursor-pointer"
      >
        <Terminal className="h-3.5 w-3.5" />
        Kurulum talimatı
        {open ? <ChevronDown className="h-3 w-3 ml-auto" /> : <ChevronRight className="h-3 w-3 ml-auto" />}
      </button>
      {open && (
        <div className="border-t border-border bg-muted/5 p-3 space-y-3">
          <p className="text-xs text-muted-foreground">
            Müşteri sunucusunda agent'ı şu ortam değişkenleriyle çalıştır:
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
            Ya da parametre olarak ver: <code className="font-mono text-foreground">./agent -central https://... -api-key {apiKey.slice(0, 8)}…</code>
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
// doesn't mount: they still need to fire self_upgrade from the action
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
        {isDirty && <Badge variant="outline" className="text-[10px] text-yellow-400 border-yellow-400/40">kaydedilmedi</Badge>}
      </div>
      <Textarea
        placeholder={'/opt/example-app\n/opt/another-app'}
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
          Mount'ları canlıya almak için <code className="font-mono">agent.self_upgrade</code> komutu gerekli; yukarıdaki <strong>"Kaydet ve uygula"</strong> tuşu ikisini birlikte yapar.
        </p>
      )}
    </div>
  )
}

// DeployerAddrEditor: operator-set "host:port" the central admin
// dials over the private network to bridge live container logs for
// this agent's host. Tiny field, no apply step (no agent-side change
// needed, it's all central-side routing).
function DeployerAddrEditor({
  agentID, initial, hostID, onSaved,
}: {
  agentID: string
  initial: string
  hostID: string
  onSaved: () => void
}) {
  const [val, setVal] = useState(initial)
  const [saving, setSaving] = useState(false)
  const isDirty = val.trim() !== initial.trim()

  async function handleSave() {
    setSaving(true)
    try {
      await api.updateAgentDeployerAddr(agentID, val.trim())
      toast.success(val.trim() ? 'Deployer addr kaydedildi' : 'Deployer addr temizlendi')
      onSaved()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Kayıt başarısız')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-2 rounded border border-border/60 bg-background/40 p-3">
      <div className="flex items-center gap-2">
        <Label className="text-xs font-medium">Deployer addr (canlı container log için)</Label>
        {isDirty && <Badge variant="outline" className="text-[10px] text-yellow-400 border-yellow-400/40">kaydedilmedi</Badge>}
      </div>
      <Input
        placeholder="10.0.0.3:9100"
        value={val}
        onChange={e => setVal(e.target.value)}
        className="font-mono text-xs bg-background/60"
      />
      <p className="text-[11px] text-muted-foreground">
        Agent'ın deployer gRPC TCP portu (install-agent.sh → <code className="font-mono">AGENT_DEPLOYER_TCP_BIND</code>).
        Boş bırakırsan canlı tail bu agent için devre dışı.
        {hostID ? <> Host ID: <code className="font-mono">{hostID}</code></> : null}
      </p>
      <div className="flex items-center gap-2">
        <Button size="sm" variant="outline" disabled={!isDirty || saving} onClick={handleSave}>
          {saving ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Save className="h-3.5 w-3.5 mr-1.5" />}
          Kaydet
        </Button>
      </div>
    </div>
  )
}

function formatDate(value?: string | null): string {
  return value ? new Date(value).toLocaleString('tr-TR') : 'Yok'
}

export default function Agents() {
  const [agents, setAgents] = useState<Agent[]>([])
  const [loading, setLoading] = useState(true)
  const [createOpen, setCreateOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)
  // A create or a key rotation is the only place a plaintext key flows back.
  // Row and key are kept together until the operator dismisses the banner.
  const [revealed, setRevealed] = useState<{ agent: Agent; api_key: string; rotated: boolean } | null>(null)
  // Bumped after a command is sent, to make the history components refetch.
  const [historyRefresh, setHistoryRefresh] = useState(0)
  const [deleteTarget, setDeleteTarget] = useState<Agent | null>(null)
  const [revokeTarget, setRevokeTarget] = useState<Agent | null>(null)
  const [rotateTarget, setRotateTarget] = useState<Agent | null>(null)

  const load = useCallback(async () => {
    try {
      const list = await api.listAgents()
      setAgents(list)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Agent listesi yüklenemedi')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function replaceAgent(next: Agent) {
    setAgents(prev => prev.map(a => (a.id === next.id ? next : a)))
  }

  async function handleCreate() {
    if (!newName.trim()) return
    setCreating(true)
    try {
      const res = await api.createAgent(newName.trim())
      setRevealed({ ...res, rotated: false })
      setAgents(prev => [res.agent, ...prev])
      setNewName('')
      setCreateOpen(false)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Agent oluşturulamadı')
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    try {
      await api.deleteAgent(deleteTarget.id)
      setAgents(prev => prev.filter(a => a.id !== deleteTarget.id))
      toast.success(`"${deleteTarget.name}" silindi`)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Silinemedi')
    } finally {
      setDeleteTarget(null)
    }
  }

  async function handleRevoke() {
    if (!revokeTarget) return
    try {
      const agent = await api.revokeAgent(revokeTarget.id)
      replaceAgent(agent)
      toast.success(`"${agent.name}" anahtarı iptal edildi`)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Anahtar iptal edilemedi')
    } finally {
      setRevokeTarget(null)
    }
  }

  async function handleRotate() {
    if (!rotateTarget) return
    try {
      const res = await api.rotateAgentKey(rotateTarget.id)
      replaceAgent(res.agent)
      setRevealed({ ...res, rotated: true })
      toast.success(`"${res.agent.name}" için yeni anahtar üretildi`)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Yeni anahtar üretilemedi')
    } finally {
      setRotateTarget(null)
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">Agent'lar</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Config'i central'dan çeken ve trafiği karşılayan uzak sunucular
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon" onClick={load} className="h-9 w-9 cursor-pointer border-border">
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </Button>
          <Button onClick={() => setCreateOpen(true)} className="gap-2 cursor-pointer">
            <Plus className="h-4 w-4" />
            Yeni agent
          </Button>
        </div>
      </div>

      {/* A key shown once: after a create or a rotation */}
      {revealed && (
        <div className="rounded-lg border border-primary/40 bg-primary/5 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Check className="h-4 w-4 text-primary" />
            <span className="text-sm font-semibold text-foreground">
              {revealed.rotated
                ? `"${revealed.agent.name}" için yeni anahtar üretildi. Eski anahtar artık çalışmıyor; agent'ı bu anahtarla yeniden başlat. Anahtar bir daha gösterilmeyecek.`
                : `"${revealed.agent.name}" oluşturuldu. API anahtarını şimdi kopyala, bir daha gösterilmeyecek.`}
            </span>
            <Button
              variant="ghost"
              size="sm"
              className="ml-auto text-xs text-muted-foreground cursor-pointer"
              onClick={() => setRevealed(null)}
            >
              Kapat
            </Button>
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 font-mono text-sm bg-background border border-border rounded px-3 py-2 text-foreground break-all">
              {revealed.api_key}
            </code>
            <CopyButton text={revealed.api_key} className="shrink-0" />
          </div>
          <DeployInstructions agent={revealed.agent} apiKey={revealed.api_key} />
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
          <p className="text-sm text-muted-foreground">Henüz kayıtlı agent yok</p>
          <Button onClick={() => setCreateOpen(true)} variant="outline" size="sm" className="gap-2 cursor-pointer">
            <Plus className="h-4 w-4" />
            İlk agent'ı oluştur
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          {agents.map(agent => {
            const revoked = !agent.is_active
            return (
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
                        )} title={agent.last_seen_at ? formatDate(agent.last_seen_at) : 'Hiç bağlanmadı'}>
                          {online
                            ? <Wifi className="h-3 w-3" />
                            : <WifiOff className="h-3 w-3" />}
                          {label}
                        </span>
                      )
                    })()}
                    <Badge variant={revoked ? 'destructive' : 'default'} className="text-xs">
                      {revoked ? 'İptal edildi' : 'Etkin'}
                    </Badge>
                    {!revoked && (
                      <AgentActionMenu
                        agentID={agent.id}
                        agentName={agent.name}
                        onCommandSent={() => setHistoryRefresh(n => n + 1)}
                      />
                    )}
                    <Button
                      variant="ghost"
                      size="icon"
                      title="Agent kaydını sil"
                      className="h-8 w-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10 cursor-pointer"
                      onClick={() => setDeleteTarget(agent)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>

                {revoked && (
                  <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-foreground">
                    Anahtar {formatDate(agent.revoked_at)} tarihinde
                    {agent.revoked_by ? <> <span className="font-mono">{agent.revoked_by}</span> tarafından</> : null} iptal edildi.
                    Edge son aldığı config ile hizmet vermeyi sürdürür ama central'a bağlanamaz; geri almak için yeni anahtar üret.
                  </div>
                )}

                <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-background px-3 py-2">
                  <KeyRound className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  <span className="flex-1 min-w-0 text-xs text-muted-foreground truncate">
                    API anahtarı gizli, yalnız üretildiği anda gösterilir
                  </span>
                  <Button
                    size="sm" variant="outline"
                    className="h-7 text-xs gap-1 cursor-pointer"
                    onClick={() => setRotateTarget(agent)}
                  >
                    <RefreshCw className="h-3 w-3" />
                    Yeni anahtar üret
                  </Button>
                  {!revoked && (
                    <Button
                      size="sm" variant="outline"
                      className="h-7 text-xs gap-1 cursor-pointer text-destructive hover:text-destructive"
                      onClick={() => setRevokeTarget(agent)}
                    >
                      <Ban className="h-3 w-3" />
                      Anahtarı iptal et
                    </Button>
                  )}
                </div>

                {/* Observability strip: only render when we have any signal,
                    so freshly-registered agents that haven't pulled yet still
                    look clean. */}
                {(agent.last_config_pull_at || agent.config_version) && (
                  <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                    <div className="rounded border border-border/60 bg-background/40 px-2.5 py-1.5">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">Son config çekimi</p>
                      <p className="font-mono text-foreground/90 truncate" title={agent.last_config_pull_at ?? ''}>
                        {formatDate(agent.last_config_pull_at)}
                      </p>
                    </div>
                    <div className="rounded border border-border/60 bg-background/40 px-2.5 py-1.5">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">Uygulanan sürüm</p>
                      <p className="font-mono text-foreground/90 truncate" title={agent.config_version ?? ''}>
                        {agent.config_version || 'Yok'}
                      </p>
                    </div>
                    {agent.last_remote_addr ? (
                      <div className="rounded border border-border/60 bg-background/40 px-2.5 py-1.5">
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">Son bağlantı adresi</p>
                        <p className="font-mono text-foreground/90 truncate" title={agent.last_user_agent ?? ''}>
                          {agent.last_remote_addr}
                        </p>
                      </div>
                    ) : null}
                    {agent.public_ip ? (
                      <div className="rounded border border-emerald-500/30 bg-emerald-500/5 px-2.5 py-1.5">
                        <p className="text-[10px] uppercase tracking-wider text-emerald-400/80">Public IP (DNS hedefi)</p>
                        <p className="font-mono text-foreground/90 truncate" title="Agent kendi public IP'sini bildiriyor; DNS doğrulaması bu IP'yi bekler">
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

                <DeployerAddrEditor
                  agentID={agent.id}
                  initial={agent.deployer_addr ?? ''}
                  hostID={agent.host_id ?? ''}
                  onSaved={() => { void load() }}
                />

                <AgentCommandHistory agentID={agent.id} refreshKey={historyRefresh} />
              </div>
            )
          })}
        </div>
      )}

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Yeni agent</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-1.5">
              <Label>Agent adı</Label>
              <Input
                placeholder="ör. eu-west-1, musteri-42"
                value={newName}
                onChange={e => setNewName(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleCreate()}
                autoFocus
              />
              <p className="text-xs text-muted-foreground">
                Bu uzak kurulum için ayırt edici bir ad. API anahtarı otomatik üretilir.
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)} className="cursor-pointer">
              Vazgeç
            </Button>
            <Button onClick={handleCreate} disabled={creating || !newName.trim()} className="cursor-pointer">
              {creating ? 'Oluşturuluyor…' : 'Oluştur'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Revoke confirm */}
      <AlertDialog open={!!revokeTarget} onOpenChange={open => !open && setRevokeTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>"{revokeTarget?.name}" anahtarı iptal edilsin mi?</AlertDialogTitle>
            <AlertDialogDescription>
              Anahtar hemen geçersiz olur, açık bağlantılar kapanır ve bekleyen komutlar düşer. Agent'a
              ulaşılamasa da iptal gerçekleşir. Edge son aldığı config ile trafiğe hizmet vermeyi
              sürdürür ama config güncellemesi, log gönderimi ve deploy durur. Geri dönüş yalnız yeni
              anahtarla olur; eski anahtar bir daha çalışmaz.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer">Vazgeç</AlertDialogCancel>
            <AlertDialogAction onClick={handleRevoke} className="bg-destructive hover:bg-destructive/90 cursor-pointer">
              İptal et
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Rotate confirm */}
      <AlertDialog open={!!rotateTarget} onOpenChange={open => !open && setRotateTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>"{rotateTarget?.name}" için yeni anahtar üretilsin mi?</AlertDialogTitle>
            <AlertDialogDescription>
              Mevcut anahtar hemen çalışmaz hale gelir. Yeni anahtar bir kez gösterilir; agent onunla
              yeniden başlatılana kadar central'a bağlanamaz. Host ve servis bağları korunur.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer">Vazgeç</AlertDialogCancel>
            <AlertDialogAction onClick={handleRotate} className="cursor-pointer">
              Yeni anahtar üret
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete confirm */}
      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>"{deleteTarget?.name}" silinsin mi?</AlertDialogTitle>
            <AlertDialogDescription>
              Anahtar hemen geçersiz olur ve agent kaydı silinir. Bu agent'a bağlı host'lar, servisler ve
              zamanlanmış işler agent'sız kalır. Aynı sunucuyu geri getirmek istiyorsan silmek yerine
              anahtarı iptal et; yeni anahtarla bağlar korunarak döner.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer">Vazgeç</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} className="bg-destructive hover:bg-destructive/90 cursor-pointer">
              Sil
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
