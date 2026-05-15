import { useEffect, useMemo, useState } from 'react'
import { Eye, EyeOff, Loader2, Plus, Settings, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import type { Agent, DeployComponent } from '@/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import {
  Dialog, DialogContent, DialogDescription,
  DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'

const ENV_MASK = '********'

// EnvRow is the in-memory representation of a single key/value pair the
// operator is editing. `isNewSecret` separates "this row's value is
// currently the mask placeholder coming from the server" (keep ciphertext
// unchanged) from "the operator just clicked the eye icon to type a fresh
// secret" (encrypt on submit).
interface EnvRow {
  key: string
  value: string
  isSecret: boolean
  // valueDirty is true once the operator types in the value field. When a
  // row is secret and not dirty, we keep the masked placeholder on submit
  // so the existing ciphertext is preserved server-side.
  valueDirty: boolean
  // reveal flips the value cell from password-style to plain text.
  reveal: boolean
}

function buildEnvRows(component: DeployComponent): EnvRow[] {
  const secretSet = new Set(component.env_secret_keys ?? [])
  const rows: EnvRow[] = []
  for (const [k, v] of Object.entries(component.env ?? {})) {
    rows.push({
      key: k,
      value: v,
      isSecret: secretSet.has(k),
      valueDirty: false,
      reveal: false,
    })
  }
  rows.sort((a, b) => a.key.localeCompare(b.key))
  return rows
}

interface ComponentEditorDialogProps {
  open: boolean
  projectSlug: string
  componentSlug: string | null // null = create new component in this project
  onClose: () => void
  onSaved: () => void
}

export function ComponentEditorDialog({
  open, projectSlug, componentSlug, onClose, onSaved,
}: ComponentEditorDialogProps) {
  const isCreate = componentSlug === null
  const [loading, setLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [tab, setTab] = useState<'general' | 'env' | 'advanced'>('general')

  // Fields
  const [slugDraft, setSlugDraft] = useState('')
  const [name, setName] = useState('')
  const [imageRepo, setImageRepo] = useState('')
  const [internalPort, setInternalPort] = useState('8080')
  const [healthPath, setHealthPath] = useState('/health')
  const [healthExpectedStatus, setHealthExpectedStatus] = useState('200')
  const [restartRetries, setRestartRetries] = useState('1')
  const [drainTimeout, setDrainTimeout] = useState('30')
  const [longDrainTimeout, setLongDrainTimeout] = useState('300')
  // Image retention window for rollback. Lower = less disk, fewer rollback
  // hops; higher = more disk, more recovery surface. SQL CHECK enforces ≥1.
  const [keepReleases, setKeepReleases] = useState('3')
  const [migrationCommand, setMigrationCommand] = useState('')
  const [networks, setNetworks] = useState('')
  const [envFilePath, setEnvFilePath] = useState('')
  const [isRoutable, setIsRoutable] = useState(true)
  // Host: "" = central, non-empty = agent ID. Editable only on create —
  // an existing service has running containers on one host and switching
  // would orphan them.
  const [agentID, setAgentID] = useState('')
  const [agents, setAgents] = useState<Agent[]>([])
  const [envRows, setEnvRows] = useState<EnvRow[]>([])
  const [mounts, setMounts] = useState<import('@/types').Mount[]>([])

  // Bulk paste
  const [bulkOpen, setBulkOpen] = useState(false)
  const [bulkText, setBulkText] = useState('')
  const [bulkAsSecret, setBulkAsSecret] = useState(false)

  useEffect(() => {
    if (!open) return
    // Always refresh the agent list on open so the host picker shows
    // newly-registered agents without a page reload.
    api.listAgents().then(setAgents).catch(() => {})
    if (isCreate) {
      // Defaults for a new service
      setSlugDraft('')
      setName('')
      setImageRepo('')
      setInternalPort('8080')
      setHealthPath('/health')
      setHealthExpectedStatus('200')
      setRestartRetries('1')
      setDrainTimeout('30')
      setLongDrainTimeout('300')
      setKeepReleases('3')
      setMigrationCommand('')
      setNetworks('')
      setEnvFilePath('')
      setIsRoutable(true)
      setAgentID('')
      setEnvRows([])
      setMounts([])
      setTab('general')
      return
    }
    setLoading(true)
    api.getDeployComponent(projectSlug, componentSlug!).then(c => {
      setSlugDraft(c.slug)
      setName(c.name)
      setImageRepo(c.image_repo)
      setInternalPort(String(c.internal_port))
      setHealthPath(c.health_path)
      setHealthExpectedStatus(String(c.health_expected_status))
      setRestartRetries(String(c.restart_retries))
      setDrainTimeout(String(c.drain_timeout_seconds))
      setLongDrainTimeout(String(c.long_drain_timeout_seconds))
      setKeepReleases(String(c.keep_releases ?? 3))
      setMigrationCommand((c.migration_command ?? []).join(' '))
      setNetworks((c.networks ?? []).join(', '))
      setEnvFilePath(c.env_file_path ?? '')
      setIsRoutable(c.is_routable)
      setAgentID(c.agent_id ?? '')
      setEnvRows(buildEnvRows(c))
      setMounts(c.mounts ?? [])
      setTab('general')
    }).catch(err => {
      toast.error(err instanceof Error ? err.message : 'Servis bilgileri yüklenemedi')
    }).finally(() => setLoading(false))
  }, [open, projectSlug, componentSlug, isCreate])

  const envKeysUsed = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const r of envRows) counts[r.key] = (counts[r.key] ?? 0) + 1
    return counts
  }, [envRows])

  function addEnvRow(secret = false) {
    setEnvRows(rows => [...rows, { key: '', value: '', isSecret: secret, valueDirty: true, reveal: !secret }])
  }

  function updateRow(idx: number, patch: Partial<EnvRow>) {
    setEnvRows(rows => rows.map((r, i) => (i === idx ? { ...r, ...patch } : r)))
  }

  function removeRow(idx: number) {
    setEnvRows(rows => rows.filter((_, i) => i !== idx))
  }

  function applyBulk() {
    if (!bulkText.trim()) {
      setBulkOpen(false)
      return
    }
    // Lightweight .env parser — same shape as the server's parseEnvFile()
    // but tolerant of "export KEY=VALUE", surrounding quotes, and inline #.
    const incoming: { key: string; value: string }[] = []
    for (const rawLine of bulkText.split(/\r?\n/)) {
      let line = rawLine.trim()
      if (!line || line.startsWith('#')) continue
      if (line.startsWith('export ')) line = line.slice('export '.length)
      const eq = line.indexOf('=')
      if (eq < 0) continue
      const key = line.slice(0, eq).trim()
      if (!key) continue
      let value = line.slice(eq + 1).trim()
      // Strip matching quotes only (don't peel ' from middle).
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1)
      }
      incoming.push({ key, value })
    }
    if (incoming.length === 0) {
      toast.error('Geçerli KEY=VALUE satırı bulunamadı')
      return
    }
    setEnvRows(rows => {
      const map = new Map(rows.map(r => [r.key, r]))
      for (const { key, value } of incoming) {
        map.set(key, {
          key,
          value,
          isSecret: bulkAsSecret,
          valueDirty: true,
          reveal: !bulkAsSecret,
        })
      }
      return Array.from(map.values())
    })
    setBulkText('')
    setBulkOpen(false)
    toast.success(`${incoming.length} env değişkeni eklendi`)
  }

  async function handleSubmit() {
    if (isCreate) {
      if (!/^[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]$|^[a-z0-9]$/.test(slugDraft)) {
        toast.error('Servis tanımlayıcısı 1–64 karakter, küçük harf/rakam/(-,_) olmalı')
        return
      }
    }
    if (!name.trim()) { toast.error('İsim gerekli'); return }
    if (!imageRepo.trim()) { toast.error('Docker image gerekli'); return }
    const port = Number(internalPort)
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      toast.error('Port 1–65535 arasında olmalı'); return
    }
    // Validate env: keys unique, non-empty
    for (const k of Object.keys(envKeysUsed)) {
      if (envKeysUsed[k] > 1) { toast.error(`Yinelenen env anahtarı: ${k}`); return }
    }
    for (const row of envRows) {
      if (!row.key.trim()) { toast.error('Boş env anahtarı var'); return }
    }

    // Build the env map. For secret rows that the operator didn't touch,
    // re-send the mask placeholder so the server keeps the existing
    // ciphertext. For freshly-typed secret rows, send the plaintext —
    // the server encrypts before persisting.
    const env: Record<string, string> = {}
    const envSecretKeys: string[] = []
    for (const row of envRows) {
      const key = row.key.trim()
      if (row.isSecret) envSecretKeys.push(key)
      env[key] = row.isSecret && !row.valueDirty ? ENV_MASK : row.value
    }

    const payload: api.DeployComponentInput = {
      slug: isCreate ? slugDraft.trim() : undefined,
      name: name.trim(),
      image_repo: imageRepo.trim(),
      internal_port: port,
      health_path: healthPath.trim() || '/',
      health_expected_status: Number(healthExpectedStatus) || 200,
      restart_retries: Math.max(0, Number(restartRetries) || 0),
      drain_timeout_seconds: Math.max(1, Number(drainTimeout) || 30),
      long_drain_timeout_seconds: Math.max(1, Number(longDrainTimeout) || 300),
      keep_releases: Math.min(50, Math.max(1, Number(keepReleases) || 3)),
      migration_command: migrationCommand.trim()
        ? migrationCommand.trim().split(/\s+/)
        : [],
      networks: networks.trim()
        ? networks.split(',').map(s => s.trim()).filter(Boolean)
        : [],
      env_file_path: envFilePath.trim(),
      env,
      env_secret_keys: envSecretKeys,
      mounts: mounts.filter(m => m.target.trim() && (m.type !== 'bind' || (m.source ?? '').trim())),
      is_routable: isRoutable,
      // Only sent on create — update endpoint ignores agent_id by design
      // (server preserves the original host to avoid orphaned containers).
      ...(isCreate ? { agent_id: agentID || undefined } : {}),
    }

    setSubmitting(true)
    try {
      if (isCreate) {
        await api.createDeployComponent(projectSlug, payload)
        toast.success('Servis oluşturuldu')
      } else {
        await api.updateDeployComponent(projectSlug, componentSlug!, payload)
        toast.success('Servis güncellendi')
      }
      onSaved()
      onClose()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Kaydedilemedi')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={v => !v && !submitting && onClose()}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Settings className="h-4 w-4 text-primary" />
            {isCreate ? 'Yeni Servis' : `Servisi Düzenle · ${componentSlug}`}
          </DialogTitle>
          <DialogDescription>
            {isCreate
              ? 'Bu uygulama için yeni bir servis tanımla.'
              : 'Yapılandırma değişiklikleri sonraki deploy\'la yürürlüğe girer.'}
          </DialogDescription>
        </DialogHeader>

        {/* Tabs */}
        <div className="flex gap-1 rounded-md border border-border p-1 bg-muted/10 shrink-0">
          {(['general', 'env', 'advanced'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                'flex-1 rounded px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer',
                tab === t ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
              )}
            >
              {t === 'general' ? 'Genel' : t === 'env' ? 'Ortam Değişkenleri' : 'Gelişmiş'}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex-1 flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto pt-1 space-y-4">
            {tab === 'general' && (
              <div className="space-y-3">
                {isCreate && (
                  <>
                    <div className="space-y-1.5">
                      <Label className="text-xs">Servis tanımlayıcısı <span className="text-destructive">*</span></Label>
                      <Input
                        placeholder="web"
                        value={slugDraft}
                        onChange={e => setSlugDraft(e.target.value)}
                        className="font-mono text-sm"
                        autoFocus
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs">Host</Label>
                      <select
                        value={agentID}
                        onChange={e => setAgentID(e.target.value)}
                        className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                      >
                        <option value="">Bu MUVON sunucusunda (central)</option>
                        {agents.map(a => (
                          <option key={a.id} value={a.id}>Agent: {a.name} ({a.id.slice(0, 8)})</option>
                        ))}
                      </select>
                      <p className="text-[11px] text-muted-foreground">
                        Servisin Docker container'ları bu host'ta çalışır. Oluşturulduktan sonra değiştirilemez.
                      </p>
                    </div>
                  </>
                )}
                {!isCreate && (
                  <div className="space-y-1.5">
                    <Label className="text-xs">Host</Label>
                    <div className="rounded-md border border-border bg-muted/10 px-3 py-2 text-sm font-mono">
                      {agentID === '' ? 'Bu MUVON sunucusu (central)' : (() => {
                        const a = agents.find(x => x.id === agentID)
                        return a ? `Agent: ${a.name} (${a.id.slice(0, 8)})` : `Agent: ${agentID.slice(0, 8)}`
                      })()}
                    </div>
                    <p className="text-[11px] text-muted-foreground">Sabit. Taşımak için servisi silip yeniden oluşturmalısın.</p>
                  </div>
                )}
                <div className="space-y-1.5">
                  <Label className="text-xs">İsim</Label>
                  <Input value={name} onChange={e => setName(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Docker image <span className="text-destructive">*</span></Label>
                  <Input
                    placeholder="ghcr.io/firma/uygulama"
                    value={imageRepo}
                    onChange={e => setImageRepo(e.target.value)}
                    className="font-mono text-sm"
                  />
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div className="space-y-1.5">
                    <Label className="text-xs">Port</Label>
                    <Input
                      type="number"
                      min={1}
                      max={65535}
                      value={internalPort}
                      onChange={e => setInternalPort(e.target.value)}
                      className="font-mono text-sm"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Sağlık yolu</Label>
                    <Input
                      value={healthPath}
                      onChange={e => setHealthPath(e.target.value)}
                      className="font-mono text-sm"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Beklenen kod</Label>
                    <Input
                      type="number"
                      value={healthExpectedStatus}
                      onChange={e => setHealthExpectedStatus(e.target.value)}
                      className="font-mono text-sm"
                    />
                  </div>
                </div>
                <div className="flex items-center gap-2 pt-1">
                  <input
                    id="is_routable"
                    type="checkbox"
                    checked={isRoutable}
                    onChange={e => setIsRoutable(e.target.checked)}
                    className="h-4 w-4"
                  />
                  <Label htmlFor="is_routable" className="text-xs cursor-pointer">
                    MUVON yönlendirmesine açık (kapalıysa servis sadece dahili)
                  </Label>
                </div>
              </div>
            )}

            {tab === 'env' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-xs text-muted-foreground">
                    Gizli olarak işaretlenen değerler şifreli saklanır, panelde maskelenir.
                  </p>
                  <div className="flex items-center gap-1">
                    <Button size="sm" variant="outline" onClick={() => setBulkOpen(true)}>
                      .env yapıştır
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => addEnvRow(false)}>
                      <Plus className="h-3 w-3 mr-1" /> Değişken
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => addEnvRow(true)}>
                      <Plus className="h-3 w-3 mr-1" /> Gizli
                    </Button>
                  </div>
                </div>

                {bulkOpen && (
                  <div className="rounded-md border border-border bg-muted/10 p-3 space-y-2">
                    <Label className="text-xs">.env içeriği</Label>
                    <Textarea
                      rows={6}
                      value={bulkText}
                      onChange={e => setBulkText(e.target.value)}
                      placeholder={'DB_HOST=db.local\nAPI_KEY=...'}
                      className="font-mono text-xs"
                    />
                    <div className="flex items-center gap-2">
                      <input
                        id="bulk_secret"
                        type="checkbox"
                        checked={bulkAsSecret}
                        onChange={e => setBulkAsSecret(e.target.checked)}
                        className="h-4 w-4"
                      />
                      <Label htmlFor="bulk_secret" className="text-xs cursor-pointer">Hepsini gizli olarak işaretle</Label>
                      <div className="ml-auto flex gap-1">
                        <Button size="sm" variant="ghost" onClick={() => { setBulkOpen(false); setBulkText('') }}>İptal</Button>
                        <Button size="sm" onClick={applyBulk}>Ekle</Button>
                      </div>
                    </div>
                  </div>
                )}

                {envRows.length === 0 && !bulkOpen && (
                  <p className="text-xs text-muted-foreground py-4 text-center">
                    Henüz ortam değişkeni yok.
                  </p>
                )}

                <div className="space-y-1.5">
                  {envRows.map((row, idx) => (
                    <div key={idx} className="grid grid-cols-[1fr_1fr_auto] gap-1.5 items-center">
                      <Input
                        placeholder="KEY"
                        value={row.key}
                        onChange={e => updateRow(idx, { key: e.target.value })}
                        className={cn(
                          'font-mono text-xs h-8',
                          row.key && envKeysUsed[row.key] > 1 && 'border-destructive',
                        )}
                      />
                      <div className="flex items-center gap-1">
                        <Input
                          type={row.isSecret && !row.reveal ? 'password' : 'text'}
                          placeholder={row.isSecret && !row.valueDirty ? ENV_MASK : 'value'}
                          value={row.value}
                          onChange={e => updateRow(idx, { value: e.target.value, valueDirty: true })}
                          className="font-mono text-xs h-8"
                        />
                        {row.isSecret && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 shrink-0"
                            onClick={() => updateRow(idx, { reveal: !row.reveal })}
                            title={row.reveal ? 'Gizle' : 'Göster'}
                          >
                            {row.reveal ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                          </Button>
                        )}
                      </div>
                      <div className="flex items-center gap-1">
                        {row.isSecret && (
                          <Badge variant="outline" className="text-[10px] px-1 py-0 border-amber-400/40 text-amber-300 bg-amber-400/10">
                            gizli
                          </Badge>
                        )}
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 shrink-0 text-muted-foreground hover:text-destructive"
                          onClick={() => removeRow(idx)}
                          title="Sil"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {tab === 'advanced' && (
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <Label className="text-xs">Migration komutu</Label>
                  <Input
                    placeholder="./migrate.sh"
                    value={migrationCommand}
                    onChange={e => setMigrationCommand(e.target.value)}
                    className="font-mono text-xs"
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Her release'de yeni container'lar başlamadan önce bir kez çalışır. Boş bırakırsanız atlanır.
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Docker network'leri</Label>
                  <Input
                    placeholder="muvon-internal, db-net"
                    value={networks}
                    onChange={e => setNetworks(e.target.value)}
                    className="font-mono text-xs"
                  />
                  <p className="text-[11px] text-muted-foreground">Virgülle ayır. Container bu network'lere bağlanır.</p>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">.env dosya yolu (host)</Label>
                  <Input
                    placeholder="/var/lib/muvon/uygulamam.env"
                    value={envFilePath}
                    onChange={e => setEnvFilePath(e.target.value)}
                    className="font-mono text-xs"
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Belirtilirse, container start'tan önce host'tan okunur ve yukarıdaki değişkenlerle birleştirilir.
                  </p>
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div className="space-y-1.5">
                    <Label className="text-xs">Restart deneme</Label>
                    <Input
                      type="number"
                      min={0}
                      value={restartRetries}
                      onChange={e => setRestartRetries(e.target.value)}
                      className="font-mono text-xs"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Drain (sn)</Label>
                    <Input
                      type="number"
                      min={1}
                      value={drainTimeout}
                      onChange={e => setDrainTimeout(e.target.value)}
                      className="font-mono text-xs"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Uzun drain (sn)</Label>
                    <Input
                      type="number"
                      min={1}
                      value={longDrainTimeout}
                      onChange={e => setLongDrainTimeout(e.target.value)}
                      className="font-mono text-xs"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label className="text-xs">Tutulan release sayısı</Label>
                  <Input
                    type="number"
                    min={1}
                    max={50}
                    value={keepReleases}
                    onChange={e => setKeepReleases(e.target.value)}
                    className="font-mono text-xs w-24"
                  />
                  <p className="text-[11px] text-muted-foreground leading-snug">
                    Başarılı promote sonrası son N release'in imajı yerel Docker'da kalır;
                    daha eski (ve canlı bir instance'a bağlı olmayan) imajlar silinir.
                    Düşük tutmak diski boşaltır, rollback hedef sayısını azaltır. Varsayılan 3.
                  </p>
                </div>

                <div className="space-y-2 pt-2 border-t border-border">
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-xs">Mounts (bind / volume)</Label>
                      <p className="text-[11px] text-muted-foreground mt-0.5">
                        Host path veya named volume container'a bağlanır. Bind için <code className="font-mono">source</code> host path; volume için volume adı.
                      </p>
                    </div>
                    <Button
                      type="button" size="sm" variant="outline"
                      onClick={() => setMounts(m => [...m, { type: 'bind', source: '', target: '', read_only: false }])}
                    >
                      + Mount
                    </Button>
                  </div>

                  {mounts.length === 0 ? (
                    <p className="text-[11px] text-muted-foreground italic">Henüz mount yok.</p>
                  ) : (
                    <div className="space-y-1.5">
                      {mounts.map((m, i) => (
                        <div key={i} className="grid grid-cols-[100px_1fr_1fr_60px_28px] gap-1.5 items-center">
                          <select
                            value={m.type}
                            onChange={e => setMounts(mm => mm.map((x, j) => j === i ? { ...x, type: e.target.value as typeof x.type } : x))}
                            className="rounded-md border border-border bg-background px-2 py-1 text-xs font-mono"
                          >
                            <option value="bind">bind</option>
                            <option value="volume">volume</option>
                            <option value="tmpfs">tmpfs</option>
                          </select>
                          <Input
                            placeholder={m.type === 'bind' ? '/opt/foo/bar' : m.type === 'volume' ? 'volume-name' : '(tmpfs)'}
                            value={m.source ?? ''}
                            onChange={e => setMounts(mm => mm.map((x, j) => j === i ? { ...x, source: e.target.value } : x))}
                            disabled={m.type === 'tmpfs'}
                            className="font-mono text-xs h-7"
                          />
                          <Input
                            placeholder="/app/.env"
                            value={m.target}
                            onChange={e => setMounts(mm => mm.map((x, j) => j === i ? { ...x, target: e.target.value } : x))}
                            className="font-mono text-xs h-7"
                          />
                          <label className="flex items-center gap-1 text-[11px] text-muted-foreground cursor-pointer">
                            <input
                              type="checkbox"
                              checked={!!m.read_only}
                              onChange={e => setMounts(mm => mm.map((x, j) => j === i ? { ...x, read_only: e.target.checked } : x))}
                              className="h-3 w-3"
                            />
                            ro
                          </label>
                          <Button
                            type="button" variant="ghost" size="icon"
                            className="h-7 w-7 text-muted-foreground hover:text-destructive"
                            onClick={() => setMounts(mm => mm.filter((_, j) => j !== i))}
                            title="Sil"
                          >
                            ×
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        <DialogFooter className="shrink-0 pt-2 border-t border-border">
          <Button variant="ghost" onClick={onClose} disabled={submitting}>İptal</Button>
          <Button onClick={handleSubmit} disabled={submitting || loading}>
            {submitting && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
            {isCreate ? 'Oluştur' : 'Kaydet'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
