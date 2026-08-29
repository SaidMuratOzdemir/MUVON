import { useState, useEffect, useCallback } from 'react'
import { ShieldBan, RefreshCw, Trash2, Plus, ShieldOff, Lock } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { EmptyState } from '@/components/EmptyState'
import { cn, relativeTime } from '@/lib/utils'
import * as api from '@/api'
import type { BlockPattern, BlockPatternKind, IPBlock } from '@/types'

const KIND_LABELS: Record<BlockPatternKind, string> = {
  filename: 'Dosya adı',
  segment: 'Yol parçası',
  regex: 'Düzenli ifade',
  allow: 'İzin verilen',
}

const KIND_HELP: Record<BlockPatternKind, string> = {
  filename: 'Yolun son parçasıyla eşleşir. /.env ile /public/.env aynı sayılır.',
  segment: 'Yolun herhangi bir yerindeki ardışık parçalarla eşleşir. /var/www/.git/config yakalanır.',
  regex: 'Dosya adını düzenli ifadeyle karşılaştırır. Sabit ad vermeyen kabuk dosyaları için.',
  allow: 'Bu önekle başlayan istekler hiç puanlanmaz. Her şeyden önce bakılır.',
}

const RULE_LABELS: Record<string, string> = {
  secret_file: 'Sır dosyası',
  exploit_probe: 'Zafiyet denemesi',
  admin_probe: 'Yönetim paneli',
  artifact_probe: 'Sızıntı dosyası',
}

function scoreTone(score: number) {
  if (score >= 100) return 'bg-red-500/10 text-red-400 border-red-500/20'
  if (score >= 20) return 'bg-orange-500/10 text-orange-400 border-orange-500/20'
  if (score >= 10) return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
  return 'bg-slate-500/10 text-slate-400 border-slate-500/20'
}

// Blocking settings live on this page rather than on the Settings page so the
// threshold sits next to the patterns it applies to: a number like "30" only
// means something when you can see that one credential probe is worth 100 and
// one admin probe is worth 10.
function humanDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return '—'
  if (seconds % 86400 === 0) return `${seconds / 86400} gün`
  if (seconds % 3600 === 0) return `${seconds / 3600} saat`
  if (seconds % 60 === 0) return `${seconds / 60} dakika`
  return `${seconds} saniye`
}

export default function Security() {
  const [patterns, setPatterns] = useState<BlockPattern[]>([])
  const [blocks, setBlocks] = useState<IPBlock[]>([])
  const [settings, setSettings] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  const [newKind, setNewKind] = useState<BlockPatternKind>('filename')
  const [newPattern, setNewPattern] = useState('')
  const [newScore, setNewScore] = useState('100')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [p, b, s] = await Promise.all([
        api.listBlockPatterns(),
        api.listIPBlocks(),
        api.getSettings(),
      ])
      setPatterns(p ?? [])
      setBlocks(b ?? [])
      setSettings(s ?? {})
    } catch (e) {
      toast.error(`Yüklenemedi: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setLoading(false)
    }
  }, [])

  // Settings come back JSON-encoded, so a string value arrives quoted and a
  // boolean arrives bare.
  function readSetting(key: string): string {
    const raw = settings[key]
    if (raw === undefined || raw === null) return ''
    const s = String(raw)
    if (s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1)
    return s
  }

  const blockingOn = readSetting('security_blocking_enabled') === 'true'

  async function saveSetting(key: string, value: unknown) {
    try {
      await api.updateSetting(key, value)
      setSettings((prev) => ({ ...prev, [key]: JSON.stringify(value) }))
      toast.success('Kaydedildi')
    } catch (e) {
      toast.error(`Kaydedilemedi: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  useEffect(() => { void load() }, [load])

  async function togglePattern(p: BlockPattern, enabled: boolean) {
    try {
      await api.upsertBlockPattern({ ...p, enabled })
      setPatterns((rows) =>
        rows.map((r) => (r.kind === p.kind && r.pattern === p.pattern ? { ...r, enabled } : r)),
      )
      toast.success(enabled ? 'Desen açıldı' : 'Desen kapatıldı')
    } catch (e) {
      toast.error(`Değiştirilemedi: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  async function addPattern() {
    const pattern = newPattern.trim().toLowerCase()
    if (!pattern) {
      toast.error('Desen boş olamaz')
      return
    }
    setSaving(true)
    try {
      await api.upsertBlockPattern({
        kind: newKind,
        pattern,
        score: newKind === 'allow' ? 0 : Number(newScore) || 0,
        rule: newKind === 'allow' ? '' : 'exploit_probe',
        enabled: true,
      })
      setNewPattern('')
      toast.success('Desen eklendi')
      await load()
    } catch (e) {
      toast.error(`Eklenemedi: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setSaving(false)
    }
  }

  async function removePattern(p: BlockPattern) {
    try {
      await api.deleteBlockPattern(p.kind, p.pattern)
      toast.success('Desen silindi')
      await load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    }
  }

  async function release(key: string) {
    try {
      await api.releaseIPBlock(key)
      setBlocks((rows) => rows.filter((b) => b.key !== key))
      toast.success(`${key} serbest bırakıldı`)
    } catch (e) {
      toast.error(`Bırakılamadı: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  async function flushAll() {
    if (!confirm('Bütün engeller kaldırılacak. Devam edilsin mi?')) return
    try {
      const res = await api.flushIPBlocks()
      setBlocks([])
      toast.success(`${res.released} engel kaldırıldı`)
    } catch (e) {
      toast.error(`Kaldırılamadı: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const builtinCount = patterns.filter((p) => p.builtin).length
  const activeCount = patterns.filter((p) => p.enabled).length

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Engelleme</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Sır dosyası, zafiyet ve yönetim paneli araması yapan istemciler puanlanır.
            Eşiği aşan adres bir süre 403 alır, süre dolunca kendiliğinden açılır.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          <RefreshCw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
          Yenile
        </Button>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Ayarlar</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading ? (
            <Skeleton className="h-32 w-full" />
          ) : (
            <>
              <div className="flex items-start justify-between gap-4 rounded-md border p-3">
                <div className="space-y-1">
                  <div className="text-sm font-medium">Engellemeyi aç</div>
                  <p className="text-xs text-muted-foreground max-w-xl">
                    Kapalıyken hiçbir istek reddedilmez ve puan tutulmaz. Açmadan önce
                    aşağıdaki desen listesine bakıp hiçbir meşru isteğinizin
                    puanlanmadığını doğrulayın: gerçek bir PHP uygulamanız veya
                    WordPress kurulumunuz varsa ilgili desenleri kapatın.
                  </p>
                </div>
                <Switch
                  checked={blockingOn}
                  onCheckedChange={(v) => void saveSetting('security_blocking_enabled', v)}
                />
              </div>

              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">Eşik (puan)</label>
                  <Input
                    type="number"
                    className="tabular-nums"
                    defaultValue={readSetting('security_block_threshold')}
                    onBlur={(e) =>
                      void saveSetting('security_block_threshold', Number(e.target.value))
                    }
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Bu puanı aşan adres engellenir
                  </p>
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">Pencere (saniye)</label>
                  <Input
                    type="number"
                    className="tabular-nums"
                    defaultValue={readSetting('security_block_window_seconds')}
                    onBlur={(e) =>
                      void saveSetting('security_block_window_seconds', Number(e.target.value))
                    }
                  />
                  <p className="text-[11px] text-muted-foreground">
                    {humanDuration(Number(readSetting('security_block_window_seconds')))} içindeki
                    puanlar toplanır
                  </p>
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">İlk süre (saniye)</label>
                  <Input
                    type="number"
                    className="tabular-nums"
                    defaultValue={readSetting('security_block_ttl_seconds')}
                    onBlur={(e) =>
                      void saveSetting('security_block_ttl_seconds', Number(e.target.value))
                    }
                  />
                  <p className="text-[11px] text-muted-foreground">
                    İlk engel {humanDuration(Number(readSetting('security_block_ttl_seconds')))},
                    tekrarda ikiye katlanır
                  </p>
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">Tavan (saniye)</label>
                  <Input
                    type="number"
                    className="tabular-nums"
                    defaultValue={readSetting('security_block_ttl_max_seconds')}
                    onBlur={(e) =>
                      void saveSetting('security_block_ttl_max_seconds', Number(e.target.value))
                    }
                  />
                  <p className="text-[11px] text-muted-foreground">
                    En fazla {humanDuration(Number(readSetting('security_block_ttl_max_seconds')))}
                  </p>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">
                  Hiç engellenmeyecek adresler
                </label>
                <Input
                  className="font-mono text-xs"
                  placeholder="10.0.0.0/24, 203.0.113.5"
                  defaultValue={readSetting('security_block_allowlist')}
                  onBlur={(e) =>
                    void saveSetting('security_block_allowlist', e.target.value.trim())
                  }
                />
                <p className="text-[11px] text-muted-foreground">
                  Virgülle ayrılmış IP veya CIDR. Kendi ofisiniz ve izleme servisleriniz
                  buraya. Cloudflare arkasındaki hostlarda gerçek ziyaretçi adresi
                  puanlandığı için CDN adreslerini eklemeniz gerekmez.
                </p>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-4">
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldBan className="h-4 w-4" />
              Engellenen adresler
              {blocks.length > 0 && <Badge variant="secondary">{blocks.length}</Badge>}
            </CardTitle>
            {blocks.length > 0 && (
              <Button variant="outline" size="sm" onClick={() => void flushAll()}>
                <ShieldOff className="h-4 w-4 mr-2" />
                Hepsini bırak
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <Skeleton className="h-24 w-full" />
          ) : blocks.length === 0 ? (
            <EmptyState
              icon={ShieldBan}
              title="Engellenen adres yok"
              description="Bir istemci eşiği aştığında burada görünür ve tek tıkla bırakabilirsin."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Adres</TableHead>
                  <TableHead>Sebep</TableHead>
                  <TableHead>Eşleşen</TableHead>
                  <TableHead className="text-right">Puan</TableHead>
                  <TableHead className="text-right">Kaçıncı</TableHead>
                  <TableHead>Bitiş</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {blocks.map((b) => (
                  <TableRow key={b.key}>
                    <TableCell className="font-mono text-xs">{b.key}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{RULE_LABELS[b.rule] ?? b.rule}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {b.pattern}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{b.score}</TableCell>
                    <TableCell className="text-right tabular-nums">{b.ban_count}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {b.permanent ? 'Kalıcı' : relativeTime(b.expires_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm" onClick={() => void release(b.key)}>
                        Bırak
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Desenler</CardTitle>
          <p className="text-sm text-muted-foreground">
            {activeCount} açık, {patterns.length} toplam. Bunların {builtinCount} tanesi ürünle
            gelir: kapatılabilir ama silinemez, çünkü sonraki açılışta geri gelir.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-end gap-2 rounded-md border p-3">
            <div className="flex-1 min-w-[240px] space-y-1">
              <label className="text-xs text-muted-foreground">Desen</label>
              <Input
                value={newPattern}
                onChange={(e) => setNewPattern(e.target.value)}
                placeholder=".env.production"
                className="font-mono"
              />
            </div>
            <div className="w-40 space-y-1">
              <label className="text-xs text-muted-foreground">Tür</label>
              <Select value={newKind} onValueChange={(v) => setNewKind(v as BlockPatternKind)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {(Object.keys(KIND_LABELS) as BlockPatternKind[]).map((k) => (
                    <SelectItem key={k} value={k}>{KIND_LABELS[k]}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {newKind !== 'allow' && (
              <div className="w-24 space-y-1">
                <label className="text-xs text-muted-foreground">Puan</label>
                <Input
                  type="number"
                  value={newScore}
                  onChange={(e) => setNewScore(e.target.value)}
                  className="tabular-nums"
                />
              </div>
            )}
            <Button onClick={() => void addPattern()} disabled={saving}>
              <Plus className="h-4 w-4 mr-2" />
              Ekle
            </Button>
            <p className="w-full text-xs text-muted-foreground">{KIND_HELP[newKind]}</p>
          </div>

          {loading ? (
            <Skeleton className="h-40 w-full" />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-20">Açık</TableHead>
                  <TableHead>Desen</TableHead>
                  <TableHead>Tür</TableHead>
                  <TableHead>Sınıf</TableHead>
                  <TableHead className="text-right">Puan</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {patterns.map((p) => (
                  <TableRow key={`${p.kind}:${p.pattern}`} className={cn(!p.enabled && 'opacity-50')}>
                    <TableCell>
                      <Switch
                        checked={p.enabled}
                        onCheckedChange={(v) => void togglePattern(p, v)}
                      />
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      <div className="flex items-center gap-2">
                        {p.pattern}
                        {p.builtin && <Lock className="h-3 w-3 text-muted-foreground" />}
                      </div>
                      {p.note && (
                        <div className="text-[11px] text-muted-foreground mt-0.5 font-sans">
                          {p.note}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">{KIND_LABELS[p.kind]}</TableCell>
                    <TableCell className="text-xs">
                      {p.rule ? (RULE_LABELS[p.rule] ?? p.rule) : '—'}
                    </TableCell>
                    <TableCell className="text-right">
                      {p.kind === 'allow' ? (
                        <span className="text-xs text-muted-foreground">puanlanmaz</span>
                      ) : (
                        <Badge variant="outline" className={scoreTone(p.score)}>{p.score}</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      {!p.builtin && (
                        <Button variant="ghost" size="sm" onClick={() => void removePattern(p)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
