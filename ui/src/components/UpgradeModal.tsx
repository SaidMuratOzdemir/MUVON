import { useEffect, useMemo, useState } from 'react'
import {
  Loader2, AlertTriangle, CheckCircle2, XCircle, Download, FileText,
} from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Dialog, DialogContent, DialogDescription,
  DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'

const SEMVER_RE = /^v?\d+\.\d+\.\d+$/
function isStrictSemver(s: string): boolean { return SEMVER_RE.test(s.trim()) }
function compareSemver(a: string, b: string): number {
  const pa = a.replace(/^v/, '').split('.').map(n => parseInt(n, 10))
  const pb = b.replace(/^v/, '').split('.').map(n => parseInt(n, 10))
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i]
  }
  return 0
}

interface Props {
  open: boolean
  onClose: () => void
  onCompleted: () => void
  currentTag: string
}

/**
 * İki aşamalı modal:
 *   1. Konfigürasyon — hedef tag seçimi, DB yedek tercihi, CHANGELOG önizleme.
 *      "Başlat" butonuna basıldığında upgrade başlatılır.
 *   2. İlerleme — SSE event stream'i; her adım renderlanır.
 *
 * Hata durumlarında modal kapanmaz, kullanıcı state'i görür ve manuel
 * kapatır (re-try için tekrar açar).
 */
export function UpgradeModal({ open, onClose, onCompleted, currentTag }: Props) {
  // ── Form state (Aşama 1)
  const [targetTag, setTargetTag] = useState(currentTag || 'latest')
  const [customTag, setCustomTag] = useState('')
  const [takeBackup, setTakeBackup] = useState(true)
  const [changelog, setChangelog] = useState<string | null>(null)
  const [changelogOpen, setChangelogOpen] = useState(false)

  // ── Upgrade state (Aşama 2)
  const [phase, setPhase] = useState<'config' | 'running' | 'done' | 'failed'>('config')
  const [events, setEvents] = useState<api.UpgradeEvent[]>([])
  const [closeStream, setCloseStream] = useState<(() => void) | null>(null)

  // Reset on open
  useEffect(() => {
    if (!open) return
    setPhase('config')
    setEvents([])
    setTargetTag(currentTag || 'latest')
    setCustomTag('')
    setTakeBackup(true)
    setChangelog(null)
    setChangelogOpen(false)
    return () => {
      if (closeStream) closeStream()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  // CHANGELOG'u tembel yükle — kullanıcı butona basınca.
  async function loadChangelog() {
    if (changelog) {
      setChangelogOpen(o => !o)
      return
    }
    try {
      const md = await api.fetchChangelog()
      setChangelog(md)
      setChangelogOpen(true)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "CHANGELOG yüklenemedi")
    }
  }

  // Üst [Unreleased] / ilk sürüm bölümünü kes — iki ## başlık arası.
  const changelogPreview = useMemo(() => {
    if (!changelog) return ''
    const parts = changelog.split(/^## /m)
    // parts[0] = preamble, parts[1] = ilk ## bloğu (## başlığı kaldırılmış)
    return parts.length > 1 ? '## ' + parts[1].trim() : changelog.trim()
  }, [changelog])

  async function handleStart() {
    const effectiveTag = customTag.trim() || targetTag
    if (!effectiveTag) {
      toast.error('Hedef tag boş olamaz')
      return
    }
    // Downgrade engelleme: semver formundaki bir tag çalışan sürümden küçükse uyar.
    // latest/v0/v0.1 gibi semver olmayanlar atlanır (rolling tag, downgrade tanımsız).
    if (currentTag && isStrictSemver(effectiveTag) && isStrictSemver(currentTag)) {
      if (compareSemver(effectiveTag, currentTag) < 0) {
        const ok = window.confirm(
          `Downgrade: ${currentTag} → ${effectiveTag}\n\n` +
          `Forward-only migration kuralı: yeni schema'dan eskiye dönüş desteklenmez. ` +
          `Devam edersen container'lar muhtemelen başlatılamaz. Yine de deneyeyim mi?`,
        )
        if (!ok) return
      }
    }
    setPhase('running')
    setEvents([])
    try {
      await api.startSystemUpgrade({
        target_tag: effectiveTag,
        take_backup: takeBackup,
      })
    } catch (err) {
      // 409 veya benzeri — phase'i geri al
      setPhase('config')
      toast.error(err instanceof Error ? err.message : 'Güncelleme başlatılamadı')
      return
    }
    // Stream'e bağlan
    const close = api.createUpgradeStream(
      ev => {
        setEvents(prev => [...prev, ev])
        if (ev.done) {
          setPhase(ev.level === 'error' ? 'failed' : 'done')
          if (ev.level !== 'error') onCompleted()
        }
      },
      () => {
        // Server-side stream EOF — phase already settled by Done event,
        // but if not, fall through to done (deployer kendi container'ını
        // restart ettiği zaman stream EOF olur — bu success demek).
        setPhase(p => (p === 'running' ? 'done' : p))
        onCompleted()
      },
      () => {
        // Network error veya disconnect — running fazında ise informational.
        setPhase(p => (p === 'running' ? 'done' : p))
      },
    )
    setCloseStream(() => close)
  }

  return (
    <Dialog open={open} onOpenChange={v => !v && phase !== 'running' && onClose()}>
      <DialogContent className="max-w-2xl max-h-[90vh] flex flex-col overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Download className="h-4 w-4 text-primary" />
            Sistem güncellemesi
          </DialogTitle>
          <DialogDescription>
            {phase === 'config' && 'Hedef sürümü seç ve güncellemeyi başlat.'}
            {phase === 'running' && 'Güncelleme devam ediyor — sayfayı kapatma.'}
            {phase === 'done' && 'Güncelleme tamamlandı.'}
            {phase === 'failed' && 'Güncelleme başarısız oldu. Sunucu durumunu kontrol et.'}
          </DialogDescription>
        </DialogHeader>

        {phase === 'config' && (
          <div className="space-y-4 overflow-y-auto pt-1">
            <div className="space-y-2">
              <Label className="text-xs">Hedef sürüm</Label>
              <div className="grid grid-cols-3 gap-2">
                {(['latest', 'v0', 'v0.1'] as const).map(opt => (
                  <button
                    key={opt}
                    type="button"
                    onClick={() => { setTargetTag(opt); setCustomTag('') }}
                    className={cn(
                      'rounded-md border px-3 py-2 text-sm transition-colors text-left',
                      targetTag === opt && !customTag
                        ? 'border-primary bg-primary/5'
                        : 'border-border hover:bg-muted/20',
                    )}
                  >
                    <div className="font-mono font-medium">{opt}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">
                      {opt === 'latest'
                        ? 'her zaman en yeni'
                        : opt === 'v0'
                          ? 'major pin'
                          : 'minor pin'}
                    </div>
                  </button>
                ))}
              </div>
              <input
                type="text"
                placeholder="Veya tam sürüm: v0.1.0"
                value={customTag}
                onChange={e => setCustomTag(e.target.value)}
                className={cn(
                  'w-full rounded-md border px-3 py-2 text-sm font-mono bg-background',
                  customTag ? 'border-primary' : 'border-border',
                )}
              />
              <p className="text-[11px] text-muted-foreground">
                Patch pin (`v0.1.0`) en güvenli — major bump'lar otomatik gelmez.
              </p>
            </div>

            <div className="rounded-md border border-border p-3 flex items-start gap-2">
              <input
                id="take-backup"
                type="checkbox"
                checked={takeBackup}
                onChange={e => setTakeBackup(e.target.checked)}
                className="mt-0.5 h-4 w-4"
              />
              <div className="space-y-1 min-w-0">
                <Label htmlFor="take-backup" className="text-sm cursor-pointer">
                  PostgreSQL yedeği al (pg_dump -Fc)
                </Label>
                <p className="text-[11px] text-muted-foreground">
                  <code className="font-mono">/var/lib/muvon/backups/</code>{' '}
                  altına yazılır. Migration başarısız olursa elle restore yapabilirsin.
                </p>
              </div>
            </div>

            <div className="space-y-2">
              <Button variant="outline" size="sm" onClick={loadChangelog} className="w-full">
                <FileText className="h-3.5 w-3.5 mr-1.5" />
                {changelog ? (changelogOpen ? 'CHANGELOG\'u gizle' : 'CHANGELOG\'u göster') : 'CHANGELOG\'u getir'}
              </Button>
              {changelogOpen && changelog && (
                <pre className="text-[11px] font-mono bg-muted/20 border border-border rounded-md p-3 overflow-auto max-h-60 whitespace-pre-wrap">
                  {changelogPreview}
                </pre>
              )}
            </div>

            <div className="rounded-md border border-amber-400/30 bg-amber-400/5 p-3 flex items-start gap-2 text-xs text-amber-300">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <p><strong>Bilmen gerekenler:</strong></p>
                <ul className="list-disc list-inside space-y-0.5 opacity-90">
                  <li>Container'lar ~30-60 saniye için yeniden başlatılır.</li>
                  <li>Migration başarısız olursa muvon başlatılamaz; yedekten restore lazım.</li>
                  <li>Downgrade desteklenmiyor — yeni sürümden eskiye geri dönüş zor.</li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {(phase === 'running' || phase === 'done' || phase === 'failed') && (
          <div className="flex-1 overflow-y-auto space-y-2 pt-1">
            {events.length === 0 && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Güncelleme başlatılıyor...
              </div>
            )}
            {events.map((ev, i) => (
              <UpgradeEventRow key={i} ev={ev} />
            ))}
            {phase === 'done' && (
              <div className="mt-3 flex items-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/5 p-3 text-sm text-emerald-300">
                <CheckCircle2 className="h-4 w-4" />
                <span>Güncelleme tamamlandı. Sayfayı yenilemen önerilir.</span>
              </div>
            )}
            {phase === 'failed' && (
              <div className="mt-3 flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
                <XCircle className="h-4 w-4" />
                <span>Güncelleme başarısız oldu. Sunucu log'una bak.</span>
              </div>
            )}
          </div>
        )}

        <DialogFooter className="shrink-0 pt-2 border-t border-border">
          {phase === 'config' && (
            <>
              <Button variant="ghost" onClick={onClose}>İptal</Button>
              <Button onClick={handleStart}>
                <Download className="h-3.5 w-3.5 mr-1.5" />
                Başlat
              </Button>
            </>
          )}
          {phase === 'running' && (
            <p className="text-xs text-muted-foreground">
              Bittiğinde otomatik bildirim alacaksın — kapatma.
            </p>
          )}
          {(phase === 'done' || phase === 'failed') && (
            <>
              <Button variant="ghost" onClick={onClose}>Kapat</Button>
              <Button onClick={() => window.location.reload()}>Sayfayı yenile</Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function UpgradeEventRow({ ev }: { ev: api.UpgradeEvent }) {
  const icon = ev.done && ev.level === 'error'
    ? <XCircle className="h-4 w-4 text-destructive" />
    : ev.done
      ? <CheckCircle2 className="h-4 w-4 text-emerald-400" />
      : ev.level === 'warn'
        ? <AlertTriangle className="h-4 w-4 text-amber-400" />
        : <Loader2 className="h-4 w-4 text-muted-foreground animate-spin" />
  return (
    <div className="flex items-start gap-2 text-xs font-mono">
      <span className="shrink-0 pt-0.5">{icon}</span>
      <span className="text-[10px] text-muted-foreground/70 shrink-0 pt-0.5">
        {ev.step}
      </span>
      <span className="break-all">{ev.message}</span>
    </div>
  )
}
