import { useCallback, useEffect, useState } from 'react'
import {
  RefreshCw, Download, CheckCircle2, AlertCircle, ArrowUpRight,
} from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { UpgradeModal } from '@/components/UpgradeModal'

/**
 * Settings → Sistem'in baş kartı. Çalışan sürümü ve GHCR'daki son
 * sürümü yan yana gösterir. Eşitse "Güncel" badge'i, değilse "Yeni
 * sürüm mevcut" + "Güncelle" butonu.
 *
 * Versiyon karşılaştırması digest düzeyinde yapılır — semver tag yerine
 * Docker'in immutable content addressini (sha256:...) bazını alır.
 * Aynı tag'in farklı build'leri (örn. `:latest`'i CI bir kez daha push
 * ettiğinde) digest değişir, bu da kullanıcıya "patch geldi" sinyalini
 * doğru verir.
 */
export function SystemUpgradePanel() {
  const [running, setRunning] = useState<api.SystemVersion | null>(null)
  const [latest, setLatest] = useState<api.SystemVersionLatest | null>(null)
  const [loading, setLoading] = useState(true)
  const [checking, setChecking] = useState(false)
  const [upgradeOpen, setUpgradeOpen] = useState(false)

  const refresh = useCallback(async (force = false) => {
    if (force) setChecking(true)
    else setLoading(true)
    try {
      const [r, l] = await Promise.all([
        api.getSystemVersion(),
        api.getSystemVersionLatest(),
      ])
      setRunning(r)
      setLatest(l)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Sürüm bilgisi alınamadı')
    } finally {
      setLoading(false)
      setChecking(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  const updateAvailable = !!latest?.update_available
  const hasRegistryError = !!latest?.error

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 bg-muted/20 border-b border-border">
        <Download className="h-4 w-4 text-primary" />
        <span className="text-sm font-semibold">Sistem güncellemesi</span>
        <Button
          variant="ghost" size="icon"
          className="ml-auto h-7 w-7 cursor-pointer"
          onClick={() => refresh(true)}
          disabled={checking || loading}
          title="GHCR'daki son sürümü tekrar kontrol et"
        >
          <RefreshCw className={cn('h-3.5 w-3.5', (checking || loading) && 'animate-spin')} />
        </Button>
      </div>

      <div className="p-4 space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">Çalışan sürüm</p>
            <p className="text-sm font-mono break-all">
              {loading ? '...' : (running?.running ?? 'bilinmiyor')}
            </p>
          </div>
          <div className="space-y-1">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">
              GHCR :latest
            </p>
            <p className="text-sm font-mono break-all">
              {loading ? '...' : (latest?.digest ? latest.digest.slice(7, 19) : (latest?.error ? '—' : 'bilinmiyor'))}
            </p>
          </div>
        </div>

        {hasRegistryError && (
          <div className="rounded-md border border-amber-400/40 bg-amber-400/5 p-3 text-xs text-amber-300">
            <p className="flex items-center gap-1.5">
              <AlertCircle className="h-3.5 w-3.5 shrink-0" />
              GHCR sorgusu başarısız.
            </p>
            <p className="mt-1 break-all opacity-80">{latest!.error}</p>
          </div>
        )}

        {!hasRegistryError && !loading && (
          <div className="flex items-center justify-between gap-3">
            {updateAvailable ? (
              <Badge variant="outline" className="text-amber-300 border-amber-400/40">
                Yeni sürüm mevcut
              </Badge>
            ) : (
              <Badge variant="outline" className="text-emerald-300 border-emerald-400/40">
                <CheckCircle2 className="h-3 w-3 mr-1" /> Güncel
              </Badge>
            )}
            <Button
              onClick={() => setUpgradeOpen(true)}
              disabled={loading || !latest?.tag}
            >
              <Download className="h-3.5 w-3.5 mr-1.5" />
              {updateAvailable ? 'Şimdi güncelle' : 'Yeniden uygula'}
            </Button>
          </div>
        )}

        <div className="rounded-md border border-border bg-muted/10 p-3 text-xs text-muted-foreground space-y-1.5">
          <p>
            <strong className="text-foreground">Güncelleme akışı.</strong>{' '}
            PostgreSQL yedeği alınır → image'lar GHCR'dan çekilir → container'lar
            sırayla yeniden oluşturulur (dialog-siem → muvon → muvon-deployer).
            Migration'lar binary başlangıcında otomatik koşar.
          </p>
          <p>
            Hibrit kurulumda: önce central, sonra her edge agent. Agent'lar bu
            butondan etkilenmez — onları kendi sunucularında{' '}
            <code className="font-mono text-foreground">install-agent.sh</code>{' '}
            ile güncellersin.
          </p>
          <p className="flex items-center gap-1">
            <a
              href="https://github.com/SaidMuratOzdemir/MUVON/blob/main/CHANGELOG.md"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-0.5 text-foreground hover:text-primary transition-colors"
            >
              CHANGELOG <ArrowUpRight className="h-3 w-3" />
            </a>
            — sürüm notlarını oku.
          </p>
        </div>
      </div>

      <UpgradeModal
        open={upgradeOpen}
        onClose={() => setUpgradeOpen(false)}
        onCompleted={() => refresh()}
        currentTag={running?.tag ?? 'latest'}
      />
    </div>
  )
}
