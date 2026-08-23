import { useCallback, useEffect, useState } from 'react'
import { Database, Loader2, ShieldCheck, ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'

/**
 * The backup card under Settings, "Sistem".
 *
 * The button calls the dump flow on its own, independently of a system
 * upgrade, which is what makes it useful before any risky work. A file is
 * published only after it passes verification.
 */
export function BackupPanel() {
  const [list, setList] = useState<api.BackupList | null>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setList(await api.listBackups())
    } catch {
      setList(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  async function takeBackup() {
    setRunning(true)
    try {
      const r = await api.createBackup()
      if (r.verified) {
        toast.success(`Yedek alındı ve doğrulandı (${formatBytes(r.bytes)})`)
      } else {
        toast.warning(`Yedek alındı ama doğrulanamadı: ${r.note || 'sebep bildirilmedi'}`)
      }
      await refresh()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Yedek alınamadı')
    } finally {
      setRunning(false)
    }
  }

  const newest = list?.backups?.[0]

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="flex items-center justify-between gap-2 px-4 py-3 bg-muted/20 border-b border-border">
        <div className="flex items-center gap-2 min-w-0">
          <Database className="h-4 w-4 text-primary shrink-0" />
          <span className="text-sm font-semibold text-foreground truncate">Veritabanı Yedeği</span>
        </div>
        <Button size="sm" onClick={takeBackup} disabled={running} className="cursor-pointer">
          {running && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
          {running ? 'Alınıyor…' : 'Yedek al'}
        </Button>
      </div>

      <div className="px-4 py-3 space-y-3">
        <p className="text-xs text-muted-foreground">
          <code className="font-mono">pg_dump -Fc</code> alınır, dosya <code className="font-mono">pg_restore</code> ile
          okunabildiği doğrulandıktan sonra yayınlanır. Doğrulamayı geçemeyen dosya{' '}
          <code className="font-mono">.rejected</code> olarak saklanır, yedek sayılmaz.
          {list?.keep_limit ? ` Son ${list.keep_limit} yedek tutulur, eskiler silinir.` : ''}
        </p>

        {loading ? (
          <p className="text-xs text-muted-foreground">Yükleniyor…</p>
        ) : !list || list.backups.length === 0 ? (
          <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2">
            <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
            <p className="text-xs text-amber-300">
              Hiç yedek yok. Yükseltme veya şema değişikliği öncesi bir tane alın.
            </p>
          </div>
        ) : (
          <>
            <div className="flex items-center gap-2 text-xs">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
              <span className="text-muted-foreground">
                En yeni: <span className="font-mono text-foreground">{newest?.name}</span>{' '}
                · {formatBytes(newest?.bytes ?? 0)} · {formatWhen(newest?.created_at)}
              </span>
            </div>
            <div className="divide-y divide-border/60 rounded-md border border-border/60">
              {list.backups.map(b => (
                <div key={b.name} className="flex items-center justify-between gap-3 px-3 py-2">
                  <span className="text-xs font-mono text-muted-foreground truncate">{b.name}</span>
                  <div className="flex items-center gap-2 shrink-0">
                    <Badge variant="outline" className="text-[10px] font-mono">{formatBytes(b.bytes)}</Badge>
                    <span className="text-[11px] text-muted-foreground">{formatWhen(b.created_at)}</span>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function formatBytes(n: number): string {
  if (n <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  return `${(n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

function formatWhen(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString('tr-TR', { dateStyle: 'short', timeStyle: 'short' })
}
