import { useCallback, useEffect, useState } from 'react'
import { CheckCircle2, XCircle, Clock, AlertTriangle, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

/**
 * Agent için gönderilen son komutların durumu. State machine her
 * komut için: pending → dispatched → succeeded|failed|expired. Stale
 * komutlar central'daki sweeper tarafından 5 dk sonra expired olur.
 *
 * Bu liste sayfa yenilenince otomatik fetch eder; manuel refresh için
 * sağ üstte buton var.
 */

interface Props {
  agentID: string
  refreshKey: number  // parent enqueue yaptığında değiştirilir → re-fetch
}

const STATE_STYLE: Record<api.AgentCommand['state'], { tone: string; icon: typeof CheckCircle2 }> = {
  pending:    { tone: 'text-amber-300 border-amber-400/40 bg-amber-400/5',   icon: Clock },
  dispatched: { tone: 'text-blue-300 border-blue-400/40 bg-blue-400/5',      icon: RefreshCw },
  succeeded:  { tone: 'text-emerald-300 border-emerald-400/40 bg-emerald-400/5', icon: CheckCircle2 },
  failed:     { tone: 'text-destructive border-destructive/40 bg-destructive/5', icon: XCircle },
  expired:    { tone: 'text-muted-foreground border-border',                     icon: AlertTriangle },
}

export function AgentCommandHistory({ agentID, refreshKey }: Props) {
  const [commands, setCommands] = useState<api.AgentCommand[]>([])
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const rows = await api.listAgentCommands(agentID, 10)
      setCommands(rows ?? [])
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Komut listesi alınamadı')
    } finally {
      setLoading(false)
    }
  }, [agentID])

  useEffect(() => { load() }, [load, refreshKey])

  if (loading && commands.length === 0) {
    return <p className="text-xs text-muted-foreground">Komutlar yükleniyor…</p>
  }
  if (commands.length === 0) {
    return null
  }

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">Son komutlar</p>
        <Button
          variant="ghost" size="icon"
          className="h-5 w-5 text-muted-foreground hover:text-foreground"
          onClick={load}
          disabled={loading}
          title="Yenile"
        >
          <RefreshCw className={cn('h-3 w-3', loading && 'animate-spin')} />
        </Button>
      </div>
      <div className="space-y-1">
        {commands.map(cmd => {
          const style = STATE_STYLE[cmd.state]
          return (
            <div
              key={cmd.id}
              className={cn(
                'flex items-center gap-2 rounded border px-2 py-1 text-xs',
                style.tone,
              )}
              title={cmd.result?.error || cmd.result?.output || ''}
            >
              <style.icon className={cn('h-3 w-3 shrink-0', cmd.state === 'dispatched' && 'animate-spin')} />
              <span className="font-mono shrink-0">{cmd.kind}</span>
              <Badge variant="outline" className={cn('text-[10px] py-0 px-1.5 shrink-0', style.tone)}>
                {cmd.state}
              </Badge>
              <span className="text-[10px] text-muted-foreground ml-auto shrink-0">
                {new Date(cmd.created_at).toLocaleTimeString()}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
