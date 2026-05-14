import { useState } from 'react'
import {
  MoreVertical, RefreshCw, AlertCircle, Pause, RotateCw,
  Download, Trash, Bug, Eraser,
} from 'lucide-react'
import { toast } from 'sonner'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import * as api from '@/api'

/**
 * Operatör için her agent satırında bir aksiyon menüsü.
 *
 * Her komut central tarafında muvon.agent_commands tablosuna HMAC-imzalı
 * bir row olarak yazılır; agent long-poll ile çeker, imzayı doğrular,
 * çalıştırır ve sonucu raporlar.
 *
 * Yıkıcı eylemler (drain, restart, revoke) için onay dialog'u açılır —
 * "tek tıkla kazara restart" ihtimalini sıfırlamak için.
 */

interface ActionDef {
  kind: api.AgentCommandKind
  label: string
  icon: typeof RefreshCw
  destructive: boolean
  needsConfirm: boolean
  payload?: Record<string, unknown>
}

const ACTIONS: ActionDef[] = [
  { kind: 'agent.cache_flush',   label: 'Cache temizle',           icon: Eraser,    destructive: false, needsConfirm: false, payload: { target: 'all' } },
  { kind: 'cert.renew',          label: 'Sertifikayı yenile…',     icon: RefreshCw, destructive: false, needsConfirm: false },
  { kind: 'agent.set_log_level', label: 'Debug log (30 dk)',       icon: Bug,       destructive: false, needsConfirm: false, payload: { level: 'debug', ttl_seconds: 1800 } },
  { kind: 'agent.drain',         label: 'Drain (yeni trafiği red)', icon: Pause,    destructive: true,  needsConfirm: true,  payload: { enabled: true } },
  { kind: 'agent.restart',       label: 'Yeniden başlat',           icon: RotateCw, destructive: true,  needsConfirm: true },
  { kind: 'agent.self_upgrade',  label: 'Imajı güncelle',           icon: Download, destructive: true,  needsConfirm: true },
  { kind: 'agent.revoke',        label: 'Revoke (kalıcı)',          icon: Trash,    destructive: true,  needsConfirm: true },
]

interface Props {
  agentID: string
  agentName: string
  onCommandSent?: () => void
}

export function AgentActionMenu({ agentID, agentName, onCommandSent }: Props) {
  const [confirmAction, setConfirmAction] = useState<ActionDef | null>(null)
  // cert.renew için domain prompt durumu
  const [domainPromptOpen, setDomainPromptOpen] = useState(false)
  const [domain, setDomain] = useState('')

  async function send(action: ActionDef, payload?: Record<string, unknown>) {
    try {
      await api.enqueueAgentCommand(agentID, {
        kind: action.kind,
        payload: payload ?? action.payload ?? {},
      })
      toast.success(`Komut gönderildi: ${action.label}`)
      onCommandSent?.()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Komut gönderilemedi')
    }
  }

  function handleClick(action: ActionDef) {
    if (action.kind === 'cert.renew') {
      // Domain için ayrı küçük prompt — daha temiz UX
      setDomainPromptOpen(true)
      return
    }
    if (action.needsConfirm) {
      setConfirmAction(action)
      return
    }
    send(action)
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost" size="icon"
            className="h-8 w-8 text-muted-foreground hover:text-foreground cursor-pointer"
            title="Eylemler"
          >
            <MoreVertical className="h-3.5 w-3.5" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel className="text-xs">{agentName} için eylemler</DropdownMenuLabel>
          <DropdownMenuSeparator />
          {ACTIONS.filter(a => !a.destructive).map(action => (
            <DropdownMenuItem key={action.kind} onClick={() => handleClick(action)} className="cursor-pointer">
              <action.icon className="h-3.5 w-3.5 mr-2 text-muted-foreground" />
              {action.label}
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          {ACTIONS.filter(a => a.destructive).map(action => (
            <DropdownMenuItem
              key={action.kind}
              onClick={() => handleClick(action)}
              className="cursor-pointer text-destructive focus:text-destructive"
            >
              <action.icon className="h-3.5 w-3.5 mr-2" />
              {action.label}
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Yıkıcı aksiyon onay dialog'u */}
      <AlertDialog open={confirmAction !== null} onOpenChange={v => !v && setConfirmAction(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-amber-400" />
              {confirmAction?.label}
            </AlertDialogTitle>
            <AlertDialogDescription>
              <span className="font-mono">{agentName}</span> agent'ına{' '}
              <span className="font-mono">{confirmAction?.kind}</span> komutu gönderilecek.
              {confirmAction?.kind === 'agent.revoke' && (
                <span className="block mt-2 text-destructive">
                  Bu işlem agent'ı kalıcı olarak durdurur. Bağlantı yeniden kurulamaz.
                </span>
              )}
              {confirmAction?.kind === 'agent.drain' && (
                <span className="block mt-2">
                  Yeni gelen istekler 503 ile reddedilecek. Mevcut bağlantılar tamamlanır.
                </span>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Vazgeç</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (confirmAction) send(confirmAction)
                setConfirmAction(null)
              }}
              className={confirmAction?.kind === 'agent.revoke' ? 'bg-destructive hover:bg-destructive/90' : ''}
            >
              Gönder
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* cert.renew için domain prompt */}
      <AlertDialog open={domainPromptOpen} onOpenChange={v => !v && setDomainPromptOpen(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Sertifikayı yenile</AlertDialogTitle>
            <AlertDialogDescription>
              Hangi domain için cert cache'i invalidate edilsin? Bir sonraki TLS handshake'inde
              agent autocert yeni sertifika alır.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <input
            type="text"
            placeholder="example.com"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono"
            autoFocus
          />
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => { setDomain(''); setDomainPromptOpen(false) }}>
              Vazgeç
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (domain.trim()) {
                  send({ kind: 'cert.renew', label: 'Sertifikayı yenile', icon: RefreshCw, destructive: false, needsConfirm: false }, { domain: domain.trim() })
                  setDomain('')
                  setDomainPromptOpen(false)
                } else {
                  toast.error('Domain gerekli')
                }
              }}
            >
              Gönder
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
