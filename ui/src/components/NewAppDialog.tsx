import { useEffect, useState } from 'react'
import { Loader2, Plus } from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import type { Agent } from '@/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Dialog, DialogContent, DialogDescription,
  DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'

const slugPattern = /^[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]$|^[a-z0-9]$/

// suggestSlug builds a URL-safe slug from a free-text name. Strips
// diacritics (handled by the source's already-lowercase Latin form),
// collapses everything else into hyphens, and clamps to 64 chars.
function suggestSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
}

interface NewAppDialogProps {
  open: boolean
  onClose: () => void
  onCreated: (projectSlug: string) => void
}

// agentID tri-state:
//   null  → operator hasn't picked yet (submit blocked)
//   ''    → central (this MUVON host)
//   uuid  → edge agent's ID
// Default null so the wizard never silently defaults to central — that
// foot-gun caused real components to land on the wrong host.
type HostChoice = string | null

export function NewAppDialog({ open, onClose, onCreated }: NewAppDialogProps) {
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [slugTouched, setSlugTouched] = useState(false)
  const [sourceRepo, setSourceRepo] = useState('')
  const [componentSlug, setComponentSlug] = useState('web')
  const [imageRepo, setImageRepo] = useState('')
  const [internalPort, setInternalPort] = useState('8080')
  const [healthPath, setHealthPath] = useState('/health')
  const [agentID, setAgentID] = useState<HostChoice>(null)
  const [agents, setAgents] = useState<Agent[]>([])
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (!open) return
    setAgentID(null)
    api.listAgents()
      .then(setAgents)
      .catch(err => toast.error(err instanceof Error ? err.message : "Agent listesi alınamadı"))
  }, [open])

  function reset() {
    setName('')
    setSlug('')
    setSlugTouched(false)
    setSourceRepo('')
    setComponentSlug('web')
    setImageRepo('')
    setInternalPort('8080')
    setHealthPath('/health')
    setAgentID(null)
    setSubmitting(false)
  }

  function handleClose() {
    if (submitting) return
    reset()
    onClose()
  }

  function handleNameChange(value: string) {
    setName(value)
    if (!slugTouched) {
      setSlug(suggestSlug(value))
    }
  }

  function validate(): string | null {
    if (!name.trim()) return 'Uygulama adı gerekli'
    if (!slugPattern.test(slug)) return 'Tanımlayıcı 1–64 karakter, küçük harf/rakam/(-,_) olmalı'
    if (!componentSlug.trim()) return 'Servis tanımlayıcısı gerekli'
    if (!slugPattern.test(componentSlug)) return 'Servis tanımlayıcısı slug formatında olmalı'
    if (!imageRepo.trim()) return 'Docker image gerekli'
    const port = Number(internalPort)
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return 'Port 1–65535 arasında olmalı'
    if (agentID === null) return 'Konum seçilmedi: ya bu MUVON sunucusunu ya da bir agent seç'
    return null
  }

  async function handleSubmit() {
    const err = validate()
    if (err) {
      toast.error(err)
      return
    }
    setSubmitting(true)
    try {
      await api.createDeployProject({
        slug: slug.trim(),
        name: name.trim(),
        source_repo: sourceRepo.trim() || undefined,
      })
      try {
        await api.createDeployComponent(slug.trim(), {
          slug: componentSlug.trim(),
          name: name.trim(),
          image_repo: imageRepo.trim(),
          internal_port: Number(internalPort),
          health_path: healthPath.trim() || '/',
          agent_id: agentID || undefined,  // null/'' → central (omit); uuid → edge
        })
      } catch (componentErr) {
        // Project created but component failed — surface this clearly so
        // the operator knows the partial state (project exists, no service).
        toast.error(
          `Uygulama oluşturuldu ama servis eklenemedi: ${
            componentErr instanceof Error ? componentErr.message : 'bilinmeyen hata'
          }. Uygulama detayından servisi tekrar ekleyin.`,
          { duration: 8000 },
        )
        onCreated(slug.trim())
        reset()
        onClose()
        return
      }
      toast.success('Uygulama oluşturuldu')
      onCreated(slug.trim())
      reset()
      onClose()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Oluşturulamadı')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={v => !v && handleClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Plus className="h-4 w-4 text-primary" />
            Yeni Uygulama
          </DialogTitle>
          <DialogDescription>
            Hemen başlamak için adı, Docker image'ı ve dinleme portunu girmen yeterli. Detayları sonra düzenleyebilirsin.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 pt-1">
          <div className="space-y-1.5">
            <Label className="text-xs">Nerede host edilecek? <span className="text-destructive">*</span></Label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setAgentID('')}
                className={`rounded-md border px-3 py-2 text-left text-sm transition-colors ${
                  agentID === '' ? 'border-primary bg-primary/5' : 'border-border hover:bg-muted/20'
                }`}
              >
                <div className="font-medium">Bu MUVON sunucusu</div>
                <div className="text-[11px] text-muted-foreground mt-0.5">Container'lar central'da çalışır</div>
              </button>
              <div className="space-y-1">
                <select
                  value={agentID ?? ''}
                  onChange={e => setAgentID(e.target.value === '' ? null : e.target.value)}
                  disabled={agents.length === 0}
                  className={`w-full rounded-md border px-3 py-2 text-sm bg-background disabled:opacity-40 disabled:cursor-not-allowed ${
                    agentID !== '' && agentID !== null ? 'border-primary bg-primary/5' : 'border-border'
                  }`}
                >
                  <option value="">— Agent seç —</option>
                  {agents.map(a => (
                    <option key={a.id} value={a.id}>{a.name} ({a.id.slice(0, 8)})</option>
                  ))}
                </select>
                <p className="text-[11px] text-muted-foreground">
                  {agents.length === 0 ? 'Tanımlı agent yok' : 'Müşterinin sunucusunda çalışan agent'}
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs">Uygulama adı <span className="text-destructive">*</span></Label>
            <Input
              placeholder="Müşteri portalı"
              value={name}
              onChange={e => handleNameChange(e.target.value)}
              autoFocus
            />
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs">Tanımlayıcı (URL ve panelde kullanılır)</Label>
            <Input
              placeholder="musteri-portali"
              value={slug}
              onChange={e => { setSlug(e.target.value); setSlugTouched(true) }}
              className="font-mono text-sm"
            />
            <p className="text-[11px] text-muted-foreground">Küçük harf, rakam, tire veya alt çizgi. Oluşturulduktan sonra değiştirilemez.</p>
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs">Kaynak repo (opsiyonel)</Label>
            <Input
              placeholder="github.com/firma/musteri-portali"
              value={sourceRepo}
              onChange={e => setSourceRepo(e.target.value)}
              className="font-mono text-sm"
            />
          </div>

          <div className="pt-2 mt-2 border-t border-border space-y-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">İlk Servis</p>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Servis tanımlayıcısı</Label>
                <Input
                  placeholder="web"
                  value={componentSlug}
                  onChange={e => setComponentSlug(e.target.value)}
                  className="font-mono text-sm"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Dinleme portu <span className="text-destructive">*</span></Label>
                <Input
                  type="number"
                  min={1}
                  max={65535}
                  value={internalPort}
                  onChange={e => setInternalPort(e.target.value)}
                  className="font-mono text-sm"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Docker image <span className="text-destructive">*</span></Label>
              <Input
                placeholder="ghcr.io/firma/musteri-portali"
                value={imageRepo}
                onChange={e => setImageRepo(e.target.value)}
                className="font-mono text-sm"
              />
              <p className="text-[11px] text-muted-foreground">
                Image:tag, deploy webhook'unda gönderilir. Burada sadece repo adresi yeterli.
              </p>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Sağlık kontrolü yolu</Label>
              <Input
                placeholder="/health"
                value={healthPath}
                onChange={e => setHealthPath(e.target.value)}
                className="font-mono text-sm"
              />
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={handleClose} disabled={submitting}>İptal</Button>
          <Button onClick={handleSubmit} disabled={submitting}>
            {submitting && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
            Oluştur
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
