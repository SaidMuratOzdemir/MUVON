import { useState } from 'react'
import { toast } from 'sonner'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import * as api from '@/api'

const MIN_LENGTH = 8

/**
 * Changing the password is also "sign out everywhere": the server bumps
 * token_version, so access tokens on other devices stop validating on their
 * next request and their refresh rows are revoked. This session stays open
 * because the server returns fresh cookies.
 */
export function ChangePasswordDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [saving, setSaving] = useState(false)

  function reset() {
    setCurrent('')
    setNext('')
    setConfirm('')
  }

  const tooShort = next.length > 0 && next.length < MIN_LENGTH
  const mismatch = confirm.length > 0 && next !== confirm
  const canSubmit =
    current.length > 0 && next.length >= MIN_LENGTH && next === confirm && !saving

  async function submit() {
    setSaving(true)
    try {
      await api.changePassword(current, next)
      toast.success('Parola değiştirildi', {
        description: 'Diğer tüm oturumlar kapatıldı.',
      })
      reset()
      onOpenChange(false)
    } catch (err) {
      toast.error('Parola değiştirilemedi', {
        description: err instanceof Error ? err.message : String(err),
      })
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset()
        onOpenChange(next)
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Parolayı değiştir</DialogTitle>
          <DialogDescription>
            Kaydettiğinde bu hesabın diğer tüm oturumları kapanır.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label className="text-xs" htmlFor="current-password">
              Mevcut parola
            </Label>
            <Input
              id="current-password"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs" htmlFor="new-password">
              Yeni parola
            </Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
            {tooShort && (
              <p className="text-xs text-destructive">
                En az {MIN_LENGTH} karakter olmalı.
              </p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs" htmlFor="confirm-password">
              Yeni parola (tekrar)
            </Label>
            <Input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && canSubmit) submit()
              }}
            />
            {mismatch && (
              <p className="text-xs text-destructive">Parolalar eşleşmiyor.</p>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={saving}>
            Vazgeç
          </Button>
          <Button onClick={submit} disabled={!canSubmit}>
            {saving ? 'Kaydediliyor...' : 'Değiştir'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
