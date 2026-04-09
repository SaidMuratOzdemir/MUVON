import { useState, useEffect, useCallback } from 'react'
import {
  Shield, Trash2, RefreshCw, AlertTriangle,
  CheckCircle2, Clock, Upload, Loader2,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { cn } from '@/lib/utils'
import * as api from '@/api'
import type { TLSCert } from '@/types'

function daysUntil(dateStr: string): number {
  const diff = new Date(dateStr).getTime() - Date.now()
  return Math.ceil(diff / (1000 * 60 * 60 * 24))
}

function CertCard({ cert, onDelete }: { cert: TLSCert; onDelete: () => void }) {
  const days = daysUntil(cert.expires_at)
  const isExpired = days < 0
  const isCritical = days < 7 && !isExpired
  const isWarning = days < 30 && !isCritical && !isExpired

  const statusColor = isExpired
    ? 'border-destructive/40 bg-destructive/5'
    : isCritical
      ? 'border-destructive/40 bg-destructive/5'
      : isWarning
        ? 'border-yellow-400/40 bg-yellow-400/5'
        : 'border-primary/20 bg-primary/5'

  const icon = isExpired || isCritical
    ? <AlertTriangle className="h-5 w-5 text-destructive" />
    : isWarning
      ? <AlertTriangle className="h-5 w-5 text-yellow-400" />
      : <CheckCircle2 className="h-5 w-5 text-primary" />

  const expiryBadge = isExpired
    ? <Badge variant="destructive" className="text-xs">Expired</Badge>
    : isCritical
      ? <Badge variant="destructive" className="text-xs">{days}d left</Badge>
      : isWarning
        ? <Badge variant="outline" className="text-xs text-yellow-400 border-yellow-400/40">{days}d left</Badge>
        : <Badge variant="default" className="text-xs">{days}d left</Badge>

  return (
    <div className={cn('rounded-lg border p-4 flex items-start gap-4 transition-colors', statusColor)}>
      <div className="shrink-0 mt-0.5">{icon}</div>
      <div className="flex-1 min-w-0 space-y-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono font-semibold text-foreground">{cert.domain}</span>
          {expiryBadge}
        </div>
        <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <Shield className="h-3 w-3 shrink-0" />
            <span className="truncate">{cert.issuer || 'Unknown issuer'}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Clock className="h-3 w-3 shrink-0" />
            <span>Expires: {new Date(cert.expires_at).toLocaleDateString()}</span>
          </div>
          <div className="text-muted-foreground/60">
            Added: {new Date(cert.created_at).toLocaleDateString()}
          </div>
          <div className="text-muted-foreground/60">ID: {cert.id}</div>
        </div>
      </div>
      <Button
        variant="ghost"
        size="icon"
        className="shrink-0 h-8 w-8 cursor-pointer hover:text-destructive hover:bg-destructive/10"
        onClick={onDelete}
      >
        <Trash2 className="h-4 w-4" />
      </Button>
    </div>
  )
}

export default function TLSCerts() {
  const [certs, setCerts] = useState<TLSCert[]>([])
  const [loading, setLoading] = useState(true)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<TLSCert | null>(null)
  const [form, setForm] = useState({ domain: '', cert_pem: '', key_pem: '' })
  const [uploading, setUploading] = useState(false)
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setCerts((await api.listCerts()) ?? [])
    } catch {
      toast.error('Failed to load certificates')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleUpload() {
    if (!form.domain || !form.cert_pem || !form.key_pem) {
      toast.error('All fields are required')
      return
    }
    setUploading(true)
    try {
      await api.uploadCert({ domain: form.domain, cert_pem: form.cert_pem, key_pem: form.key_pem })
      toast.success(`Certificate uploaded for ${form.domain}`)
      setForm({ domain: '', cert_pem: '', key_pem: '' })
      setUploadOpen(false)
      await load()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  async function handleDelete(cert: TLSCert) {
    try {
      await api.deleteCert(cert.id)
      toast.success(`Certificate for ${cert.domain} deleted`)
      setCerts(prev => prev.filter(c => c.id !== cert.id))
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Delete failed')
    } finally {
      setDeleteTarget(null)
    }
  }

  function readFile(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = e => resolve(e.target?.result as string)
      reader.onerror = reject
      reader.readAsText(file)
    })
  }

  async function handleCertFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const text = await readFile(file)
    setForm(f => ({ ...f, cert_pem: text }))
  }

  async function handleKeyFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const text = await readFile(file)
    setForm(f => ({ ...f, key_pem: text }))
  }

  const filtered = certs.filter(c =>
    c.domain.toLowerCase().includes(search.toLowerCase())
  )

  const expiringSoon = certs.filter(c => {
    const d = daysUntil(c.expires_at)
    return d >= 0 && d < 30
  }).length

  const expired = certs.filter(c => daysUntil(c.expires_at) < 0).length

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">TLS Certificates</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            {certs.length} certificate{certs.length !== 1 ? 's' : ''}
            {expiringSoon > 0 && (
              <span className="ml-2 text-yellow-400">&bull; {expiringSoon} expiring soon</span>
            )}
            {expired > 0 && (
              <span className="ml-2 text-destructive">&bull; {expired} expired</span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon" onClick={load} className="h-9 w-9 cursor-pointer border-border">
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </Button>
          <Button onClick={() => setUploadOpen(true)} className="gap-2 cursor-pointer">
            <Upload className="h-4 w-4" /> Upload Certificate
          </Button>
        </div>
      </div>

      {/* Let's Encrypt info */}
      <div className="flex items-start gap-3 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 text-sm">
        <CheckCircle2 className="h-4 w-4 text-primary shrink-0 mt-0.5" />
        <div>
          <p className="text-foreground font-medium">Automatic TLS via Let's Encrypt</p>
          <p className="text-muted-foreground text-xs mt-0.5">
            DiaLog automatically provisions and renews certificates for configured hosts.
            Manually uploaded certificates take priority over Let's Encrypt.
          </p>
        </div>
      </div>

      {/* Search */}
      <Input
        placeholder="Search certificates…"
        className="max-w-sm bg-card border-border"
        value={search}
        onChange={e => setSearch(e.target.value)}
      />

      {/* List */}
      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3].map(i => <Skeleton key={i} className="h-24 w-full rounded-lg" />)}
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <Shield className="h-12 w-12 text-muted-foreground/30 mb-4" />
          <p className="text-muted-foreground">
            {search ? 'No certificates match your search' : 'No manually uploaded certificates'}
          </p>
          {!search && (
            <p className="text-xs text-muted-foreground/60 mt-2">
              Let's Encrypt certificates are managed automatically
            </p>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(cert => (
            <CertCard
              key={cert.id}
              cert={cert}
              onDelete={() => setDeleteTarget(cert)}
            />
          ))}
        </div>
      )}

      {/* Upload Dialog */}
      <Dialog open={uploadOpen} onOpenChange={v => !v && setUploadOpen(false)}>
        <DialogContent className="bg-card border-border max-w-lg">
          <DialogHeader>
            <DialogTitle>Upload TLS Certificate</DialogTitle>
            <DialogDescription>
              Upload a PEM-encoded certificate and private key. This will override Let's Encrypt for the specified domain.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label>Domain</Label>
              <Input
                placeholder="example.com"
                className="bg-background border-border font-mono"
                value={form.domain}
                onChange={e => setForm(f => ({ ...f, domain: e.target.value }))}
              />
            </div>
            <div className="space-y-2">
              <Label>Certificate (PEM)</Label>
              <div className="space-y-2">
                <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer hover:text-foreground transition-colors">
                  <Upload className="h-3.5 w-3.5" />
                  Upload .crt / .pem file
                  <input type="file" accept=".pem,.crt,.cer" className="sr-only" onChange={handleCertFile} />
                </label>
                <textarea
                  rows={4}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;..."
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-xs font-mono text-foreground placeholder:text-muted-foreground resize-none focus:outline-none focus:ring-2 focus:ring-ring"
                  value={form.cert_pem}
                  onChange={e => setForm(f => ({ ...f, cert_pem: e.target.value }))}
                />
              </div>
              {form.cert_pem && (
                <p className="text-xs text-primary flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3" /> Certificate loaded
                </p>
              )}
            </div>
            <div className="space-y-2">
              <Label>Private Key (PEM)</Label>
              <div className="space-y-2">
                <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer hover:text-foreground transition-colors">
                  <Upload className="h-3.5 w-3.5" />
                  Upload .key / .pem file
                  <input type="file" accept=".pem,.key" className="sr-only" onChange={handleKeyFile} />
                </label>
                <textarea
                  rows={4}
                  placeholder="-----BEGIN PRIVATE KEY-----&#10;..."
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-xs font-mono text-foreground placeholder:text-muted-foreground resize-none focus:outline-none focus:ring-2 focus:ring-ring"
                  value={form.key_pem}
                  onChange={e => setForm(f => ({ ...f, key_pem: e.target.value }))}
                />
              </div>
              {form.key_pem && (
                <p className="text-xs text-primary flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3" /> Private key loaded
                </p>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadOpen(false)} className="cursor-pointer border-border">Cancel</Button>
            <Button onClick={handleUpload} disabled={uploading} className="cursor-pointer">
              {uploading && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
              Upload Certificate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Dialog */}
      <AlertDialog open={!!deleteTarget} onOpenChange={v => !v && setDeleteTarget(null)}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Certificate</AlertDialogTitle>
            <AlertDialogDescription>
              Delete the certificate for <code className="font-mono text-foreground">{deleteTarget?.domain}</code>?
              Let's Encrypt will be used instead if the domain is still active.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="cursor-pointer border-border">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90 cursor-pointer"
              onClick={() => deleteTarget && handleDelete(deleteTarget)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
