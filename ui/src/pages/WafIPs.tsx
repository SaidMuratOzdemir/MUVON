import { useState, useEffect, useCallback } from 'react'
import {
  ShieldBan, ShieldCheck, Search,
  Ban, CheckCircle2, AlertTriangle,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
// Select unused for now but kept for future filter enhancements
import { cn, relativeTime } from '@/lib/utils'
import { EmptyState } from '@/components/EmptyState'
import * as api from '@/api'
import type { WafIPState } from '@/types'

type IPFilter = 'all' | 'banned' | 'whitelisted' | 'scored'

function ipStatusBadge(ip: WafIPState) {
  if (ip.banned) return { label: 'Banned', cls: 'bg-red-500/10 text-red-400 border-red-500/20', icon: ShieldBan }
  if (ip.whitelisted) return { label: 'Whitelisted', cls: 'bg-primary/10 text-primary border-primary/20', icon: ShieldCheck }
  if (ip.cumulative_score > 0) return { label: 'Scored', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/20', icon: AlertTriangle }
  return { label: 'Clean', cls: 'bg-muted text-muted-foreground border-border', icon: CheckCircle2 }
}

function scoreColor(score: number): string {
  if (score >= 100) return 'text-red-400'
  if (score >= 50) return 'text-amber-400'
  if (score >= 10) return 'text-yellow-400'
  if (score > 0) return 'text-blue-400'
  return 'text-muted-foreground'
}

export default function WafIPs() {
  const [ips, setIPs] = useState<WafIPState[]>([])
  const [loading, setLoading] = useState(true)
  const [serviceDown, setServiceDown] = useState(false)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<IPFilter>('all')
  const [banOpen, setBanOpen] = useState(false)
  const [whitelistOpen, setWhitelistOpen] = useState(false)
  const [banForm, setBanForm] = useState({ ip: '', reason: 'manual_ban', duration: 60 })
  const [wlForm, setWlForm] = useState({ ip: '' })
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      setServiceDown(false)
      const data = await api.listWafIPs()
      setIPs(data.ips ?? [])
    } catch (err) {
      if (api.isServiceUnavailable(err)) {
        setServiceDown(true)
      } else {
        toast.error(err instanceof api.ApiError ? err.message : 'Failed to load IP states')
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleBan() {
    if (!banForm.ip) { toast.error('IP address required'); return }
    setSaving(true)
    try {
      await api.banIP(banForm.ip, banForm.reason, banForm.duration)
      toast.success(`${banForm.ip} banned`)
      setBanOpen(false)
      setBanForm({ ip: '', reason: 'manual_ban', duration: 60 })
      load()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Ban failed')
    } finally { setSaving(false) }
  }

  async function handleUnban(ip: string) {
    try {
      await api.unbanIP(ip)
      toast.success(`${ip} unbanned`)
      load()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Unban failed')
    }
  }

  async function handleWhitelist() {
    if (!wlForm.ip) { toast.error('IP address required'); return }
    setSaving(true)
    try {
      await api.whitelistIP(wlForm.ip)
      toast.success(`${wlForm.ip} whitelisted`)
      setWhitelistOpen(false)
      setWlForm({ ip: '' })
      load()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Whitelist failed')
    } finally { setSaving(false) }
  }

  async function handleRemoveWhitelist(ip: string) {
    try {
      await api.removeWhitelist(ip)
      toast.success(`${ip} removed from whitelist`)
      load()
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Remove failed')
    }
  }

  const filtered = ips.filter(ip => {
    if (filter === 'banned' && !ip.banned) return false
    if (filter === 'whitelisted' && !ip.whitelisted) return false
    if (filter === 'scored' && ip.cumulative_score <= 0) return false
    if (search && !ip.ip.includes(search)) return false
    return true
  })

  if (serviceDown) {
    return (
      <div className="p-6">
        <h1 className="text-xl font-bold text-foreground tracking-tight mb-6">IP Management</h1>
        <EmptyState
          variant="service-offline"
          title="muWAF Servisi Cevrimdisi"
          description="IP yonetimi icin muWAF servisinin calisiyor olmasi gerekiyor."
        />
      </div>
    )
  }

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">IP Management</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            {ips.filter(i => i.banned).length} banned, {ips.filter(i => i.whitelisted).length} whitelisted
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-2 cursor-pointer border-border"
            onClick={() => setWhitelistOpen(true)}
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            Whitelist IP
          </Button>
          <Button
            size="sm"
            className="gap-2 cursor-pointer bg-destructive hover:bg-destructive/90"
            onClick={() => setBanOpen(true)}
          >
            <Ban className="h-3.5 w-3.5" />
            Ban IP
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Search IP address..."
            className="pl-9 bg-card border-border h-9 font-mono"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <div className="flex gap-1">
          {([
            { value: 'all', label: 'All' },
            { value: 'banned', label: 'Banned' },
            { value: 'whitelisted', label: 'Whitelisted' },
            { value: 'scored', label: 'Scored' },
          ] as const).map(f => (
            <Button
              key={f.value}
              variant={filter === f.value ? 'default' : 'outline'}
              size="sm"
              className={cn('h-8 px-3 text-xs cursor-pointer border-border',
                f.value === 'banned' && filter !== f.value && 'text-red-400',
                f.value === 'whitelisted' && filter !== f.value && 'text-primary',
              )}
              onClick={() => setFilter(f.value)}
            >
              {f.label}
            </Button>
          ))}
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="space-y-1">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-12 w-full rounded-sm" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          title={search || filter !== 'all' ? 'No matching IPs' : 'No tracked IPs'}
          description="IP addresses will appear here when the WAF detects suspicious activity"
        />
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="bg-card hover:bg-card border-border">
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider">IP Address</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-28">Status</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-24 text-center">Score</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider">Reason</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-32">Last Seen</TableHead>
                <TableHead className="text-[10px] font-semibold uppercase tracking-wider w-28 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map(ip => {
                const status = ipStatusBadge(ip)
                const StatusIcon = status.icon
                return (
                  <TableRow key={ip.ip} className="border-border hover:bg-muted/10 transition-colors">
                    <TableCell className="font-mono text-sm text-foreground font-medium">
                      {ip.ip}
                    </TableCell>
                    <TableCell>
                      <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-medium', status.cls)}>
                        <StatusIcon className="h-3 w-3" />
                        {status.label}
                      </span>
                    </TableCell>
                    <TableCell className="text-center">
                      <span className={cn('font-mono text-sm font-bold', scoreColor(ip.cumulative_score))}>
                        {ip.cumulative_score.toFixed(1)}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground max-w-xs truncate">
                      {ip.ban_reason || '—'}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground font-mono">
                      {ip.last_seen ? relativeTime(ip.last_seen) : '—'}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        {ip.banned && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs cursor-pointer text-primary hover:text-primary"
                            onClick={() => handleUnban(ip.ip)}
                          >
                            Unban
                          </Button>
                        )}
                        {ip.whitelisted && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs cursor-pointer text-destructive hover:text-destructive"
                            onClick={() => handleRemoveWhitelist(ip.ip)}
                          >
                            Remove
                          </Button>
                        )}
                        {!ip.banned && !ip.whitelisted && (
                          <>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 text-xs cursor-pointer text-destructive hover:text-destructive"
                              onClick={() => { setBanForm({ ip: ip.ip, reason: 'manual_ban', duration: 60 }); setBanOpen(true) }}
                            >
                              Ban
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 text-xs cursor-pointer text-primary hover:text-primary"
                              onClick={async () => {
                                try {
                                  await api.whitelistIP(ip.ip)
                                  toast.success(`${ip.ip} whitelisted`)
                                  load()
                                } catch (err) {
                                  toast.error(err instanceof api.ApiError ? err.message : 'Failed')
                                }
                              }}
                            >
                              Whitelist
                            </Button>
                          </>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Ban Dialog */}
      <Dialog open={banOpen} onOpenChange={setBanOpen}>
        <DialogContent className="bg-card border-border sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-foreground">
              <Ban className="h-5 w-5 text-destructive" />
              Ban IP Address
            </DialogTitle>
            <DialogDescription>Block all requests from this IP</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">IP Address</Label>
              <Input
                className="bg-background border-border font-mono"
                placeholder="192.168.1.100"
                value={banForm.ip}
                onChange={e => setBanForm(f => ({ ...f, ip: e.target.value }))}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Reason</Label>
                <Input
                  className="bg-background border-border"
                  value={banForm.reason}
                  onChange={e => setBanForm(f => ({ ...f, reason: e.target.value }))}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Duration (min)</Label>
                <Input
                  type="number"
                  min={1}
                  className="bg-background border-border font-mono"
                  value={banForm.duration}
                  onChange={e => setBanForm(f => ({ ...f, duration: Number(e.target.value) }))}
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" className="cursor-pointer border-border" onClick={() => setBanOpen(false)}>Cancel</Button>
              <Button className="cursor-pointer gap-2 bg-destructive hover:bg-destructive/90" onClick={handleBan} disabled={saving}>
                <Ban className="h-3.5 w-3.5" /> Ban
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Whitelist Dialog */}
      <Dialog open={whitelistOpen} onOpenChange={setWhitelistOpen}>
        <DialogContent className="bg-card border-border sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-foreground">
              <ShieldCheck className="h-5 w-5 text-primary" />
              Whitelist IP Address
            </DialogTitle>
            <DialogDescription>Exempt this IP from WAF inspection</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">IP Address</Label>
              <Input
                className="bg-background border-border font-mono"
                placeholder="10.0.0.1"
                value={wlForm.ip}
                onChange={e => setWlForm({ ip: e.target.value })}
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" className="cursor-pointer border-border" onClick={() => setWhitelistOpen(false)}>Cancel</Button>
              <Button className="cursor-pointer gap-2" onClick={handleWhitelist} disabled={saving}>
                <ShieldCheck className="h-3.5 w-3.5" /> Whitelist
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
