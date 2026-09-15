import { useState, useEffect, useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  RefreshCw, ChevronLeft, ChevronRight, Check, Bell, BellOff,
  Radio, Eye, User, BellRing, ExternalLink, FlaskConical,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent } from '@/components/ui/card'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle,
} from '@/components/ui/sheet'
import { cn, formatNumber } from '@/lib/utils'
import { DELIVERY_LABELS, SEVERITIES, SEVERITY_LABELS, formatDateTime as formatTime } from '@/lib/alerts'
import { EmptyState } from '@/components/EmptyState'
import { SeverityBadge } from '@/components/SeverityBadge'
import * as api from '@/api'
import type {
  Alert, AlertDetail, AlertDeliveryRecord, AlertProjectChannels, AlertRule, AlertStats,
} from '@/types'

const PAGE_SIZE = 50

const DELIVERY_KIND_LABELS: Record<AlertDeliveryRecord['kind'], string> = {
  opened: 'Açılış',
  escalated: 'Önem yükseldi',
  reminder: 'Hatırlatma',
  digest: 'Günlük özet',
  test: 'Test',
}

const DELIVERY_STATUS: Record<AlertDeliveryRecord['status'], { label: string; tone: string }> = {
  pending: { label: 'Bekliyor', tone: 'text-yellow-400 border-yellow-400/40' },
  sent: { label: 'Gönderildi', tone: 'text-emerald-400 border-emerald-400/40' },
  failed: { label: 'Başarısız', tone: 'text-red-400 border-red-400/40' },
  skipped: { label: 'Atlandı', tone: 'text-muted-foreground' },
}

function StatCard({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <Card className="border-border bg-card">
      <CardContent className="p-4">
        <p className="text-xs text-muted-foreground font-medium">{label}</p>
        <p className={cn('text-2xl font-bold font-mono mt-1', tone ?? 'text-foreground')}>{value}</p>
      </CardContent>
    </Card>
  )
}

export default function Alerts() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState<AlertStats | null>(null)
  const [rules, setRules] = useState<AlertRule[]>([])
  const [projects, setProjects] = useState<AlertProjectChannels[]>([])

  const [source, setSource] = useState('')
  const [ruleFilter, setRuleFilter] = useState('all')
  const [projectFilter, setProjectFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [showAcked, setShowAcked] = useState(false)

  const openId = searchParams.get('id') ?? ''

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: api.AlertSearchParams = { limit: PAGE_SIZE, offset }
      if (ruleFilter !== 'all') params.rule_id = ruleFilter
      if (projectFilter !== 'all') params.project = projectFilter
      if (severityFilter !== 'all') params.severity = severityFilter
      if (!showAcked) params.acknowledged = false
      const s = source.trim()
      if (s) {
        if (/^[\d.:a-fA-F]+$/.test(s) && /[.:]/.test(s)) params.source_ip = s
        else params.host = s
      }
      const res = await api.searchAlerts(params)
      setAlerts(res.data ?? [])
      setTotal(res.total ?? 0)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Alarmlar yüklenemedi')
    } finally {
      setLoading(false)
    }
  }, [offset, ruleFilter, projectFilter, severityFilter, showAcked, source])

  const loadStats = useCallback(async () => {
    try {
      setStats(await api.getAlertStats())
    } catch {
      /* the counters are a convenience; the list still works without them */
    }
  }, [])

  useEffect(() => {
    void (async () => {
      try {
        const [r, p] = await Promise.all([api.listAlertRules(), api.listAlertProjects()])
        setRules(r)
        setProjects(p)
      } catch {
        /* filters fall back to showing every alert */
      }
    })()
  }, [])

  useEffect(() => {
    const t = setTimeout(() => { void load() }, 250)
    return () => clearTimeout(t)
  }, [load])
  useEffect(() => { void loadStats() }, [loadStats, alerts.length])

  function openDetail(id: string) {
    const next = new URLSearchParams(searchParams)
    next.set('id', id)
    setSearchParams(next, { replace: true })
  }

  function closeDetail() {
    const next = new URLSearchParams(searchParams)
    next.delete('id')
    setSearchParams(next, { replace: true })
  }

  async function handleAck(id: string) {
    try {
      const updated = await api.acknowledgeAlert(id)
      setAlerts(list => (showAcked ? list.map(x => (x.id === id ? updated : x)) : list.filter(x => x.id !== id)))
      void loadStats()
      toast.success('Alarm onaylandı')
      return updated
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Onaylanamadı')
      return null
    }
  }

  const canPrev = offset > 0
  const canNext = offset + PAGE_SIZE < total

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground tracking-tight flex items-center gap-2">
            <Bell className="h-6 w-6 text-primary" />
            Alarmlar
          </h1>
          <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
            Web kurallarından ve uygulama olay kurallarından doğan alarmlar. Bir alarm onaylanana kadar açık
            kalır, aynı olay tekrar ettikçe sayısı artar ve yeniden bildirilmez.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" asChild>
            <Link to="/alert-rules"><BellRing className="h-4 w-4 mr-2" />Kurallar</Link>
          </Button>
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
            Yenile
          </Button>
        </div>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard label="Açık" value={formatNumber(stats.total_open)} tone={stats.total_open > 0 ? 'text-red-400' : 'text-emerald-400'} />
          <StatCard label="Kritik açık" value={formatNumber(stats.by_severity?.critical ?? 0)} tone="text-red-400" />
          <StatCard label="Yüksek açık" value={formatNumber(stats.by_severity?.high ?? 0)} tone="text-orange-400" />
          <StatCard label="Uyarı açık" value={formatNumber(stats.by_severity?.warning ?? 0)} tone="text-yellow-400" />
        </div>
      )}

      <Card className="border-border bg-card">
        <CardContent className="p-4 flex flex-col lg:flex-row gap-3 flex-wrap">
          <Input
            placeholder="Host veya IP"
            value={source}
            onChange={e => { setOffset(0); setSource(e.target.value) }}
            className="lg:w-56 bg-background border-border"
          />
          <Select value={projectFilter} onValueChange={v => { setOffset(0); setProjectFilter(v) }}>
            <SelectTrigger className="lg:w-48 bg-background border-border cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tüm projeler</SelectItem>
              {projects.map(p => <SelectItem key={p.project} value={p.project}>{p.name}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={ruleFilter} onValueChange={v => { setOffset(0); setRuleFilter(v) }}>
            <SelectTrigger className="lg:w-64 bg-background border-border cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tüm kurallar</SelectItem>
              {rules.map(r => <SelectItem key={r.id} value={r.id}>{r.project ? `${r.project}: ${r.name}` : r.name}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={severityFilter} onValueChange={v => { setOffset(0); setSeverityFilter(v) }}>
            <SelectTrigger className="lg:w-40 bg-background border-border cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tüm önemler</SelectItem>
              {[...SEVERITIES].reverse().map(s => <SelectItem key={s} value={s}>{SEVERITY_LABELS[s]}</SelectItem>)}
            </SelectContent>
          </Select>
          <Button
            variant={showAcked ? 'default' : 'outline'}
            size="sm"
            onClick={() => { setOffset(0); setShowAcked(v => !v) }}
            className="cursor-pointer"
          >
            {showAcked ? <BellOff className="h-4 w-4 mr-2" /> : <Bell className="h-4 w-4 mr-2" />}
            {showAcked ? 'Onaylananlar dahil' : 'Yalnız açık alarmlar'}
          </Button>
        </CardContent>
      </Card>

      <Card className="border-border bg-card">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-border">
                  <TableHead className="text-xs w-[150px]">Son görülme</TableHead>
                  <TableHead className="text-xs w-[100px]">Önem</TableHead>
                  <TableHead className="text-xs">Alarm</TableHead>
                  <TableHead className="text-xs w-[160px]">Proje</TableHead>
                  <TableHead className="text-xs w-[180px]">Kaynak</TableHead>
                  <TableHead className="text-xs w-[70px] text-right">Tekrar</TableHead>
                  <TableHead className="text-xs w-[100px] text-right">İşlem</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && alerts.length === 0 && Array.from({ length: 6 }).map((_, i) => (
                  <TableRow key={i} className="border-border">
                    {Array.from({ length: 7 }).map((__, j) => (
                      <TableCell key={j}><Skeleton className="h-4 w-full" /></TableCell>
                    ))}
                  </TableRow>
                ))}
                {!loading && alerts.length === 0 && (
                  <TableRow className="border-border"><TableCell colSpan={7}>
                    <EmptyState
                      icon={Radio}
                      title="Eşleşen alarm yok"
                      description="Filtreleri genişletin ya da onaylanmış alarmları da gösterin."
                    />
                  </TableCell></TableRow>
                )}
                {alerts.map(a => (
                  <TableRow
                    key={a.id}
                    className={cn('border-border cursor-pointer', a.acknowledged && 'opacity-60')}
                    onClick={() => openDetail(a.id)}
                  >
                    <TableCell className="text-xs text-muted-foreground font-mono">{formatTime(a.last_seen_at)}</TableCell>
                    <TableCell><SeverityBadge severity={a.severity} /></TableCell>
                    <TableCell className="text-sm">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{a.title}</span>
                        {a.is_test && (
                          <Badge variant="outline" className="gap-1 text-[10px] text-sky-400 border-sky-400/40">
                            <FlaskConical className="h-3 w-3" />TEST
                          </Badge>
                        )}
                      </div>
                      {(a.group_key || a.rule_name !== a.title) && (
                        <div className="text-xs text-muted-foreground mt-0.5">
                          {a.rule_name !== a.title && <span>{a.rule_name}</span>}
                          {a.group_key && <span className="font-mono ml-2">{a.group_key}</span>}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">
                      {a.project ? (
                        <span className="font-mono">{a.project}{a.component ? ` / ${a.component}` : ''}</span>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-xs font-mono text-muted-foreground">
                      {a.host && <div>{a.host}</div>}
                      {a.source_ip && <div>{a.source_ip}</div>}
                    </TableCell>
                    <TableCell className="text-right text-sm font-mono">
                      {a.occurrences > 1 ? (
                        <Badge variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/20">
                          ×{a.occurrences}
                        </Badge>
                      ) : '1'}
                    </TableCell>
                    <TableCell className="text-right" onClick={e => e.stopPropagation()}>
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer" onClick={() => openDetail(a.id)} title="Ayrıntı">
                          <Eye className="h-3.5 w-3.5" />
                        </Button>
                        {!a.acknowledged && (
                          <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer hover:text-emerald-400" onClick={() => void handleAck(a.id)} title="Onayla">
                            <Check className="h-3.5 w-3.5" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {total > PAGE_SIZE && (
            <div className="flex items-center justify-between p-4 border-t border-border text-xs text-muted-foreground">
              <span>{offset + 1} ile {Math.min(offset + PAGE_SIZE, total)} arası, toplam {formatNumber(total)}</span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setOffset(o => Math.max(0, o - PAGE_SIZE))} disabled={!canPrev || loading}>
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="sm" onClick={() => setOffset(o => o + PAGE_SIZE)} disabled={!canNext || loading}>
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <AlertDetailSheet
        alertId={openId}
        onClose={closeDetail}
        onAck={handleAck}
      />
    </div>
  )
}

function AlertDetailSheet({
  alertId, onClose, onAck,
}: {
  alertId: string
  onClose: () => void
  onAck: (id: string) => Promise<Alert | null>
}) {
  const [detail, setDetail] = useState<AlertDetail | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    if (!alertId) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const fetchOnce = async () => {
      try {
        const d = await api.getAlert(alertId)
        if (cancelled) return
        setDetail(d)
        setFailed(false)
        // While a notification is still on its way, keep the outcome current.
        if (d.deliveries.some(x => x.status === 'pending')) timer = setTimeout(() => { void fetchOnce() }, 4000)
      } catch {
        if (!cancelled) setFailed(true)
      }
    }
    void fetchOnce()
    return () => { cancelled = true; if (timer) clearTimeout(timer) }
  }, [alertId])

  const open = Boolean(alertId)
  const current = detail && detail.id === alertId ? detail : null

  return (
    <Sheet open={open} onOpenChange={v => !v && onClose()}>
      <SheetContent className="bg-card border-border w-full sm:max-w-2xl overflow-y-auto">
        {!current ? (
          <div className="p-6 text-sm text-muted-foreground">
            {failed ? 'Alarm bulunamadı.' : 'Yükleniyor…'}
          </div>
        ) : (
          <>
            <SheetHeader className="space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <SeverityBadge severity={current.severity} />
                <Badge variant="outline" className="text-xs">{current.rule_name}</Badge>
                {current.is_test && <Badge variant="outline" className="text-xs text-sky-400 border-sky-400/40">TEST</Badge>}
              </div>
              <SheetTitle className="text-lg">{current.title}</SheetTitle>
              <SheetDescription>
                İlk görülme {formatTime(current.first_seen_at)}, son görülme {formatTime(current.last_seen_at)}, {current.occurrences} kez
              </SheetDescription>
            </SheetHeader>

            <div className="space-y-5 p-4">
              <div className="space-y-2">
                {current.project && <DetailRow label="Proje" value={current.component ? `${current.project} / ${current.component}` : current.project} mono />}
                {current.group_key && <DetailRow label="Grup" value={current.group_key} mono />}
                {current.host && <DetailRow label="Host" value={current.host} mono />}
                {current.source_ip && <DetailRow label="IP" value={current.source_ip} mono />}
                <AlertActorRow alert={current} />
                <DetailRow label="Teslim" value={DELIVERY_LABELS[current.delivery]} />
                {current.next_reminder_at && !current.acknowledged && (
                  <DetailRow label="Sonraki hatırlatma" value={formatTime(current.next_reminder_at)} />
                )}
                {current.acknowledged ? (
                  <DetailRow label="Onay" value={`${current.acknowledged_by || 'bilinmiyor'}, ${formatTime(current.acknowledged_at)}`} />
                ) : (
                  <Button
                    className="w-full cursor-pointer"
                    onClick={async () => {
                      const updated = await onAck(current.id)
                      if (updated) setDetail({ ...current, ...updated })
                    }}
                  >
                    <Check className="h-4 w-4 mr-2" />
                    Onayla
                  </Button>
                )}
              </div>

              <section>
                <h3 className="text-xs font-medium text-muted-foreground mb-2">Bildirimler</h3>
                {current.deliveries.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    Bu alarm için bildirim yok. Kural bir kanala bağlı değilse ya da teslim modu günlük özet veya yalnız kayıt ise böyledir.
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {current.deliveries.map(d => (
                      <div key={d.id} className="rounded-md border border-border px-3 py-2 text-xs">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium">{d.channel_name}</span>
                          <Badge variant="outline" className="text-[10px]">{DELIVERY_KIND_LABELS[d.kind]}</Badge>
                          <Badge variant="outline" className={cn('text-[10px]', DELIVERY_STATUS[d.status].tone)}>
                            {DELIVERY_STATUS[d.status].label}
                          </Badge>
                          <span className="ml-auto text-muted-foreground font-mono">{formatTime(d.sent_at ?? d.created_at)}</span>
                        </div>
                        {d.last_error && (
                          <p className="mt-1 text-muted-foreground break-words">
                            {d.attempts} deneme. Son hata: <span className="font-mono">{d.last_error}</span>
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </section>

              {current.evidence.length > 0 && (
                <section>
                  <h3 className="text-xs font-medium text-muted-foreground mb-2">
                    Alarmın doğduğu log satırları
                  </h3>
                  <div className="space-y-2">
                    {current.evidence.map(ev => (
                      <div key={ev.log_id} className="rounded-md border border-border bg-muted/20 p-2 text-xs">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-muted-foreground">{formatTime(ev.log_timestamp)}</span>
                          {ev.component && <Badge variant="outline" className="text-[10px]">{ev.component}</Badge>}
                          {Object.entries(ev.fields ?? {}).map(([k, v]) => (
                            <Badge key={k} variant="outline" className="text-[10px] font-mono">{k}={v}</Badge>
                          ))}
                          <Link
                            to={`/container-logs?tab=history&container_id=${encodeURIComponent(ev.container_id)}&focus=${encodeURIComponent(ev.log_id)}`}
                            className="ml-auto inline-flex items-center gap-1 text-primary hover:underline"
                          >
                            Satırı aç <ExternalLink className="h-3 w-3" />
                          </Link>
                        </div>
                        <pre className="mt-1.5 whitespace-pre-wrap break-all font-mono text-[11px]">{ev.line}</pre>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {current.detail && Object.keys(current.detail).length > 0 && (
                <section>
                  <h3 className="text-xs font-medium text-muted-foreground mb-2">Ayrıntı</h3>
                  <pre className="text-xs bg-muted/40 border border-border rounded-md p-3 overflow-x-auto font-mono">
                    {JSON.stringify(current.detail, null, 2)}
                  </pre>
                </section>
              )}
              <DetailRow label="Parmak izi" value={current.fingerprint} mono />
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}

// resolveActor reads the identity the web rules attach to their alerts.
function resolveActor(alert: Alert): string | null {
  const d = (alert.detail ?? {}) as Record<string, unknown>
  for (const key of ['actor_email', 'actor_name', 'actor_sub']) {
    const v = d[key]
    if (typeof v === 'string' && v !== '') return v
  }
  const match = alert.fingerprint.match(/^[^:]+:user:(.+)$/)
  return match ? match[1] : null
}

function AlertActorRow({ alert }: { alert: Alert }) {
  const actor = resolveActor(alert)
  if (!actor) return null
  const verified = (alert.detail as Record<string, unknown> | undefined)?.['actor_verified']
  return (
    <div className="flex justify-between gap-4 text-sm border-b border-border pb-2 items-start">
      <span className="text-muted-foreground">Kullanıcı</span>
      <div className="text-right break-all flex flex-col items-end gap-1">
        <Link
          to={`/logs?user=${encodeURIComponent(actor)}`}
          className="text-primary hover:underline font-mono text-xs inline-flex items-center gap-1"
          title="Bu kullanıcının bütün isteklerini göster"
        >
          <User className="h-3 w-3" />
          {actor}
        </Link>
        {verified === false && (
          <Badge variant="outline" className="text-[10px] bg-amber-500/10 text-amber-400 border-amber-500/30">
            imza doğrulanmadı
          </Badge>
        )}
      </div>
    </div>
  )
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4 text-sm border-b border-border pb-2">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn('text-right text-foreground break-all', mono && 'font-mono text-xs')}>{value}</span>
    </div>
  )
}
