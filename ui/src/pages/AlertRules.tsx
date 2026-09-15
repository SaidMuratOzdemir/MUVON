import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  BellRing, Plus, RefreshCw, Trash2, Pencil, Send, Lock, Mail, MessageSquare, Search, X, Loader2, Zap,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { EmptyState } from '@/components/EmptyState'
import { SeverityBadge } from '@/components/SeverityBadge'
import { cn } from '@/lib/utils'
import { DELIVERY_LABELS, SEVERITIES, SEVERITY_LABELS, describeTrigger } from '@/lib/alerts'
import * as api from '@/api'
import type {
  AlertChannel, AlertDeliveryMode, AlertFieldCondition, AlertProjectChannels, AlertRule, AlertSeverity,
  AlertTrigger, DeployProjectSummary, ProjectEvent,
} from '@/types'

type TabKey = 'rules' | 'channels' | 'projects'

const OP_LABELS: Record<AlertFieldCondition['op'], string> = {
  eq: 'eşittir',
  ne: 'eşit değildir',
  in: 'şunlardan biri',
  not_in: 'şunlardan biri değil',
  exists: 'alan var',
}

const TRIGGER_LABELS: Record<AlertTrigger['type'], string> = {
  each: 'Her olayda',
  count: 'Pencerede N olay',
  distinct: 'Pencerede N farklı değer',
  baseline: 'Geçmiş ortalamaya göre artış',
}

const ALL = '__all__'

const splitList = (s: string) => s.split(',').map(x => x.trim()).filter(Boolean)

function errorText(err: unknown, fallback: string): string {
  return err instanceof api.ApiError ? err.message : fallback
}

// ── Rule draft ──────────────────────────────────────────────────────────
// The editor works on strings so a half-typed number or list is not lost
// while the operator is typing; conversion happens once, on save.

interface ConditionDraft { key: string; op: AlertFieldCondition['op']; values: string }
interface ClauseDraft { events: string; fields: ConditionDraft[] }
interface TierDraft {
  severity: AlertSeverity
  type: AlertTrigger['type']
  count: string
  windowMinutes: string
  field: string
  ratio: string
  baselineDays: string
}
interface RuleDraft {
  id?: string
  name: string
  description: string
  enabled: boolean
  project: string
  component: string
  clauses: ClauseDraft[]
  groupBy: string
  tiers: TierDraft[]
  notifyFields: string
  delivery: AlertDeliveryMode
  remindMinutes: string
  channelIds: string[]
}

function emptyTier(severity: AlertSeverity = 'critical'): TierDraft {
  return { severity, type: 'each', count: '3', windowMinutes: '60', field: '', ratio: '3', baselineDays: '7' }
}

function newRuleDraft(project: string): RuleDraft {
  return {
    name: '', description: '', enabled: true, project, component: '',
    clauses: [{ events: '', fields: [] }], groupBy: '', tiers: [emptyTier()],
    notifyFields: '', delivery: 'instant', remindMinutes: '240', channelIds: [],
  }
}

function ruleToDraft(r: AlertRule): RuleDraft {
  const clauses = r.match.any.length > 0 ? r.match.any : [{ events: [], fields: [] }]
  return {
    id: r.id,
    name: r.name,
    description: r.description,
    enabled: r.enabled,
    project: r.project ?? '',
    component: r.component,
    clauses: clauses.map(c => ({
      events: c.events.join(', '),
      fields: c.fields.map(f => ({ key: f.key, op: f.op, values: f.values.join(', ') })),
    })),
    groupBy: r.group_by,
    tiers: r.tiers.map(t => ({
      severity: t.severity,
      type: t.trigger.type,
      count: String(t.trigger.count ?? 3),
      windowMinutes: String(Math.round((t.trigger.window_seconds ?? 3600) / 60)),
      field: t.trigger.field ?? '',
      ratio: String(t.trigger.ratio ?? 3),
      baselineDays: String(t.trigger.baseline_days ?? 7),
    })),
    notifyFields: r.notify_fields.join(', '),
    delivery: r.delivery,
    remindMinutes: String(r.remind_minutes),
    channelIds: r.channel_ids,
  }
}

function tierTrigger(t: TierDraft): AlertTrigger {
  const window = Number(t.windowMinutes) * 60
  if (t.type === 'count') return { type: 'count', count: Number(t.count), window_seconds: window }
  if (t.type === 'distinct') return { type: 'distinct', field: t.field.trim(), count: Number(t.count), window_seconds: window }
  if (t.type === 'baseline') {
    return { type: 'baseline', ratio: Number(t.ratio), baseline_days: Number(t.baselineDays), count: Number(t.count) }
  }
  return { type: 'each' }
}

function draftToInput(d: RuleDraft): api.AlertRuleInput {
  return {
    name: d.name.trim(),
    description: d.description.trim(),
    enabled: d.enabled,
    project: d.project,
    component: d.component,
    match: {
      any: d.clauses.map(c => ({
        events: splitList(c.events),
        fields: c.fields.map(f => ({
          key: f.key.trim(),
          op: f.op,
          values: f.op === 'exists' ? [] : f.op === 'eq' || f.op === 'ne' ? [f.values.trim()] : splitList(f.values),
        })),
      })),
    },
    group_by: d.groupBy.trim(),
    tiers: d.tiers.map(t => ({ severity: t.severity, trigger: tierTrigger(t) })),
    notify_fields: splitList(d.notifyFields),
    delivery: d.delivery,
    remind_minutes: d.delivery === 'instant' ? Number(d.remindMinutes) || 0 : 0,
    channel_ids: d.channelIds,
  }
}

function ruleToInput(r: AlertRule): api.AlertRuleInput {
  return {
    name: r.name, description: r.description, enabled: r.enabled, project: r.project ?? '',
    component: r.component, match: r.match, group_by: r.group_by, tiers: r.tiers,
    notify_fields: r.notify_fields, delivery: r.delivery, remind_minutes: r.remind_minutes, channel_ids: r.channel_ids,
  }
}

// ── Page ────────────────────────────────────────────────────────────────

export default function AlertRules() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') ?? 'rules') as TabKey
  const setTab = (v: string) => {
    const next = new URLSearchParams(params)
    next.set('tab', v)
    setParams(next, { replace: true })
  }

  const [rules, setRules] = useState<AlertRule[]>([])
  const [channels, setChannels] = useState<AlertChannel[]>([])
  const [projects, setProjects] = useState<DeployProjectSummary[]>([])
  const [defaults, setDefaults] = useState<AlertProjectChannels[]>([])
  const [loading, setLoading] = useState(true)

  const [ruleDraft, setRuleDraft] = useState<RuleDraft | null>(null)
  const [builtinEditing, setBuiltinEditing] = useState<AlertRule | null>(null)
  const [channelEditing, setChannelEditing] = useState<AlertChannel | 'new' | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [r, c, p, d] = await Promise.all([
        api.listAlertRules(), api.listAlertChannels(), api.listDeployProjects(), api.listAlertProjects(),
      ])
      setRules(r)
      setChannels(c)
      setProjects(p ?? [])
      setDefaults(d)
    } catch (err) {
      toast.error(errorText(err, 'Alarm kuralları yüklenemedi'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const channelNames = useMemo(() => new Map(channels.map(c => [c.id, c.name])), [channels])
  const defaultsByProject = useMemo(() => new Map(defaults.map(d => [d.project, d.channel_ids])), [defaults])
  const eventRules = rules.filter(r => r.kind === 'event')
  const builtinRules = rules.filter(r => r.kind === 'builtin')

  function routeSummary(r: AlertRule): { text: string; warn: boolean } {
    if (r.delivery === 'none') return { text: 'Yalnız kayıt', warn: false }
    let ids = r.channel_ids
    let suffix = ''
    if (ids.length === 0 && r.kind === 'event') {
      ids = defaultsByProject.get(r.project ?? '') ?? []
      suffix = ' (proje varsayılanı)'
    }
    if (ids.length === 0) return { text: 'Kanal yok, bildirim gitmez', warn: true }
    const names = ids.map(id => channelNames.get(id) ?? 'silinmiş kanal').join(', ')
    return { text: `${DELIVERY_LABELS[r.delivery]}: ${names}${suffix}`, warn: false }
  }

  async function runRuleTest(rule: AlertRule) {
    try {
      const res = await api.testAlertRule(rule.id)
      toast.success(`Test alarmı açıldı. ${res.channels.join(', ')} kanalına birkaç saniye içinde gönderilecek.`, {
        action: { label: 'Alarmı aç', onClick: () => navigate(`/alerts?id=${res.alert_id}`) },
      })
    } catch (err) {
      toast.error(errorText(err, 'Test başlatılamadı'))
    }
  }

  async function toggleRule(rule: AlertRule, enabled: boolean) {
    try {
      const updated = rule.kind === 'builtin'
        ? await api.updateAlertRule(rule.id, {
          enabled, delivery: rule.delivery, remind_minutes: rule.remind_minutes, channel_ids: rule.channel_ids,
        })
        : await api.updateAlertRule(rule.id, { ...ruleToInput(rule), enabled })
      setRules(list => list.map(r => (r.id === rule.id ? updated : r)))
      toast.success(enabled ? 'Kural açıldı' : 'Kural kapatıldı')
    } catch (err) {
      toast.error(errorText(err, 'Değiştirilemedi'))
    }
  }

  async function removeRule(rule: AlertRule) {
    if (!confirm(`"${rule.name}" kuralı silinecek. Açık alarmları kalır. Devam edilsin mi?`)) return
    try {
      await api.deleteAlertRule(rule.id)
      setRules(list => list.filter(r => r.id !== rule.id))
      toast.success('Kural silindi')
    } catch (err) {
      toast.error(errorText(err, 'Silinemedi'))
    }
  }

  async function testChannel(c: AlertChannel) {
    const pending = toast.loading(`${c.name} kanalına test gönderiliyor`)
    try {
      await api.testAlertChannel(c.id)
      toast.success(`${c.name} kanalına test bildirimi gönderildi`, { id: pending })
    } catch (err) {
      toast.error(`${c.name}: ${errorText(err, 'gönderilemedi')}`, { id: pending })
    }
  }

  async function toggleChannel(c: AlertChannel, enabled: boolean) {
    try {
      const updated = await api.updateAlertChannel(c.id, {
        name: c.name, enabled, email_to: c.email_to, digest_hour: c.digest_hour, digest_timezone: c.digest_timezone,
      })
      setChannels(list => list.map(x => (x.id === c.id ? updated : x)))
    } catch (err) {
      toast.error(errorText(err, 'Değiştirilemedi'))
    }
  }

  async function removeChannel(c: AlertChannel) {
    if (!confirm(`"${c.name}" kanalı silinecek ve ona bağlı bütün kurallardan çıkarılacak. Devam edilsin mi?`)) return
    try {
      await api.deleteAlertChannel(c.id)
      toast.success('Kanal silindi')
      await load()
    } catch (err) {
      toast.error(errorText(err, 'Silinemedi'))
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <BellRing className="h-6 w-6 text-primary" />
            Alarm Kuralları
          </h1>
          <p className="text-sm text-muted-foreground mt-1 max-w-3xl">
            Uygulamaların loglarına yazdığı olaylardan ve web trafiğinden alarm üreten kurallar, bildirimlerin
            gideceği kanallar ve projelerin varsayılan kanalları.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          <RefreshCw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
          Yenile
        </Button>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="rules">Kurallar</TabsTrigger>
          <TabsTrigger value="channels">Kanallar</TabsTrigger>
          <TabsTrigger value="projects">Proje varsayılanları</TabsTrigger>
        </TabsList>

        <TabsContent value="rules" className="mt-4 space-y-6">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <CardTitle className="text-base">Uygulama olay kuralları</CardTitle>
                  <p className="text-sm text-muted-foreground mt-1">
                    Uygulama loga <code className="font-mono text-xs">event.name</code> alanı olan bir JSON satırı
                    yazdığında eşleşir. Kural bir projeye aittir.
                  </p>
                </div>
                <Button
                  size="sm"
                  onClick={() => setRuleDraft(newRuleDraft(projects[0]?.project.slug ?? ''))}
                  disabled={projects.length === 0}
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Yeni kural
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {loading ? (
                <Skeleton className="h-32 w-full" />
              ) : eventRules.length === 0 ? (
                <EmptyState
                  icon={Zap}
                  title="Henüz olay kuralı yok"
                  description="Bir projenin loglarındaki olaylardan alarm üretmek için yeni kural ekleyin."
                />
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-16">Açık</TableHead>
                        <TableHead>Kural</TableHead>
                        <TableHead>Proje</TableHead>
                        <TableHead>Kademeler</TableHead>
                        <TableHead>Bildirim</TableHead>
                        <TableHead className="w-32" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {eventRules.map(r => {
                        const route = routeSummary(r)
                        const events = Array.from(new Set(r.match.any.flatMap(c => c.events)))
                        return (
                          <TableRow key={r.id} className={cn(!r.enabled && 'opacity-50')}>
                            <TableCell>
                              <Switch checked={r.enabled} onCheckedChange={v => void toggleRule(r, v)} />
                            </TableCell>
                            <TableCell>
                              <div className="font-medium text-sm">{r.name}</div>
                              <div className="text-xs text-muted-foreground font-mono mt-0.5 break-all">
                                {events.join(', ')}
                                {r.group_by && <span className="font-sans">, {r.group_by} bazında</span>}
                              </div>
                            </TableCell>
                            <TableCell className="text-xs font-mono">
                              {r.project}{r.component ? ` / ${r.component}` : ''}
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-col gap-1">
                                {r.tiers.map((t, i) => (
                                  <div key={i} className="flex items-center gap-2 text-xs">
                                    <SeverityBadge severity={t.severity} />
                                    <span className="text-muted-foreground">{describeTrigger(t.trigger)}</span>
                                  </div>
                                ))}
                              </div>
                            </TableCell>
                            <TableCell className={cn('text-xs', route.warn ? 'text-yellow-400' : 'text-muted-foreground')}>
                              {route.text}
                            </TableCell>
                            <TableCell className="text-right whitespace-nowrap">
                              <Button variant="ghost" size="icon" className="h-8 w-8" title="Bir kez tetikle" onClick={() => void runRuleTest(r)}>
                                <Send className="h-3.5 w-3.5" />
                              </Button>
                              <Button variant="ghost" size="icon" className="h-8 w-8" title="Düzenle" onClick={() => setRuleDraft(ruleToDraft(r))}>
                                <Pencil className="h-3.5 w-3.5" />
                              </Button>
                              <Button variant="ghost" size="icon" className="h-8 w-8" title="Sil" onClick={() => void removeRule(r)}>
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            </TableCell>
                          </TableRow>
                        )
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Yerleşik web kuralları</CardTitle>
              <p className="text-sm text-muted-foreground mt-1">
                HTTP trafiğinden ve sertifikalardan alarm üreten, ürünle gelen kurallar. Eşikleri Ayarlar
                sayfasından değişir; burada yalnız açık olup olmadıkları ve nereye bildirdikleri seçilir.
                Bir kanala bağlanana kadar yalnız Alarmlar sayfasına kaydedilirler.
              </p>
            </CardHeader>
            <CardContent>
              {loading ? (
                <Skeleton className="h-32 w-full" />
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-16">Açık</TableHead>
                        <TableHead>Kural</TableHead>
                        <TableHead>Bildirim</TableHead>
                        <TableHead className="w-24" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {builtinRules.map(r => {
                        const route = routeSummary(r)
                        return (
                          <TableRow key={r.id} className={cn(!r.enabled && 'opacity-50')}>
                            <TableCell>
                              <Switch checked={r.enabled} onCheckedChange={v => void toggleRule(r, v)} />
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-2 text-sm font-medium">
                                {r.name}
                                <Lock className="h-3 w-3 text-muted-foreground" />
                              </div>
                              <div className="text-xs text-muted-foreground mt-0.5">{r.description}</div>
                            </TableCell>
                            <TableCell className={cn('text-xs', route.warn ? 'text-yellow-400' : 'text-muted-foreground')}>
                              {route.text}
                              {r.delivery === 'instant' && r.remind_minutes > 0 && (
                                <div>kritikse {r.remind_minutes} dakikada bir hatırlatır</div>
                              )}
                            </TableCell>
                            <TableCell className="text-right whitespace-nowrap">
                              <Button variant="ghost" size="icon" className="h-8 w-8" title="Bir kez tetikle" onClick={() => void runRuleTest(r)}>
                                <Send className="h-3.5 w-3.5" />
                              </Button>
                              <Button variant="ghost" size="icon" className="h-8 w-8" title="Bildirimi düzenle" onClick={() => setBuiltinEditing(r)}>
                                <Pencil className="h-3.5 w-3.5" />
                              </Button>
                            </TableCell>
                          </TableRow>
                        )
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="channels" className="mt-4">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <CardTitle className="text-base">Kanallar</CardTitle>
                  <p className="text-sm text-muted-foreground mt-1">
                    E-posta kanalları Ayarlar sayfasındaki SMTP gönderim hesabını kullanır. Günlük özet, kanalın
                    saatinde ve saat diliminde gönderilir.
                  </p>
                </div>
                <Button size="sm" onClick={() => setChannelEditing('new')}>
                  <Plus className="h-4 w-4 mr-2" />
                  Yeni kanal
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {loading ? (
                <Skeleton className="h-24 w-full" />
              ) : channels.length === 0 ? (
                <EmptyState
                  icon={MessageSquare}
                  title="Kanal yok"
                  description="Bildirim gönderebilmek için bir Slack veya e-posta kanalı ekleyin."
                />
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-16">Açık</TableHead>
                        <TableHead>Ad</TableHead>
                        <TableHead>Hedef</TableHead>
                        <TableHead>Günlük özet</TableHead>
                        <TableHead className="w-40" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {channels.map(c => (
                        <TableRow key={c.id} className={cn(!c.enabled && 'opacity-50')}>
                          <TableCell>
                            <Switch checked={c.enabled} onCheckedChange={v => void toggleChannel(c, v)} />
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2 text-sm font-medium">
                              {c.kind === 'slack' ? <MessageSquare className="h-3.5 w-3.5" /> : <Mail className="h-3.5 w-3.5" />}
                              {c.name}
                            </div>
                          </TableCell>
                          <TableCell className="text-xs font-mono text-muted-foreground">
                            {c.kind === 'slack' ? (c.webhook_host ?? 'webhook tanımlı') : c.email_to.join(', ')}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {String(c.digest_hour).padStart(2, '0')}:00 {c.digest_timezone}
                          </TableCell>
                          <TableCell className="text-right whitespace-nowrap">
                            <Button variant="outline" size="sm" className="h-8 mr-1" onClick={() => void testChannel(c)}>
                              <Send className="h-3.5 w-3.5 mr-1.5" />Test
                            </Button>
                            <Button variant="ghost" size="icon" className="h-8 w-8" title="Düzenle" onClick={() => setChannelEditing(c)}>
                              <Pencil className="h-3.5 w-3.5" />
                            </Button>
                            <Button variant="ghost" size="icon" className="h-8 w-8" title="Sil" onClick={() => void removeChannel(c)}>
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="projects" className="mt-4">
          <ProjectDefaults
            loading={loading}
            defaults={defaults}
            channels={channels}
            onSaved={updated => setDefaults(list => list.map(d => (d.project === updated.project ? updated : d)))}
          />
        </TabsContent>
      </Tabs>

      {ruleDraft && (
        <RuleDialog
          initial={ruleDraft}
          projects={projects}
          channels={channels}
          defaults={defaultsByProject}
          onClose={() => setRuleDraft(null)}
          onSaved={async (saved, test) => {
            setRuleDraft(null)
            await load()
            if (test) await runRuleTest(saved)
          }}
        />
      )}
      {builtinEditing && (
        <BuiltinDialog
          rule={builtinEditing}
          channels={channels}
          onClose={() => setBuiltinEditing(null)}
          onSaved={updated => {
            setBuiltinEditing(null)
            setRules(list => list.map(r => (r.id === updated.id ? updated : r)))
          }}
        />
      )}
      {channelEditing && (
        <ChannelDialog
          channel={channelEditing === 'new' ? null : channelEditing}
          onClose={() => setChannelEditing(null)}
          onSaved={async () => {
            setChannelEditing(null)
            await load()
          }}
        />
      )}
    </div>
  )
}

// ── Shared pieces ───────────────────────────────────────────────────────

function ChannelPicker({
  channels, selected, onChange,
}: {
  channels: AlertChannel[]
  selected: string[]
  onChange: (ids: string[]) => void
}) {
  if (channels.length === 0) {
    return <p className="text-xs text-muted-foreground">Önce Kanallar sekmesinden bir kanal ekleyin.</p>
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {channels.map(c => {
        const on = selected.includes(c.id)
        return (
          <button
            type="button"
            key={c.id}
            onClick={() => onChange(on ? selected.filter(x => x !== c.id) : [...selected, c.id])}
            className={cn(
              'rounded-md border px-2 py-1 text-xs transition-colors cursor-pointer',
              on ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground',
              !c.enabled && 'opacity-50',
            )}
            title={c.enabled ? undefined : 'Kanal kapalı'}
          >
            {c.name}
            <span className="ml-1 text-[10px] opacity-70">{c.kind === 'slack' ? 'Slack' : 'E-posta'}</span>
          </button>
        )
      })}
    </div>
  )
}

function Field({ label, hint, children, className }: { label: string; hint?: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('space-y-1', className)}>
      <Label className="text-xs text-muted-foreground">{label}</Label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  )
}

// ── Event rule editor ───────────────────────────────────────────────────

function RuleDialog({
  initial, projects, channels, defaults, onClose, onSaved,
}: {
  initial: RuleDraft
  projects: DeployProjectSummary[]
  channels: AlertChannel[]
  defaults: Map<string, string[]>
  onClose: () => void
  onSaved: (rule: AlertRule, test: boolean) => Promise<void>
}) {
  const [d, setD] = useState<RuleDraft>(initial)
  const [saving, setSaving] = useState(false)
  const [events, setEvents] = useState<ProjectEvent[] | null>(null)
  const [loadingEvents, setLoadingEvents] = useState(false)

  const project = projects.find(p => p.project.slug === d.project)
  const update = (patch: Partial<RuleDraft>) => setD(prev => ({ ...prev, ...patch }))
  const updateClause = (i: number, patch: Partial<ClauseDraft>) =>
    setD(prev => ({ ...prev, clauses: prev.clauses.map((c, j) => (j === i ? { ...c, ...patch } : c)) }))
  const updateCondition = (ci: number, fi: number, patch: Partial<ConditionDraft>) =>
    updateClause(ci, { fields: d.clauses[ci].fields.map((f, j) => (j === fi ? { ...f, ...patch } : f)) })
  const updateTier = (i: number, patch: Partial<TierDraft>) =>
    setD(prev => ({ ...prev, tiers: prev.tiers.map((t, j) => (j === i ? { ...t, ...patch } : t)) }))

  async function loadEvents() {
    if (!d.project) return
    setLoadingEvents(true)
    try {
      setEvents(await api.listProjectEvents(d.project, d.component))
    } catch (err) {
      toast.error(errorText(err, 'Olaylar okunamadı'))
    } finally {
      setLoadingEvents(false)
    }
  }

  function addEventToFirstClause(name: string) {
    const current = splitList(d.clauses[0].events)
    if (current.includes(name)) return
    updateClause(0, { events: [...current, name].join(', ') })
  }

  async function save(test: boolean) {
    if (!d.name.trim()) {
      toast.error('Kurala bir ad verin')
      return
    }
    setSaving(true)
    try {
      const input = draftToInput(d)
      const saved = d.id ? await api.updateAlertRule(d.id, input) : await api.createAlertRule(input)
      toast.success(d.id ? 'Kural kaydedildi' : 'Kural oluşturuldu')
      await onSaved(saved, test)
    } catch (err) {
      toast.error(errorText(err, 'Kaydedilemedi'))
    } finally {
      setSaving(false)
    }
  }

  const projectDefaultNames = (defaults.get(d.project) ?? [])
    .map(id => channels.find(c => c.id === id)?.name)
    .filter(Boolean)
    .join(', ')

  return (
    <Dialog open onOpenChange={v => !v && onClose()}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{d.id ? 'Olay kuralını düzenle' : 'Yeni olay kuralı'}</DialogTitle>
          <DialogDescription>
            Satır, aşağıdaki gruplardan herhangi birine uyarsa eşleşir. Kademeler düşükten yükseğe sıralanır ve
            sağlanan en yüksek kademe alarmın önemini belirler.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Ad">
              <Input value={d.name} onChange={e => update({ name: e.target.value })} placeholder="Ödeme alınamadı" />
            </Field>
            <div className="flex items-end justify-between gap-3">
              <Field label="Açık" className="flex-1">
                <Switch checked={d.enabled} onCheckedChange={v => update({ enabled: v })} />
              </Field>
            </div>
            <Field label="Açıklama" className="sm:col-span-2" hint="Alarmı gören ekibin ne yapacağını anlatın.">
              <Textarea rows={2} value={d.description} onChange={e => update({ description: e.target.value })} />
            </Field>
            <Field label="Proje">
              <Select value={d.project} onValueChange={v => { update({ project: v, component: '' }); setEvents(null) }}>
                <SelectTrigger><SelectValue placeholder="Proje seçin" /></SelectTrigger>
                <SelectContent>
                  {projects.map(p => <SelectItem key={p.project.slug} value={p.project.slug}>{p.project.name}</SelectItem>)}
                </SelectContent>
              </Select>
            </Field>
            <Field label="Component">
              <Select value={d.component || ALL} onValueChange={v => { update({ component: v === ALL ? '' : v }); setEvents(null) }}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>Bütün componentler</SelectItem>
                  {(project?.components ?? []).map(c => <SelectItem key={c.slug} value={c.slug}>{c.name}</SelectItem>)}
                </SelectContent>
              </Select>
            </Field>
          </div>

          <div className="rounded-md border p-3 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-medium">Son 7 günde görülen olaylar</span>
              <Button variant="outline" size="sm" onClick={() => void loadEvents()} disabled={!d.project || loadingEvents}>
                {loadingEvents ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Search className="h-3.5 w-3.5 mr-1.5" />}
                Olayları getir
              </Button>
            </div>
            {events && events.length === 0 && (
              <p className="text-xs text-muted-foreground">
                Bu projede son 7 günde <code className="font-mono">event.name</code> alanı olan satır yok. Uygulamanın
                log biçimini kontrol edin; olay adlarını yine de elle yazabilirsiniz.
              </p>
            )}
            {events && events.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {events.map(ev => (
                  <button
                    type="button"
                    key={ev.name}
                    onClick={() => addEventToFirstClause(ev.name)}
                    className="rounded-md border border-border px-2 py-1 text-left text-xs hover:border-primary cursor-pointer"
                    title={ev.fields.length > 0 ? `Alanlar: ${ev.fields.join(', ')}` : 'Başka alan yok'}
                  >
                    <span className="font-mono">{ev.name}</span>
                    <span className="ml-1.5 text-muted-foreground">{ev.count}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Eşleşme</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => update({ clauses: [...d.clauses, { events: '', fields: [] }] })}
              >
                <Plus className="h-3.5 w-3.5 mr-1" />Grup ekle
              </Button>
            </div>
            {d.clauses.map((c, ci) => (
              <div key={ci} className="rounded-md border p-3 space-y-2">
                <div className="flex items-start gap-2">
                  <Field label={ci === 0 ? 'Olay adları' : `Veya olay adları`} className="flex-1" hint="Virgülle ayırın.">
                    <Input
                      className="font-mono text-xs"
                      value={c.events}
                      onChange={e => updateClause(ci, { events: e.target.value })}
                      placeholder="PAYMENT_BLOCKED, PAYMENT_RETRY_EXHAUSTED"
                    />
                  </Field>
                  {d.clauses.length > 1 && (
                    <Button
                      variant="ghost" size="icon" className="mt-5 h-8 w-8" title="Grubu kaldır"
                      onClick={() => update({ clauses: d.clauses.filter((_, j) => j !== ci) })}
                    >
                      <X className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </div>
                {c.fields.map((f, fi) => (
                  <div key={fi} className="flex flex-wrap items-center gap-2">
                    <Input
                      className="w-40 font-mono text-xs"
                      value={f.key}
                      onChange={e => updateCondition(ci, fi, { key: e.target.value })}
                      placeholder="job_family"
                    />
                    <Select value={f.op} onValueChange={v => updateCondition(ci, fi, { op: v as AlertFieldCondition['op'] })}>
                      <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {(Object.keys(OP_LABELS) as AlertFieldCondition['op'][]).map(op => (
                          <SelectItem key={op} value={op}>{OP_LABELS[op]}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {f.op !== 'exists' && (
                      <Input
                        className="flex-1 min-w-[160px] font-mono text-xs"
                        value={f.values}
                        onChange={e => updateCondition(ci, fi, { values: e.target.value })}
                        placeholder={f.op === 'in' || f.op === 'not_in' ? 'değer1, değer2' : 'değer'}
                      />
                    )}
                    <Button
                      variant="ghost" size="icon" className="h-8 w-8" title="Koşulu kaldır"
                      onClick={() => updateClause(ci, { fields: c.fields.filter((_, j) => j !== fi) })}
                    >
                      <X className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-xs"
                  onClick={() => updateClause(ci, { fields: [...c.fields, { key: '', op: 'eq', values: '' }] })}
                >
                  <Plus className="h-3 w-3 mr-1" />Alan koşulu ekle
                </Button>
              </div>
            ))}
          </div>

          <Field
            label="Gruplama alanı"
            hint="Boş bırakılırsa kural tek bir alarm üretir. Örneğin job_id verilirse her iş için ayrı alarm açılır ve eşikler iş başına sayılır."
          >
            <Input className="font-mono text-xs" value={d.groupBy} onChange={e => update({ groupBy: e.target.value })} placeholder="job_id" />
          </Field>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Kademeler</span>
              <Button
                variant="ghost"
                size="sm"
                disabled={d.tiers.length >= 4}
                onClick={() => update({ tiers: [...d.tiers, emptyTier()] })}
              >
                <Plus className="h-3.5 w-3.5 mr-1" />Kademe ekle
              </Button>
            </div>
            {d.tiers.map((t, ti) => (
              <div key={ti} className="flex flex-wrap items-end gap-2 rounded-md border p-3">
                <Field label="Önem" className="w-32">
                  <Select value={t.severity} onValueChange={v => updateTier(ti, { severity: v as AlertSeverity })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {SEVERITIES.map(s => <SelectItem key={s} value={s}>{SEVERITY_LABELS[s]}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </Field>
                <Field label="Tetikleyici" className="w-56">
                  <Select value={t.type} onValueChange={v => updateTier(ti, { type: v as AlertTrigger['type'] })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {(Object.keys(TRIGGER_LABELS) as AlertTrigger['type'][]).map(k => (
                        <SelectItem key={k} value={k}>{TRIGGER_LABELS[k]}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
                {t.type === 'distinct' && (
                  <Field label="Alan" className="w-32">
                    <Input className="font-mono text-xs" value={t.field} onChange={e => updateTier(ti, { field: e.target.value })} placeholder="job_id" />
                  </Field>
                )}
                {t.type !== 'each' && (
                  <Field label={t.type === 'baseline' ? 'Asgari olay' : 'Adet'} className="w-24">
                    <Input type="number" min={1} value={t.count} onChange={e => updateTier(ti, { count: e.target.value })} />
                  </Field>
                )}
                {(t.type === 'count' || t.type === 'distinct') && (
                  <Field label="Pencere (dakika)" className="w-32">
                    <Input type="number" min={1} value={t.windowMinutes} onChange={e => updateTier(ti, { windowMinutes: e.target.value })} />
                  </Field>
                )}
                {t.type === 'baseline' && (
                  <>
                    <Field label="Kat" className="w-20">
                      <Input type="number" step="0.5" min={1} value={t.ratio} onChange={e => updateTier(ti, { ratio: e.target.value })} />
                    </Field>
                    <Field label="Geçmiş (gün)" className="w-28">
                      <Input type="number" min={1} max={7} value={t.baselineDays} onChange={e => updateTier(ti, { baselineDays: e.target.value })} />
                    </Field>
                  </>
                )}
                {d.tiers.length > 1 && (
                  <Button
                    variant="ghost" size="icon" className="h-9 w-9" title="Kademeyi kaldır"
                    onClick={() => update({ tiers: d.tiers.filter((_, j) => j !== ti) })}
                  >
                    <X className="h-3.5 w-3.5" />
                  </Button>
                )}
                <p className="w-full text-[11px] text-muted-foreground">{describeTrigger(tierTrigger(t))}</p>
              </div>
            ))}
          </div>

          <Field
            label="Bildirimde gösterilecek alanlar"
            hint="Virgülle ayırın. Slack ve e-postaya yalnız bu alanlar gider; satırın geri kalanı yalnız panelde görünür. Kişisel veri taşıyan alanları eklemeyin."
          >
            <Input className="font-mono text-xs" value={d.notifyFields} onChange={e => update({ notifyFields: e.target.value })} placeholder="job_id, attempts" />
          </Field>

          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Teslim">
              <Select value={d.delivery} onValueChange={v => update({ delivery: v as AlertDeliveryMode })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="instant">Anında: açılınca ve önem yükselince</SelectItem>
                  <SelectItem value="digest">Günlük özet</SelectItem>
                  <SelectItem value="none">Yalnız kayıt, bildirim yok</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            {d.delivery === 'instant' && (
              <Field label="Kritik alarmı hatırlat (dakika)" hint="Onaylanmayan kritik alarm bu aralıkla yeniden bildirilir. 0 kapatır.">
                <Input type="number" min={0} value={d.remindMinutes} onChange={e => update({ remindMinutes: e.target.value })} />
              </Field>
            )}
          </div>

          {d.delivery !== 'none' && (
            <Field
              label="Kanallar"
              hint={d.channelIds.length === 0
                ? (projectDefaultNames ? `Seçim yapılmazsa projenin varsayılanı kullanılır: ${projectDefaultNames}.` : 'Seçim yapılmazsa projenin varsayılan kanalları kullanılır, ancak bu projenin varsayılanı yok.')
                : undefined}
            >
              <ChannelPicker channels={channels} selected={d.channelIds} onChange={ids => update({ channelIds: ids })} />
            </Field>
          )}
        </div>

        <DialogFooter className="gap-2">
          <Button variant="ghost" onClick={onClose} disabled={saving}>Vazgeç</Button>
          <Button variant="outline" onClick={() => void save(true)} disabled={saving || d.delivery === 'none'}>
            <Send className="h-4 w-4 mr-2" />
            Kaydet ve bir kez tetikle
          </Button>
          <Button onClick={() => void save(false)} disabled={saving}>
            {saving && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Kaydet
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Builtin rule routing ────────────────────────────────────────────────

function BuiltinDialog({
  rule, channels, onClose, onSaved,
}: {
  rule: AlertRule
  channels: AlertChannel[]
  onClose: () => void
  onSaved: (rule: AlertRule) => void
}) {
  const [enabled, setEnabled] = useState(rule.enabled)
  const [delivery, setDelivery] = useState<AlertDeliveryMode>(rule.delivery)
  const [remind, setRemind] = useState(String(rule.remind_minutes))
  const [channelIds, setChannelIds] = useState(rule.channel_ids)
  const [saving, setSaving] = useState(false)

  async function save() {
    setSaving(true)
    try {
      const updated = await api.updateAlertRule(rule.id, {
        enabled, delivery, remind_minutes: delivery === 'instant' ? Number(remind) || 0 : 0, channel_ids: channelIds,
      })
      toast.success('Kural kaydedildi')
      onSaved(updated)
    } catch (err) {
      toast.error(errorText(err, 'Kaydedilemedi'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={v => !v && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{rule.name}</DialogTitle>
          <DialogDescription>{rule.description}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="flex items-center justify-between rounded-md border p-3">
            <span className="text-sm">Kural açık</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>
          <Field label="Teslim">
            <Select value={delivery} onValueChange={v => setDelivery(v as AlertDeliveryMode)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="instant">Anında</SelectItem>
                <SelectItem value="digest">Günlük özet</SelectItem>
                <SelectItem value="none">Yalnız kayıt</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          {delivery === 'instant' && (
            <Field label="Kritik alarmı hatırlat (dakika)" hint="0 kapatır.">
              <Input type="number" min={0} value={remind} onChange={e => setRemind(e.target.value)} />
            </Field>
          )}
          {delivery !== 'none' && (
            <Field label="Kanallar">
              <ChannelPicker channels={channels} selected={channelIds} onChange={setChannelIds} />
            </Field>
          )}
          <p className="text-xs text-muted-foreground">
            Bu kuralın eşikleri Ayarlar sayfasındaki tespit bölümünden değiştirilir.
          </p>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={saving}>Vazgeç</Button>
          <Button onClick={() => void save()} disabled={saving}>Kaydet</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Channel editor ──────────────────────────────────────────────────────

function ChannelDialog({
  channel, onClose, onSaved,
}: {
  channel: AlertChannel | null
  onClose: () => void
  onSaved: () => Promise<void>
}) {
  const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  const [name, setName] = useState(channel?.name ?? '')
  const [kind, setKind] = useState<'slack' | 'email'>(channel?.kind ?? 'slack')
  const [enabled, setEnabled] = useState(channel?.enabled ?? true)
  const [webhook, setWebhook] = useState('')
  const [recipients, setRecipients] = useState(channel?.email_to.join(', ') ?? '')
  const [hour, setHour] = useState(String(channel?.digest_hour ?? 9))
  const [zone, setZone] = useState(channel?.digest_timezone ?? browserZone)
  const [saving, setSaving] = useState(false)

  async function save() {
    setSaving(true)
    try {
      const input: api.AlertChannelInput = {
        name: name.trim(),
        enabled,
        email_to: kind === 'email' ? splitList(recipients) : [],
        digest_hour: Number(hour),
        digest_timezone: zone.trim(),
      }
      if (kind === 'slack' && webhook.trim()) input.slack_webhook = webhook.trim()
      if (channel) {
        await api.updateAlertChannel(channel.id, input)
      } else {
        await api.createAlertChannel({ ...input, kind })
      }
      toast.success(channel ? 'Kanal kaydedildi' : 'Kanal oluşturuldu')
      await onSaved()
    } catch (err) {
      toast.error(errorText(err, 'Kaydedilemedi'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={v => !v && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{channel ? 'Kanalı düzenle' : 'Yeni kanal'}</DialogTitle>
          <DialogDescription>
            Kaydettikten sonra listeden test bildirimi göndererek kanalın çalıştığını doğrulayın.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <Field label="Ad">
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="Ekip Slack" />
          </Field>
          {!channel && (
            <Field label="Tür">
              <Select value={kind} onValueChange={v => setKind(v as 'slack' | 'email')}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="slack">Slack</SelectItem>
                  <SelectItem value="email">E-posta</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          )}
          {kind === 'slack' ? (
            <Field
              label="Slack webhook adresi"
              hint={channel ? `Kayıtlı adres ${channel.webhook_host ?? ''} için. Değiştirmek için yeni adresi yazın, boş bırakırsanız korunur.` : 'Adres şifreli saklanır ve panelde bir daha gösterilmez.'}
            >
              <Input
                type="password"
                value={webhook}
                onChange={e => setWebhook(e.target.value)}
                placeholder="https://hooks.slack.com/services/..."
                autoComplete="off"
              />
            </Field>
          ) : (
            <Field label="Alıcılar" hint="Virgülle ayırın.">
              <Input value={recipients} onChange={e => setRecipients(e.target.value)} placeholder="ekip@example.com" />
            </Field>
          )}
          <div className="grid gap-3 grid-cols-2">
            <Field label="Günlük özet saati">
              <Select value={hour} onValueChange={setHour}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {Array.from({ length: 24 }, (_, h) => (
                    <SelectItem key={h} value={String(h)}>{String(h).padStart(2, '0')}:00</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field label="Saat dilimi">
              <Input value={zone} onChange={e => setZone(e.target.value)} placeholder="Europe/Istanbul" />
            </Field>
          </div>
          <div className="flex items-center justify-between rounded-md border p-3">
            <span className="text-sm">Kanal açık</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={saving}>Vazgeç</Button>
          <Button onClick={() => void save()} disabled={saving}>Kaydet</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Project defaults ────────────────────────────────────────────────────

function ProjectDefaults({
  loading, defaults, channels, onSaved,
}: {
  loading: boolean
  defaults: AlertProjectChannels[]
  channels: AlertChannel[]
  onSaved: (updated: AlertProjectChannels) => void
}) {
  const [edits, setEdits] = useState<Record<string, string[]>>({})
  const [saving, setSaving] = useState<string | null>(null)

  async function save(project: string) {
    setSaving(project)
    try {
      const updated = await api.setAlertProjectChannels(project, edits[project] ?? [])
      onSaved(updated)
      setEdits(prev => {
        const next = { ...prev }
        delete next[project]
        return next
      })
      toast.success('Varsayılan kanallar kaydedildi')
    } catch (err) {
      toast.error(errorText(err, 'Kaydedilemedi'))
    } finally {
      setSaving(null)
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Proje varsayılanları</CardTitle>
        <p className="text-sm text-muted-foreground mt-1">
          Kendi kanalı seçilmemiş olay kuralları, projesinin buradaki kanallarına bildirir. Bir projenin ekibi değişince
          kuralları tek tek düzenlemek yerine buradan değiştirin.
        </p>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-24 w-full" />
        ) : defaults.length === 0 ? (
          <EmptyState icon={BellRing} title="Proje yok" description="Uygulamalar sayfasından bir proje oluşturun." />
        ) : (
          <div className="divide-y divide-border">
            {defaults.map(p => {
              const selected = edits[p.project] ?? p.channel_ids
              const dirty = edits[p.project] !== undefined
              return (
                <div key={p.project} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center">
                  <div className="sm:w-48">
                    <div className="text-sm font-medium">{p.name}</div>
                    <div className="text-xs font-mono text-muted-foreground">{p.project}</div>
                  </div>
                  <div className="flex-1">
                    <ChannelPicker
                      channels={channels}
                      selected={selected}
                      onChange={ids => setEdits(prev => ({ ...prev, [p.project]: ids }))}
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    {dirty && <Badge variant="outline" className="text-[10px] text-yellow-400 border-yellow-400/40">kaydedilmedi</Badge>}
                    <Button size="sm" variant={dirty ? 'default' : 'outline'} disabled={!dirty || saving === p.project} onClick={() => void save(p.project)}>
                      Kaydet
                    </Button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
