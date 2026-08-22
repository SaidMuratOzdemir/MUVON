import { useState, useEffect, useCallback } from 'react'
import {
  Save, RefreshCw, Loader2, HardDrive, Shield,
  Activity, AlertTriangle, Check, KeyRound, Globe, Bell,
  Mail, Send, Radar, Lock, AlertOctagon, FileKey, Download,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import * as api from '@/api'
import { SystemUpgradePanel } from '@/components/SystemUpgradePanel'

interface SettingDef {
  key: string
  label: string
  description: string
  type: 'string' | 'number' | 'boolean' | 'password'
  placeholder?: string
  unit?: string
}

interface SettingGroup {
  title: string
  icon: React.ElementType
  description?: string
  settings: SettingDef[]
  // extra renders a group-specific panel under the fields. Retention uses it
  // to show what Timescale actually enforces, so the input box can never
  // again imply a policy that is not installed.
  extra?: 'retention'
  // testAction adds a "Send Test" button to groups that configure outbound
  // notifications (Slack / SMTP). The button fires the corresponding
  // /api/alerting/test/* endpoint and toasts the result.
  testAction?: 'slack' | 'smtp'
}

const SETTING_GROUPS: SettingGroup[] = [
  {
    title: 'Log Retention',
    icon: HardDrive,
    extra: 'retention',
    settings: [
      {
        key: 'retention_days',
        label: 'Retention Period',
        description: 'How long diaLOG keeps HTTP logs, captured bodies, container logs, client events and alerts. Lowering it deletes everything outside the new window within a day, permanently: chunks are dropped, not archived. 0 keeps data forever and lets the disk grow without bound.',
        type: 'number',
        placeholder: '30',
        unit: 'days',
      },
    ],
  },
  {
    title: 'Proxy Behavior',
    icon: Activity,
    settings: [
      {
        key: 'enable_body_capture',
        label: 'Capture Bodies',
        description: 'Store request and response bodies in SIEM log detail',
        type: 'boolean',
      },
      {
        key: 'max_body_capture_size',
        label: 'Max Captured Body',
        description: 'Maximum bytes captured per request or response body in SIEM logs',
        type: 'number',
        placeholder: '65536',
        unit: 'bytes',
      },
    ],
  },
  {
    title: 'TLS / ACME',
    icon: Shield,
    settings: [
      {
        key: 'letsencrypt_email',
        label: 'ACME Email',
        description: "Email address for Let's Encrypt certificate notifications",
        type: 'string',
        placeholder: 'admin@example.com',
      },
      {
        key: 'letsencrypt_staging',
        label: 'ACME Staging Mode',
        description: "Use Let's Encrypt staging environment (for testing only)",
        type: 'boolean',
      },
    ],
  },
  {
    title: 'JWT Identity',
    icon: KeyRound,
    settings: [
      {
        key: 'jwt_identity_enabled',
        label: 'Enable JWT Identity',
        description: 'Extract user identity from JWT tokens in Authorization header',
        type: 'boolean',
      },
      {
        key: 'jwt_identity_mode',
        label: 'JWT Mode',
        description: 'verify = validate signature first, decode = extract claims without verification',
        type: 'string',
        placeholder: 'verify',
      },
      {
        key: 'jwt_claims',
        label: 'JWT Claims',
        description: 'Comma-separated list of JWT claim keys to extract (e.g. sub,email,name,role)',
        type: 'string',
        placeholder: 'sub,email,name,role',
      },
      {
        key: 'jwt_secret',
        label: 'JWT Secret',
        description: 'HS256 HMAC secret for JWT verification (write-only, not displayed after save)',
        type: 'password',
        placeholder: 'Enter JWT secret',
      },
    ],
  },
  {
    title: 'GeoIP',
    icon: Globe,
    settings: [
      {
        key: 'geoip_enabled',
        label: 'Enable GeoIP',
        description: 'Enrich logs with geographic information from client IPs',
        type: 'boolean',
      },
      {
        key: 'geoip_db_path',
        label: 'GeoIP Database Path',
        description: 'Path to GeoLite2-City.mmdb file on disk',
        type: 'string',
        placeholder: '/data/GeoLite2-City.mmdb',
      },
    ],
  },
  {
    title: 'Alerting (Slack)',
    icon: Bell,
    testAction: 'slack',
    settings: [
      {
        key: 'alerting_enabled',
        label: 'Enable Alerting',
        description: 'Send notifications when correlation rules detect anomalies',
        type: 'boolean',
      },
      {
        key: 'alerting_cooldown_seconds',
        label: 'Cooldown',
        description: 'Minimum seconds between alerts with the same fingerprint',
        type: 'number',
        placeholder: '300',
        unit: 'sec',
      },
      {
        key: 'alerting_slack_webhook',
        label: 'Slack Webhook URL',
        description: 'Slack incoming webhook URL for alert notifications',
        type: 'string',
        placeholder: 'https://hooks.slack.com/services/...',
      },
    ],
  },
  {
    title: 'Email (SMTP)',
    icon: Mail,
    testAction: 'smtp',
    settings: [
      {
        key: 'alerting_smtp_host',
        label: 'SMTP Host',
        description: 'SMTP server hostname',
        type: 'string',
        placeholder: 'smtp.example.com',
      },
      {
        key: 'alerting_smtp_port',
        label: 'SMTP Port',
        description: 'SMTP server port (587 for STARTTLS, 465 for implicit TLS)',
        type: 'number',
        placeholder: '587',
      },
      {
        key: 'alerting_smtp_username',
        label: 'SMTP Username',
        description: 'SMTP authentication username',
        type: 'string',
        placeholder: 'alerts@example.com',
      },
      {
        key: 'alerting_smtp_password',
        label: 'SMTP Password',
        description: 'SMTP authentication password (write-only, not displayed after save)',
        type: 'password',
        placeholder: 'Enter SMTP password',
      },
      {
        key: 'alerting_smtp_from',
        label: 'From Address',
        description: 'Sender email address for alert notifications',
        type: 'string',
        placeholder: 'alerts@example.com',
      },
      {
        key: 'alerting_smtp_to',
        label: 'To Address(es)',
        description: 'Comma-separated recipient email addresses',
        type: 'string',
        placeholder: 'team@example.com',
      },
    ],
  },
  // ── Threat Detection Rules ──────────────────────────────────────────────
  // Seven correlation rules, each in its own card so thresholds, windows,
  // and path lists stay next to the rule they describe. Defaults ship with
  // the DB migration; these fields let ops tune per-app without a restart.
  {
    title: 'Path Scan Detection',
    icon: Radar,
    description: 'Alerts when a single IP hits N distinct 404 paths in the window. Classic scanner behaviour.',
    settings: [
      { key: 'correlation_path_scan_distinct', label: 'Distinct Paths', description: 'How many different 404 URLs an IP must touch to trip the rule.', type: 'number', placeholder: '10' },
      { key: 'correlation_path_scan_window_seconds', label: 'Window', description: 'Rolling window size for the counter.', type: 'number', placeholder: '120', unit: 'sec' },
    ],
  },
  {
    title: 'Auth Brute Force',
    icon: Lock,
    description: 'Counts auth failures per IP. 401/403 always count; 400 counts only on login endpoints (Django/simplejwt emit 400 on bad credentials).',
    settings: [
      { key: 'correlation_auth_brute_count', label: 'Failure Count', description: 'Failures needed to fire the alert.', type: 'number', placeholder: '5' },
      { key: 'correlation_auth_brute_window_seconds', label: 'Window', description: 'Rolling window size.', type: 'number', placeholder: '120', unit: 'sec' },
      { key: 'correlation_auth_paths', label: 'Login Paths', description: 'Comma-separated login endpoint paths (exact match, trailing-slash insensitive). 400 on any of these counts as an auth failure.', type: 'string', placeholder: '/api/auth/login,/api/authentication/login/' },
    ],
  },
  {
    title: '5xx Error Spike',
    icon: AlertOctagon,
    description: 'Per-host 5xx counter. Fires once, then falls under the alert cooldown so outages do not flood Slack.',
    settings: [
      { key: 'correlation_error_spike_count', label: '5xx Count', description: 'Server errors needed to fire.', type: 'number', placeholder: '10' },
      { key: 'correlation_error_spike_window_seconds', label: 'Window', description: 'Rolling window size.', type: 'number', placeholder: '60', unit: 'sec' },
    ],
  },
  {
    title: 'Traffic Anomaly',
    icon: Activity,
    description: 'Per-host current-RPS vs baseline-RPS. Useful for detecting sudden traffic bursts on low-to-medium-traffic hosts.',
    settings: [
      { key: 'correlation_anomaly_enabled', label: 'Enable', description: 'Turn the anomaly rule on/off without losing its thresholds.', type: 'boolean' },
      { key: 'correlation_anomaly_ratio', label: 'Ratio Threshold', description: 'Current RPS must exceed baseline RPS by this factor to fire.', type: 'string', placeholder: '3.0' },
      { key: 'correlation_anomaly_baseline_seconds', label: 'Baseline Window', description: 'Length of the rolling baseline (the non-current portion is used for the average).', type: 'number', placeholder: '600', unit: 'sec' },
      { key: 'correlation_anomaly_current_seconds', label: 'Current Window', description: 'Recent interval compared against the baseline.', type: 'number', placeholder: '60', unit: 'sec' },
      { key: 'correlation_anomaly_min_baseline', label: 'Min Baseline Events', description: 'Hosts with fewer than this many baseline events are skipped so tiny hosts do not trip easily.', type: 'number', placeholder: '20' },
    ],
  },
  {
    title: 'Sensitive Access',
    icon: FileKey,
    description: 'Fires when too many requests land on configured high-value paths from the same IP. Leave paths empty to disable the rule.',
    settings: [
      { key: 'correlation_sensitive_paths', label: 'Paths', description: 'Comma-separated glob patterns (use * for a single segment). E.g. /api/applications/*/generate_pdf_report/', type: 'string', placeholder: '/api/applications/*/generate_pdf_report/' },
      { key: 'correlation_sensitive_threshold', label: 'Threshold', description: 'Hits within the window to fire.', type: 'number', placeholder: '10' },
      { key: 'correlation_sensitive_window_seconds', label: 'Window', description: 'Rolling window size.', type: 'number', placeholder: '300', unit: 'sec' },
    ],
  },
  {
    title: 'Data Export Burst',
    icon: Download,
    description: 'Per-user export/download volume. Keyed by JWT identity (sub/user_id/email), falling back to IP. Rotating IPs do not split an insider footprint.',
    settings: [
      { key: 'correlation_export_pattern', label: 'URL Pattern', description: 'Case-insensitive regex (Go syntax). Paths that match this pattern count toward the burst.', type: 'string', placeholder: '(?i)(download|export|report|\\.pdf|\\.xlsx|\\.csv)' },
      { key: 'correlation_export_threshold', label: 'Threshold', description: 'Matching requests within the window to fire.', type: 'number', placeholder: '5' },
      { key: 'correlation_export_window_seconds', label: 'Window', description: 'Rolling window size.', type: 'number', placeholder: '300', unit: 'sec' },
    ],
  },
]

function TestChannelButton({ channel, disabled }: { channel: 'slack' | 'smtp'; disabled: boolean }) {
  const [sending, setSending] = useState(false)
  async function runTest() {
    setSending(true)
    try {
      if (channel === 'slack') await api.testSlackAlert()
      else await api.testSMTPAlert()
      toast.success(`${channel} test sent successfully`)
    } catch (err) {
      // Show the backend message verbatim — Slack/SMTP errors (bad URL,
      // auth failure, unreachable host) are actionable and should not be
      // generic-toasted.
      toast.error(err instanceof api.ApiError ? err.message : `${channel} test failed`)
    } finally {
      setSending(false)
    }
  }
  return (
    <Button
      size="sm"
      variant="outline"
      disabled={disabled || sending}
      onClick={runTest}
      className="cursor-pointer"
      title={disabled ? 'Save pending changes before testing' : 'Send a test alert via this channel'}
    >
      {sending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" /> : <Send className="h-3.5 w-3.5 mr-2" />}
      Send Test
    </Button>
  )
}

function SettingRow({
  def, value, saved, onChange, onSave, saving,
}: {
  def: SettingDef
  value: string
  saved: string
  onChange: (v: string) => void
  onSave: () => void
  saving: boolean
}) {
  const isDirty = value !== saved

  return (
    <div className="flex items-start gap-4 py-4">
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2">
          <Label className="text-sm font-medium text-foreground">{def.label}</Label>
          {isDirty && <Badge variant="outline" className="text-[10px] text-yellow-400 border-yellow-400/40">unsaved</Badge>}
        </div>
        <p className="text-xs text-muted-foreground">{def.description}</p>
        <code className="text-[10px] text-muted-foreground/60 font-mono">{def.key}</code>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {def.type === 'boolean' ? (
          <Switch
            checked={value === 'true'}
            onCheckedChange={v => {
              onChange(v ? 'true' : 'false')
            }}
            className="cursor-pointer"
          />
        ) : (
          <div className="flex items-center gap-2">
            <div className="relative">
              <Input
                type={def.type === 'password' ? 'password' : def.type === 'number' ? 'number' : 'text'}
                placeholder={def.placeholder}
                className={cn(
                  'w-40 bg-background border-border text-right font-mono text-sm',
                  def.unit && 'pr-12',
                  (def.type === 'string' || def.type === 'password') && 'w-64 text-left'
                )}
                value={value === '********' ? '' : value}
                onChange={e => onChange(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && isDirty && onSave()}
              />
              {def.unit && (
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-muted-foreground pointer-events-none">
                  {def.unit}
                </span>
              )}
            </div>
          </div>
        )}
        <Button
          size="icon"
          variant={isDirty ? 'default' : 'ghost'}
          className={cn(
            'h-8 w-8 cursor-pointer transition-colors',
            !isDirty && 'text-muted-foreground'
          )}
          onClick={onSave}
          disabled={!isDirty || saving}
          title={isDirty ? 'Save' : 'No changes'}
        >
          {saving
            ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
            : isDirty
              ? <Save className="h-3.5 w-3.5" />
              : <Check className="h-3.5 w-3.5" />
          }
        </Button>
      </div>
    </div>
  )
}

// RetentionStatusPanel shows what Timescale enforces, not what the input box
// says. diaLOG reconciles the setting into the retention jobs within a few
// seconds, so right after a save the two legitimately disagree for a moment;
// we re-read a couple of times instead of leaving a stale warning on screen.
function RetentionStatusPanel({ refreshKey }: { refreshKey: string }) {
  const [status, setStatus] = useState<api.RetentionStatus | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let cancelled = false
    const timers: ReturnType<typeof setTimeout>[] = []

    const fetchOnce = async () => {
      try {
        const s = await api.getRetentionStatus()
        if (!cancelled) { setStatus(s); setFailed(false) }
      } catch {
        if (!cancelled) setFailed(true)
      }
    }

    fetchOnce()
    timers.push(setTimeout(fetchOnce, 3000))
    timers.push(setTimeout(fetchOnce, 8000))
    return () => { cancelled = true; timers.forEach(clearTimeout) }
  }, [refreshKey])

  if (failed) {
    return (
      <p className="px-4 pb-3 text-xs text-muted-foreground">
        Could not read the enforced retention policy.
      </p>
    )
  }
  if (!status) return null

  if (status.unavailable) {
    return (
      <p className="px-4 pb-3 text-xs text-muted-foreground">
        No log hypertables on this deployment, so nothing enforces retention here.
      </p>
    )
  }

  const policies = status.policies ?? []
  const describe = (p: api.RetentionPolicy) =>
    p.has_policy ? `${p.days}d` : 'kept forever'

  return (
    <div className="px-4 pb-3 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-muted-foreground">Enforced by diaLOG right now:</span>
        {policies.map(p => (
          <Badge
            key={p.table}
            variant="outline"
            className={cn(
              'text-[10px] font-mono',
              (p.has_policy ? p.days : 0) === status.setting_days
                ? 'text-emerald-400 border-emerald-400/40'
                : 'text-yellow-400 border-yellow-400/40'
            )}
          >
            {p.table} {describe(p)}
          </Badge>
        ))}
      </div>
      {!status.in_sync && (
        <p className="text-xs text-yellow-400">
          The setting says {status.setting_days} days but the policies above differ. diaLOG applies
          the change within a few seconds; if this stays, diaLOG is down or cannot alter the jobs.
        </p>
      )}
    </div>
  )
}

export default function Settings() {
  const [rawValues, setRawValues] = useState<Record<string, string>>({})
  const [savedValues, setSavedValues] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [savingKey, setSavingKey] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.getSettings()
      const normalized: Record<string, string> = {}
      for (const [k, v] of Object.entries(data ?? {})) {
        normalized[k] = String(v)
      }
      setRawValues(normalized)
      setSavedValues(normalized)
    } catch {
      toast.error('Failed to load settings')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // An unset setting has no value. Falling back to the placeholder here
  // rendered the suggested default as though it were stored and in force,
  // which is how a retention window nobody had ever configured showed 90
  // while Timescale was dropping data at 30.
  function getValue(key: string, def: SettingDef) {
    return rawValues[key] ?? (def.type === 'boolean' ? 'false' : '')
  }

  function getSaved(key: string, def: SettingDef) {
    return savedValues[key] ?? (def.type === 'boolean' ? 'false' : '')
  }

  async function handleSave(key: string, value: string) {
    setSavingKey(key)
    try {
      await api.updateSetting(key, value)
      setSavedValues(prev => ({ ...prev, [key]: value }))
      toast.success(`${key} saved`)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Save failed')
    } finally {
      setSavingKey(null)
    }
  }

  const allDirtyKeys = SETTING_GROUPS.flatMap(g => g.settings).filter(s => {
    const raw = getValue(s.key, s)
    const saved = getSaved(s.key, s)
    return raw !== saved
  })

  async function saveAll() {
    for (const def of allDirtyKeys) {
      await handleSave(def.key, getValue(def.key, def))
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">Settings</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Configure proxy and SIEM behavior</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon" onClick={load} className="h-9 w-9 cursor-pointer border-border">
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </Button>
          {allDirtyKeys.length > 0 && (
            <Button onClick={saveAll} className="gap-2 cursor-pointer">
              <Save className="h-4 w-4" />
              Save All ({allDirtyKeys.length})
            </Button>
          )}
        </div>
      </div>

      {/* Sistem güncellemesi — en üstte, ayarlardan bağımsız panel */}
      <SystemUpgradePanel />

      {allDirtyKeys.length > 0 && (
        <div className="flex items-center gap-3 rounded-lg border border-yellow-400/30 bg-yellow-400/5 px-4 py-3 text-sm text-yellow-400">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{allDirtyKeys.length} unsaved change{allDirtyKeys.length !== 1 ? 's' : ''}. Remember to save.</span>
        </div>
      )}

      {loading ? (
        <div className="space-y-6">
          {[1, 2, 3].map(i => (
            <div key={i} className="space-y-3">
              <Skeleton className="h-6 w-40" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-6">
          {SETTING_GROUPS.map(group => (
            <div key={group.title} className="rounded-lg border border-border bg-card overflow-hidden">
              <div className="flex items-center justify-between gap-2 px-4 py-3 bg-muted/20 border-b border-border">
                <div className="flex items-center gap-2 min-w-0">
                  <group.icon className="h-4 w-4 text-primary shrink-0" />
                  <span className="text-sm font-semibold text-foreground truncate">{group.title}</span>
                </div>
                {group.testAction && (
                  <TestChannelButton
                    channel={group.testAction}
                    disabled={allDirtyKeys.some(s => s.key.startsWith(group.testAction === 'slack' ? 'alerting_slack' : 'alerting_smtp'))}
                  />
                )}
              </div>
              {group.description && (
                <p className="px-4 pt-3 text-xs text-muted-foreground">{group.description}</p>
              )}
              <div className="px-4 divide-y divide-border">
                {group.settings.map((def) => (
                  <SettingRow
                    key={def.key}
                    def={def}
                    value={getValue(def.key, def)}
                    saved={getSaved(def.key, def)}
                    onChange={v => setRawValues(prev => ({ ...prev, [def.key]: v }))}
                    onSave={() => handleSave(def.key, getValue(def.key, def))}
                    saving={savingKey === def.key}
                  />
                ))}
              </div>
              {group.extra === 'retention' && (
                <RetentionStatusPanel refreshKey={savedValues['retention_days'] ?? ''} />
              )}
            </div>
          ))}
        </div>
      )}

      <div className="rounded-lg border border-border bg-card px-4 py-4">
        <p className="text-xs text-muted-foreground">
          Settings are persisted to the database and take effect after the next{' '}
          <strong className="text-foreground">config reload</strong> (triggered from the Dashboard).
          Retention is picked up by diaLOG within a few seconds; the badges above show what is
          actually enforced.
        </p>
      </div>
    </div>
  )
}
