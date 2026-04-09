import { useState, useEffect, useCallback } from 'react'
import {
  Save, RefreshCw, Loader2, HardDrive, Clock, Shield,
  Activity, AlertTriangle, Check, KeyRound, Globe, Bell,
  Mail,
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

interface SettingDef {
  key: string
  label: string
  description: string
  type: 'string' | 'number' | 'boolean' | 'password'
  placeholder?: string
  unit?: string
}

const SETTING_GROUPS: { title: string; icon: React.ElementType; settings: SettingDef[] }[] = [
  {
    title: 'Log Retention',
    icon: HardDrive,
    settings: [
      {
        key: 'log_retention_days',
        label: 'Retention Period',
        description: 'How many days to keep HTTP access logs in the database',
        type: 'number',
        placeholder: '90',
        unit: 'days',
      },
    ],
  },
  {
    title: 'Rate Limiting',
    icon: Shield,
    settings: [
      {
        key: 'rate_limit_rps',
        label: 'Requests per Second',
        description: 'Maximum requests per second per client IP (0 = disabled)',
        type: 'number',
        placeholder: '100',
        unit: 'req/s',
      },
      {
        key: 'rate_limit_burst',
        label: 'Burst Size',
        description: 'Token bucket burst size for rate limiting',
        type: 'number',
        placeholder: '200',
        unit: 'tokens',
      },
    ],
  },
  {
    title: 'Proxy Behavior',
    icon: Activity,
    settings: [
      {
        key: 'proxy_timeout_seconds',
        label: 'Backend Timeout',
        description: 'Timeout for proxied requests to backend services',
        type: 'number',
        placeholder: '30',
        unit: 'seconds',
      },
      {
        key: 'max_request_body_mb',
        label: 'Max Request Body',
        description: 'Maximum size for captured request bodies in SIEM logs',
        type: 'number',
        placeholder: '1',
        unit: 'MB',
      },
      {
        key: 'max_response_body_mb',
        label: 'Max Response Body',
        description: 'Maximum size for captured response bodies in SIEM logs',
        type: 'number',
        placeholder: '1',
        unit: 'MB',
      },
    ],
  },
  {
    title: 'WAF Integration',
    icon: Shield,
    settings: [
      {
        key: 'waf_url',
        label: 'muWAF Engine URL',
        description: 'Base URL of the muWAF inspection engine (e.g. http://localhost:8000). Leave empty to disable.',
        type: 'string',
        placeholder: 'http://localhost:8000',
      },
      {
        key: 'waf_timeout_ms',
        label: 'WAF Timeout',
        description: 'Max time to wait for a WAF response before failing open (allowing the request)',
        type: 'number',
        placeholder: '200',
        unit: 'ms',
      },
    ],
  },
  {
    title: 'TLS / ACME',
    icon: Shield,
    settings: [
      {
        key: 'acme_email',
        label: 'ACME Email',
        description: "Email address for Let's Encrypt certificate notifications",
        type: 'string',
        placeholder: 'admin@example.com',
      },
      {
        key: 'acme_staging',
        label: 'ACME Staging Mode',
        description: "Use Let's Encrypt staging environment (for testing only)",
        type: 'boolean',
      },
    ],
  },
  {
    title: 'Timing',
    icon: Clock,
    settings: [
      {
        key: 'partition_ahead_days',
        label: 'Partition Lookahead',
        description: 'How many days ahead to pre-create daily log partitions',
        type: 'number',
        placeholder: '7',
        unit: 'days',
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
    title: 'Alerting',
    icon: Bell,
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
]

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
      for (const [k, v] of Object.entries(data)) {
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

  function getValue(key: string, def: SettingDef) {
    return rawValues[key] ?? (def.type === 'boolean' ? 'false' : def.placeholder ?? '')
  }

  function getSaved(key: string, def: SettingDef) {
    return savedValues[key] ?? (def.type === 'boolean' ? 'false' : def.placeholder ?? '')
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
              <div className="flex items-center gap-2 px-4 py-3 bg-muted/20 border-b border-border">
                <group.icon className="h-4 w-4 text-primary" />
                <span className="text-sm font-semibold text-foreground">{group.title}</span>
              </div>
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
            </div>
          ))}
        </div>
      )}

      <div className="rounded-lg border border-border bg-card px-4 py-4">
        <p className="text-xs text-muted-foreground">
          Settings are persisted to the database and take effect after the next{' '}
          <strong className="text-foreground">config reload</strong> (triggered from the Dashboard).
          Some settings (like retention or partition lookahead) apply at the next scheduled cron cycle.
        </p>
      </div>
    </div>
  )
}
