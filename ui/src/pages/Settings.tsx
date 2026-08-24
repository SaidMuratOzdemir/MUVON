import { useState, useEffect, useCallback } from 'react'
import {
  Save, RefreshCw, Loader2, HardDrive, Shield,
  Activity, AlertTriangle, Check, KeyRound, Bell,
  Mail, Send, Radar, Lock, AlertOctagon, FileKey, Download, Archive,
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
import { BackupPanel } from '@/components/BackupPanel'

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
  extra?: 'retention' | 'compression'
  // testAction adds a "Send Test" button to groups that configure outbound
  // notifications (Slack / SMTP). The button fires the corresponding
  // /api/alerting/test/* endpoint and toasts the result.
  testAction?: 'slack' | 'smtp'
}

const SETTING_GROUPS: SettingGroup[] = [
  {
    title: 'Log Saklama',
    icon: HardDrive,
    extra: 'retention',
    settings: [
      {
        key: 'retention_days',
        label: 'Saklama Süresi',
        description: "diaLOG'un HTTP loglarını, yakalanan gövdeleri, container loglarını, istemci olaylarını ve alarmları ne kadar süre tuttuğu. Düşürmek, yeni pencerenin dışında kalan her şeyi bir gün içinde kalıcı olarak siler: chunk'lar arşivlenmez, düşürülür. 0 veriyi sonsuza kadar tutar ve diskin sınırsız büyümesine izin verir.",
        type: 'number',
        placeholder: '30',
        unit: 'gün',
      },
    ],
  },
  {
    title: 'Sıkıştırma',
    icon: Archive,
    extra: 'compression',
    description: "Bir chunk kaç gün sonra sütunlu biçime çevrilsin. Sıkıştırma diski belirgin şekilde küçültür, ama sıkıştırılmış bir chunk trigram indeksini kullanamaz: sıkıştırılmamış pencere aynı zamanda aramanın indeksli kaldığı penceredir.",
    settings: [
      {
        key: 'compression_days',
        label: 'Sıkıştırma Süresi',
        description: "HTTP logları, container logları, istemci olayları ve alarmlar için geçerlidir. 0 politikayı kaldırır ve yeni chunk'lar sıkıştırılmadan kalır; hâlihazırda sıkıştırılmış veriyi geri açmaz.",
        type: 'number',
        placeholder: '7',
        unit: 'gün',
      },
      {
        key: 'compression_bodies_days',
        label: 'Gövde Sıkıştırma Süresi',
        description: "Yakalanan istek ve yanıt gövdeleri için ayrı tutulur, çünkü gövde aramasının indeksini devre dışı bırakan şey tam olarak bu tablonun sıkıştırılmasıdır. Büyütmek gövde aramasını daha geriye kadar hızlı tutar, karşılığı disktir.",
        type: 'number',
        placeholder: '7',
        unit: 'gün',
      },
    ],
  },
  {
    title: 'Proxy Davranışı',
    icon: Activity,
    settings: [
      {
        key: 'enable_body_capture',
        label: 'Gövdeleri Yakala',
        description: 'İstek ve yanıt gövdelerini SIEM log detayında sakla',
        type: 'boolean',
      },
      {
        key: 'max_body_capture_size',
        label: 'Azami Gövde Boyutu',
        description: 'SIEM loglarında istek veya yanıt gövdesi başına yakalanan azami bayt',
        type: 'number',
        placeholder: '65536',
        unit: 'bayt',
      },
    ],
  },
  {
    title: 'İstemci Telemetrisi (RUM)',
    icon: Radar,
    description: 'Tarayıcılara /__muvon/rum/config adresinden sunulur ve agentlara iletilir. Betiği yalnızca RUM açık olan hostlar yükler.',
    settings: [
      {
        key: 'rum_sample_rate',
        label: 'Örnekleme Oranı',
        description: 'Telemetri gönderen tarayıcı oturumlarının oranı, 0 ile 1 arasında. 1 her şeyi gönderir, 0,1 onda birini tutar. Aralık dışındaki değerler 1 sayılır.',
        type: 'string',
        placeholder: '1',
      },
      {
        key: 'rum_max_batch_bytes',
        label: 'Azami Beacon Boyutu',
        description: 'Tek bir tarayıcı beacon\'ının üst sınırı. Daha büyük yığınları istemci kütüphanesi böler.',
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
        label: 'ACME E-postası',
        description: "Let's Encrypt sertifika bildirimleri için e-posta adresi",
        type: 'string',
        placeholder: 'admin@example.com',
      },
      {
        key: 'letsencrypt_staging',
        label: 'ACME Staging Modu',
        description: "Let's Encrypt staging ortamını kullan (yalnızca test için)",
        type: 'boolean',
      },
    ],
  },
  {
    title: 'JWT Kimliği',
    icon: KeyRound,
    settings: [
      {
        key: 'jwt_identity_enabled',
        label: 'JWT Kimliğini Aç',
        description: 'Authorization başlığındaki JWT tokenlarından kullanıcı kimliğini çıkar',
        type: 'boolean',
      },
      {
        key: 'jwt_identity_mode',
        label: 'JWT Modu',
        description: 'verify = önce imzayı doğrula, decode = doğrulamadan claim çıkar',
        type: 'string',
        placeholder: 'verify',
      },
      {
        key: 'jwt_claims',
        label: 'JWT Claim Listesi',
        description: 'Çıkarılacak JWT claim anahtarları, virgülle ayrılmış (örn. sub,email,name,role)',
        type: 'string',
        placeholder: 'sub,email,name,role',
      },
      {
        key: 'jwt_secret',
        label: 'JWT Secret',
        description: 'JWT doğrulaması için HS256 HMAC secret (yalnızca yazılır, kaydedildikten sonra gösterilmez)',
        type: 'password',
        placeholder: 'JWT secret girin',
      },
    ],
  },
  {
    title: 'Alarm (Slack)',
    icon: Bell,
    testAction: 'slack',
    settings: [
      {
        key: 'alerting_enabled',
        label: 'Alarmları Aç',
        description: 'Korelasyon kuralları anomali yakaladığında bildirim gönder',
        type: 'boolean',
      },
      {
        key: 'alerting_cooldown_seconds',
        label: 'Bekleme Süresi',
        description: 'Aynı parmak izine sahip alarmlar arasındaki asgari süre',
        type: 'number',
        placeholder: '300',
        unit: 'sn',
      },
      {
        key: 'alerting_slack_webhook',
        label: 'Slack Webhook Adresi',
        description: 'Alarm bildirimleri için Slack incoming webhook adresi',
        type: 'string',
        placeholder: 'https://hooks.slack.com/services/...',
      },
    ],
  },
  {
    title: 'E-posta (SMTP)',
    icon: Mail,
    testAction: 'smtp',
    settings: [
      {
        key: 'alerting_smtp_host',
        label: 'SMTP Sunucusu',
        description: 'SMTP sunucusunun adı',
        type: 'string',
        placeholder: 'smtp.example.com',
      },
      {
        key: 'alerting_smtp_port',
        label: 'SMTP Portu',
        description: 'SMTP sunucu portu (STARTTLS için 587, örtük TLS için 465)',
        type: 'number',
        placeholder: '587',
      },
      {
        key: 'alerting_smtp_username',
        label: 'SMTP Kullanıcı Adı',
        description: 'SMTP kimlik doğrulama kullanıcı adı',
        type: 'string',
        placeholder: 'alerts@example.com',
      },
      {
        key: 'alerting_smtp_password',
        label: 'SMTP Parolası',
        description: 'SMTP kimlik doğrulama parolası (yalnızca yazılır, kaydedildikten sonra gösterilmez)',
        type: 'password',
        placeholder: 'SMTP parolası girin',
      },
      {
        key: 'alerting_smtp_from',
        label: 'Gönderen Adresi',
        description: 'Alarm bildirimlerinin gönderen e-posta adresi',
        type: 'string',
        placeholder: 'alerts@example.com',
      },
      {
        key: 'alerting_smtp_to',
        label: 'Alıcı Adresleri',
        description: 'Virgülle ayrılmış alıcı e-posta adresleri',
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
    title: 'Yol Tarama Tespiti',
    icon: Radar,
    description: 'Tek bir IP pencere içinde N farklı 404 yoluna dokunduğunda alarm üretir. Klasik tarayıcı davranışı.',
    settings: [
      { key: 'correlation_path_scan_distinct', label: 'Farklı Yol Sayısı', description: 'Kuralın tetiklenmesi için bir IP\'nin dokunması gereken farklı 404 adresi sayısı.', type: 'number', placeholder: '10' },
      { key: 'correlation_path_scan_window_seconds', label: 'Pencere', description: 'Sayacın kayan pencere boyutu.', type: 'number', placeholder: '120', unit: 'sn' },
    ],
  },
  {
    title: 'Kimlik Doğrulama Kaba Kuvvet',
    icon: Lock,
    description: 'IP başına kimlik doğrulama hatalarını sayar. 401 ve 403 her zaman sayılır, 400 yalnızca giriş uçlarında sayılır (Django ve simplejwt hatalı bilgide 400 döner).',
    settings: [
      { key: 'correlation_auth_brute_count', label: 'Hata Sayısı', description: 'Alarmın üretilmesi için gereken hata sayısı.', type: 'number', placeholder: '5' },
      { key: 'correlation_auth_brute_window_seconds', label: 'Pencere', description: 'Kayan pencere boyutu.', type: 'number', placeholder: '120', unit: 'sn' },
      { key: 'correlation_auth_paths', label: 'Giriş Yolları', description: 'Virgülle ayrılmış giriş ucu yolları (tam eşleşme, sondaki eğik çizgi önemsiz). Bunlardan birinde dönen 400, kimlik doğrulama hatası sayılır.', type: 'string', placeholder: '/api/auth/login,/api/authentication/login/' },
    ],
  },
  {
    title: '5xx Hata Sıçraması',
    icon: AlertOctagon,
    description: 'Host başına 5xx sayacı. Bir kez tetiklenir, sonra alarm bekleme süresine düşer, böylece kesintiler Slack\'i doldurmaz.',
    settings: [
      { key: 'correlation_error_spike_count', label: '5xx Sayısı', description: 'Tetiklenme için gereken sunucu hatası sayısı.', type: 'number', placeholder: '10' },
      { key: 'correlation_error_spike_window_seconds', label: 'Pencere', description: 'Kayan pencere boyutu.', type: 'number', placeholder: '60', unit: 'sn' },
    ],
  },
  {
    title: 'Trafik Anomalisi',
    icon: Activity,
    description: 'Host başına anlık RPS ile taban RPS karşılaştırması. Düşük ve orta trafikli hostlarda ani sıçramaları yakalamak için kullanışlıdır.',
    settings: [
      { key: 'correlation_anomaly_enabled', label: 'Açık', description: 'Eşiklerini kaybetmeden anomali kuralını açıp kapatır.', type: 'boolean' },
      { key: 'correlation_anomaly_ratio', label: 'Oran Eşiği', description: 'Tetiklenme için anlık RPS\'in taban RPS\'i bu katsayı kadar aşması gerekir.', type: 'string', placeholder: '3.0' },
      { key: 'correlation_anomaly_baseline_seconds', label: 'Taban Penceresi', description: 'Kayan taban penceresinin uzunluğu (ortalama için anlık olmayan kısım kullanılır).', type: 'number', placeholder: '600', unit: 'sn' },
      { key: 'correlation_anomaly_current_seconds', label: 'Anlık Pencere', description: 'Tabanla karşılaştırılan yakın aralık.', type: 'number', placeholder: '60', unit: 'sn' },
      { key: 'correlation_anomaly_min_baseline', label: 'Asgari Taban Olayı', description: 'Taban olayı bu sayının altında kalan hostlar atlanır, böylece küçük hostlar kolayca tetiklenmez.', type: 'number', placeholder: '20' },
    ],
  },
  {
    title: 'Hassas Erişim',
    icon: FileKey,
    description: 'Aynı IP\'den tanımlı kritik yollara çok sayıda istek gelince tetiklenir. Yolları boş bırakmak kuralı kapatır.',
    settings: [
      { key: 'correlation_sensitive_paths', label: 'Yollar', description: 'Virgülle ayrılmış glob desenleri (tek segment için * kullanın). Örn. /api/applications/*/generate_pdf_report/', type: 'string', placeholder: '/api/applications/*/generate_pdf_report/' },
      { key: 'correlation_sensitive_threshold', label: 'Eşik', description: 'Tetiklenme için pencere içindeki isabet sayısı.', type: 'number', placeholder: '10' },
      { key: 'correlation_sensitive_window_seconds', label: 'Pencere', description: 'Kayan pencere boyutu.', type: 'number', placeholder: '300', unit: 'sn' },
    ],
  },
  {
    title: 'Veri Dışa Aktarma Sıçraması',
    icon: Download,
    description: 'Kullanıcı başına dışa aktarma ve indirme hacmi. JWT kimliğine göre gruplanır (sub, user_id, email), yoksa IP kullanılır. IP değiştirmek içeriden gelen izi bölmez.',
    settings: [
      { key: 'correlation_export_pattern', label: 'Adres Deseni', description: 'Büyük küçük harf duyarsız regex (Go söz dizimi). Bu desene uyan yollar sıçrama sayımına dahil olur.', type: 'string', placeholder: '(?i)(download|export|report|\\.pdf|\\.xlsx|\\.csv)' },
      { key: 'correlation_export_threshold', label: 'Eşik', description: 'Tetiklenme için pencere içindeki eşleşen istek sayısı.', type: 'number', placeholder: '5' },
      { key: 'correlation_export_window_seconds', label: 'Pencere', description: 'Kayan pencere boyutu.', type: 'number', placeholder: '300', unit: 'sn' },
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
      toast.success(`${channel} testi gönderildi`)
    } catch (err) {
      // Show the backend message verbatim — Slack/SMTP errors (bad URL,
      // auth failure, unreachable host) are actionable and should not be
      // generic-toasted.
      toast.error(err instanceof api.ApiError ? err.message : `${channel} testi başarısız`)
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
      title={disabled ? 'Test etmeden önce bekleyen değişiklikleri kaydedin' : 'Bu kanaldan test alarmı gönder'}
    >
      {sending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" /> : <Send className="h-3.5 w-3.5 mr-2" />}
      Test Gönder
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
          {isDirty && <Badge variant="outline" className="text-[10px] text-yellow-400 border-yellow-400/40">kaydedilmedi</Badge>}
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
          title={isDirty ? 'Kaydet' : 'Değişiklik yok'}
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
        Uygulanan saklama politikası okunamadı.
      </p>
    )
  }
  if (!status) return null

  if (status.unavailable) {
    return (
      <p className="px-4 pb-3 text-xs text-muted-foreground">
        Bu kurulumda log hypertable yok, dolayısıyla burada saklama uygulayan bir şey de yok.
      </p>
    )
  }

  const policies = status.policies ?? []
  const describe = (p: api.RetentionPolicy) =>
    p.has_policy ? `${p.days} gün` : 'süresiz'

  return (
    <div className="px-4 pb-3 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-muted-foreground">Şu an diaLOG tarafından uygulanan:</span>
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
          Ayar {status.setting_days} gün diyor ama yukarıdaki politikalar farklı. diaLOG değişikliği
          birkaç saniye içinde uygular; bu böyle kalıyorsa diaLOG kapalıdır veya işleri değiştiremiyordur.
        </p>
      )}
    </div>
  )
}

// CompressionStatusPanel is the retention panel's twin: it reports what
// Timescale enforces plus how much of each table is already columnar, because
// raising the window does not decompress anything that was compressed under
// the old one.
function CompressionStatusPanel({ refreshKey }: { refreshKey: string }) {
  const [status, setStatus] = useState<api.CompressionStatus | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let cancelled = false
    const timers: ReturnType<typeof setTimeout>[] = []

    const fetchOnce = async () => {
      try {
        const s = await api.getCompressionStatus()
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
        Uygulanan sıkıştırma politikası okunamadı.
      </p>
    )
  }
  if (!status) return null

  if (status.unavailable) {
    return (
      <p className="px-4 pb-3 text-xs text-muted-foreground">
        Bu kurulumda log hypertable yok, dolayısıyla sıkıştırılacak bir şey de yok.
      </p>
    )
  }

  const policies = status.policies ?? []
  const wanted = (table: string) =>
    table === 'http_log_bodies' ? status.setting_bodies_days : status.setting_days

  return (
    <div className="px-4 pb-3 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-muted-foreground">Şu an diaLOG tarafından uygulanan:</span>
        {policies.map(p => (
          <Badge
            key={p.table}
            variant="outline"
            className={cn(
              'text-[10px] font-mono',
              (p.has_policy ? p.days : 0) === wanted(p.table)
                ? 'text-emerald-400 border-emerald-400/40'
                : 'text-yellow-400 border-yellow-400/40'
            )}
          >
            {p.table} {p.has_policy ? `${p.days} gün` : 'sıkıştırma yok'} · {p.compressed_chunks}/{p.chunks}
          </Badge>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        Rozetteki oran, sıkıştırılmış chunk sayısının toplama oranıdır. Süreyi büyütmek eski
        chunk'ları geri açmaz, yalnızca bundan sonrakilerin daha uzun beklemesini sağlar.
      </p>
      {!status.in_sync && (
        <p className="text-xs text-yellow-400">
          Ayarlar {status.setting_days} gün ve gövdeler için {status.setting_bodies_days} gün diyor
          ama yukarıdaki politikalar farklı. diaLOG değişikliği birkaç saniye içinde uygular; bu
          böyle kalıyorsa diaLOG kapalıdır veya işleri değiştiremiyordur.
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
      toast.error('Ayarlar yüklenemedi')
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
      toast.success(`${key} kaydedildi`)
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Kaydetme başarısız')
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
          <h1 className="text-xl font-bold text-foreground tracking-tight">Ayarlar</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Proxy ve SIEM davranışını yapılandırın</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon" onClick={load} className="h-9 w-9 cursor-pointer border-border">
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </Button>
          {allDirtyKeys.length > 0 && (
            <Button onClick={saveAll} className="gap-2 cursor-pointer">
              <Save className="h-4 w-4" />
              Tümünü Kaydet ({allDirtyKeys.length})
            </Button>
          )}
        </div>
      </div>

      {/* Sistem güncellemesi — en üstte, ayarlardan bağımsız panel */}
      <SystemUpgradePanel />

      <BackupPanel />

      {allDirtyKeys.length > 0 && (
        <div className="flex items-center gap-3 rounded-lg border border-yellow-400/30 bg-yellow-400/5 px-4 py-3 text-sm text-yellow-400">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{allDirtyKeys.length} kaydedilmemiş değişiklik. Kaydetmeyi unutmayın.</span>
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
              {group.extra === 'compression' && (
                <CompressionStatusPanel
                  refreshKey={`${savedValues['compression_days'] ?? ''}:${savedValues['compression_bodies_days'] ?? ''}`}
                />
              )}
            </div>
          ))}
        </div>
      )}

      <div className="rounded-lg border border-border bg-card px-4 py-4">
        <p className="text-xs text-muted-foreground">
          Ayarlar veri tabanına yazılır ve kendiliğinden devreye girer: MUVON ve diaLOG
          anlık görüntülerini birkaç saniyede bir yeniler. Panodaki{' '}
          <strong className="text-foreground">yapılandırmayı yenile</strong> düğmesi yalnızca bunu
          hemen zorlar ve anlık görüntüyü bağlı agentlara iletir. Saklama ve sıkıştırma, etkisi
          sürecin dışında yaşayan iki ayardır; yukarıdaki rozetler Timescale\'in gerçekte ne
          uyguladığını gösterir.
        </p>
      </div>
    </div>
  )
}
