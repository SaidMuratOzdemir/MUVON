import type { AlertDeliveryMode, AlertSeverity, AlertTrigger } from '@/types'

export const SEVERITIES: AlertSeverity[] = ['info', 'warning', 'high', 'critical']

export const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Kritik',
  high: 'Yüksek',
  warning: 'Uyarı',
  info: 'Bilgi',
}

export const SEVERITY_COLORS: Record<string, string> = {
  info: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  warning: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  critical: 'bg-red-500/10 text-red-400 border-red-500/20',
}

export const DELIVERY_LABELS: Record<AlertDeliveryMode, string> = {
  instant: 'Anında',
  digest: 'Günlük özet',
  none: 'Yalnız kayıt',
}

export function formatDateTime(value?: string): string {
  if (!value) return ''
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return ''
  return d.toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export function humanWindow(seconds?: number): string {
  if (!seconds || seconds <= 0) return ''
  if (seconds % 86400 === 0) return `${seconds / 86400} gün`
  if (seconds % 3600 === 0) return `${seconds / 3600} saat`
  if (seconds % 60 === 0) return `${seconds / 60} dakika`
  return `${seconds} saniye`
}

export function describeTrigger(t: AlertTrigger): string {
  if (t.type === 'count') return `${humanWindow(t.window_seconds)} içinde ${t.count} olay`
  if (t.type === 'distinct') return `${humanWindow(t.window_seconds)} içinde ${t.count} farklı ${t.field}`
  if (t.type === 'baseline') {
    return `son 24 saat, ${t.baseline_days} günlük ortalamanın ${t.ratio} katını aşarsa (en az ${t.count})`
  }
  return 'her olayda'
}
