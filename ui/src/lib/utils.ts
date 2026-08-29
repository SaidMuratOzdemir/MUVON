import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
}

export function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m ${seconds % 60}s`
}

export function formatNumber(n: number): string {
  if (n == null || isNaN(n)) return '0'
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return n.toString()
}

// A timestamp handed to this helper can sit on either side of now: most are in
// the past, but an expiry is not. Reading the sign keeps a future date from
// rendering as a negative age.
export function relativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime()
  const future = diff < 0
  const fmt = (n: number, unit: string) => (future ? `in ${n}${unit}` : `${n}${unit} ago`)
  const seconds = Math.floor(Math.abs(diff) / 1000)
  if (seconds < 60) return fmt(seconds, 's')
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return fmt(minutes, 'm')
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return fmt(hours, 'h')
  return fmt(Math.floor(hours / 24), 'd')
}

export function statusClass(status: number): string {
  if (status < 300) return 'status-2xx'
  if (status < 400) return 'status-3xx'
  if (status < 500) return 'status-4xx'
  return 'status-5xx'
}

export function statusBadgeVariant(status: number): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (status < 300) return 'default'
  if (status < 400) return 'secondary'
  if (status < 500) return 'outline'
  return 'destructive'
}

// `datetime-local` inputs yield "2026-08-23T14:30" in the operator's own
// timezone. Every API time bound takes RFC3339 and refuses anything else, so
// the conversion belongs at the call site rather than sending the raw value.
export function toRFC3339(local: string): string {
  const d = new Date(local)
  return isNaN(d.getTime()) ? '' : d.toISOString()
}
