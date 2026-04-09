import { useState, useEffect, useCallback } from 'react'
import * as api from '@/api'
import type { ServiceHealth } from '@/types'

export interface ServiceStatus {
  health: ServiceHealth | null
  loading: boolean
  wafOnline: boolean
  logOnline: boolean
  dbOnline: boolean
}

export function useServiceHealth(intervalMs = 30_000): ServiceStatus {
  const [health, setHealth] = useState<ServiceHealth | null>(null)
  const [loading, setLoading] = useState(true)

  const check = useCallback(async () => {
    try {
      const h = await api.health()
      setHealth(h)
    } catch {
      setHealth(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    check()
    const t = setInterval(check, intervalMs)
    return () => clearInterval(t)
  }, [check, intervalMs])

  return {
    health,
    loading,
    wafOnline: health?.services?.waf === 'ok',
    logOnline: health?.services?.logging === 'ok',
    dbOnline: health?.services?.database === 'ok',
  }
}
