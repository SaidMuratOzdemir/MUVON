import { AlertTriangle } from 'lucide-react'
import { cn } from '@/lib/utils'

interface Props {
  wafOnline: boolean
  logOnline: boolean
  className?: string
}

export function ServiceBanner({ wafOnline, logOnline, className }: Props) {
  const offlineServices: string[] = []
  if (!wafOnline) offlineServices.push('muWAF')
  if (!logOnline) offlineServices.push('diaLOG')

  if (offlineServices.length === 0) return null

  return (
    <div
      className={cn(
        'flex items-center gap-3 px-4 py-2.5 text-sm border-b',
        'bg-amber-500/8 border-amber-500/20 text-amber-400',
        className,
      )}
    >
      <AlertTriangle className="h-4 w-4 shrink-0" />
      <span className="font-medium">
        {offlineServices.join(' & ')} servisi su anda cevrimdisi
      </span>
      <span className="text-amber-400/60 text-xs ml-auto">
        Ilgili sayfalar kisitli calisabilir
      </span>
    </div>
  )
}
