import { ServerOff, SearchX, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface Props {
  variant?: 'no-data' | 'service-offline'
  icon?: LucideIcon
  title: string
  description?: string
  action?: React.ReactNode
  className?: string
}

export function EmptyState({
  variant = 'no-data',
  icon: Icon,
  title,
  description,
  action,
  className,
}: Props) {
  const DefaultIcon = variant === 'service-offline' ? ServerOff : SearchX

  const FinalIcon = Icon ?? DefaultIcon

  return (
    <div className={cn('flex flex-col items-center justify-center py-16 px-4 text-center', className)}>
      <div
        className={cn(
          'flex h-16 w-16 items-center justify-center rounded-2xl mb-5',
          variant === 'service-offline'
            ? 'bg-amber-500/10 border border-amber-500/20'
            : 'bg-muted/50 border border-border',
        )}
      >
        <FinalIcon
          className={cn(
            'h-7 w-7',
            variant === 'service-offline' ? 'text-amber-400' : 'text-muted-foreground/50',
          )}
        />
      </div>
      <h3
        className={cn(
          'text-sm font-semibold',
          variant === 'service-offline' ? 'text-amber-400' : 'text-foreground',
        )}
      >
        {title}
      </h3>
      {description && (
        <p className="text-xs text-muted-foreground mt-1.5 max-w-xs">{description}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
