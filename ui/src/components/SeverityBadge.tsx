import { AlertCircle, AlertTriangle, Info } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { SEVERITY_COLORS, SEVERITY_LABELS } from '@/lib/alerts'

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const Icon = severity === 'critical' || severity === 'high' ? AlertCircle : severity === 'warning' ? AlertTriangle : Info
  return (
    <Badge variant="outline" className={cn('gap-1', SEVERITY_COLORS[severity] ?? '', className)}>
      <Icon className="h-3 w-3" />
      {SEVERITY_LABELS[severity] ?? severity}
    </Badge>
  )
}
