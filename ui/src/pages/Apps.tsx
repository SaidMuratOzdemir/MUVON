import { useEffect, useMemo, useState } from 'react'
import { Rocket, RefreshCw, ShieldCheck, Server, GitBranch, Clock } from 'lucide-react'
import { toast } from 'sonner'
import * as api from '@/api'
import type { DeployProjectSummary, Deployment, DeploymentEvent } from '@/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { cn } from '@/lib/utils'

const statusTone: Record<string, string> = {
  pending: 'border-amber-400/40 text-amber-300 bg-amber-400/10',
  running: 'border-blue-400/40 text-blue-300 bg-blue-400/10',
  succeeded: 'border-emerald-400/40 text-emerald-300 bg-emerald-400/10',
  failed: 'border-red-400/40 text-red-300 bg-red-400/10',
  active: 'border-emerald-400/40 text-emerald-300 bg-emerald-400/10',
  warming: 'border-blue-400/40 text-blue-300 bg-blue-400/10',
  draining: 'border-amber-400/40 text-amber-300 bg-amber-400/10',
  unhealthy: 'border-red-400/40 text-red-300 bg-red-400/10',
  stopped: 'border-muted text-muted-foreground bg-muted/20',
}

export default function Apps() {
  const [projects, setProjects] = useState<DeployProjectSummary[]>([])
  const [deployments, setDeployments] = useState<Deployment[]>([])
  const [events, setEvents] = useState<DeploymentEvent[]>([])
  const [selectedDeployment, setSelectedDeployment] = useState<string>('')
  const [secretDrafts, setSecretDrafts] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)

  async function load() {
    setLoading(true)
    try {
      const [projectData, deploymentData] = await Promise.all([
        api.listDeployProjects(),
        api.listDeployments(50),
      ])
      setProjects(projectData)
      setDeployments(deploymentData)
      const first = selectedDeployment || deploymentData[0]?.id || ''
      if (first) {
        setSelectedDeployment(first)
        setEvents(await api.listDeploymentEvents(first))
      } else {
        setEvents([])
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Deployments could not be loaded')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const timer = window.setInterval(load, 10000)
    return () => window.clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function selectDeployment(id: string) {
    setSelectedDeployment(id)
    try {
      setEvents(await api.listDeploymentEvents(id))
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Events could not be loaded')
    }
  }

  async function saveSecret(project: DeployProjectSummary) {
    const secret = secretDrafts[project.project.slug]
    if (!secret) {
      toast.error('Webhook secret is required')
      return
    }
    try {
      await api.updateDeployProject(project.project.slug, { webhook_secret: secret })
      setSecretDrafts(prev => ({ ...prev, [project.project.slug]: '' }))
      toast.success('Webhook secret saved')
      await load()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Webhook secret could not be saved')
    }
  }

  const selected = useMemo(
    () => deployments.find(item => item.id === selectedDeployment),
    [deployments, selectedDeployment],
  )

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Apps</h1>
          <p className="text-sm text-muted-foreground mt-1">Managed releases, active containers, and deployment history.</p>
        </div>
        <Button variant="outline" onClick={load} disabled={loading}>
          <RefreshCw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        {projects.map(project => (
          <Card key={project.project.slug}>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Rocket className="h-4 w-4 text-primary" />
                {project.project.name}
                <Badge variant="outline" className="ml-auto">{project.project.slug}</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3 md:grid-cols-2">
                {project.components.map(component => {
                  const instances = project.instances.filter(instance => instance.component_id === component.id)
                  const active = instances.find(instance => instance.state === 'active')
                  return (
                    <div key={component.id} className="rounded-md border border-border p-3 space-y-2">
                      <div className="flex items-center gap-2">
                        <Server className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium">{component.slug}</span>
                        <Badge variant="outline" className={cn('ml-auto', statusTone[active?.state ?? 'stopped'])}>
                          {active?.state ?? 'no active'}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground break-all">{component.image_repo}</p>
                      <div className="text-xs text-muted-foreground">
                        Port {component.internal_port} · Health {component.health_path} · Retry {component.restart_retries}
                      </div>
                      {active && (
                        <div className="text-xs">
                          <span className="text-muted-foreground">Release </span>
                          <span className="font-mono">{active.release_id || active.release_uuid?.slice(0, 8)}</span>
                          <span className="text-muted-foreground"> · In flight {active.in_flight}</span>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>

              <div className="flex flex-col gap-2 sm:flex-row">
                <Input
                  type="password"
                  placeholder="New webhook secret"
                  value={secretDrafts[project.project.slug] ?? ''}
                  onChange={event => setSecretDrafts(prev => ({ ...prev, [project.project.slug]: event.target.value }))}
                />
                <Button onClick={() => saveSecret(project)} className="sm:w-40">
                  <ShieldCheck className="h-4 w-4 mr-2" />
                  Save Secret
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <GitBranch className="h-4 w-4 text-primary" />
              Deployments
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Project</TableHead>
                  <TableHead>Release</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {deployments.map(deployment => (
                  <TableRow
                    key={deployment.id}
                    className="cursor-pointer"
                    onClick={() => selectDeployment(deployment.id)}
                  >
                    <TableCell>{deployment.project_slug}</TableCell>
                    <TableCell className="font-mono text-xs">{deployment.release_id.slice(0, 12)}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={statusTone[deployment.status]}>
                        {deployment.status}
                      </Badge>
                    </TableCell>
                    <TableCell>{deployment.trigger}</TableCell>
                    <TableCell className="text-muted-foreground">{new Date(deployment.created_at).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
                {deployments.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                      No deployments yet
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Clock className="h-4 w-4 text-primary" />
              Timeline
            </CardTitle>
          </CardHeader>
          <CardContent>
            {selected && (
              <div className="mb-4 rounded-md border border-border p-3">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={statusTone[selected.status]}>{selected.status}</Badge>
                  <span className="font-mono text-xs">{selected.release_id.slice(0, 12)}</span>
                </div>
                {selected.error && <p className="text-sm text-red-300 mt-2">{selected.error}</p>}
              </div>
            )}
            <div className="space-y-3">
              {events.map(event => (
                <div key={event.id} className="border-l border-border pl-3">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{event.event_type}</span>
                    <span className="text-xs text-muted-foreground">{new Date(event.created_at).toLocaleTimeString()}</span>
                  </div>
                  <p className="text-sm text-muted-foreground">{event.message}</p>
                </div>
              ))}
              {events.length === 0 && (
                <p className="text-sm text-muted-foreground">Select a deployment to see events.</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
