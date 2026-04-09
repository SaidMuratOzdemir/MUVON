import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Activity, Eye, EyeOff, Loader2, Lock, User } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import * as api from '@/api'

export default function Login() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [showPw, setShowPw] = useState(false)
  const [loginForm, setLoginForm] = useState({ username: '', password: '' })
  const [setupForm, setSetupForm] = useState({ username: '', password: '', confirm: '' })

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault()
    if (!loginForm.username || !loginForm.password) {
      toast.error('Please fill in all fields')
      return
    }
    setLoading(true)
    try {
      const { token } = await api.login(loginForm.username, loginForm.password)
      localStorage.setItem('dialog_token', token)
      navigate('/', { replace: true })
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleSetup(e: React.FormEvent) {
    e.preventDefault()
    if (!setupForm.username || !setupForm.password) {
      toast.error('Please fill in all fields')
      return
    }
    if (setupForm.password !== setupForm.confirm) {
      toast.error('Passwords do not match')
      return
    }
    if (setupForm.password.length < 8) {
      toast.error('Password must be at least 8 characters')
      return
    }
    setLoading(true)
    try {
      const { token } = await api.setup(setupForm.username, setupForm.password)
      localStorage.setItem('dialog_token', token)
      toast.success('Admin account created')
      navigate('/', { replace: true })
    } catch (err) {
      toast.error(err instanceof api.ApiError ? err.message : 'Setup failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,hsl(217_33%_17%/0.15)_1px,transparent_1px),linear-gradient(to_bottom,hsl(217_33%_17%/0.15)_1px,transparent_1px)] bg-[size:4rem_4rem]" />
      <div className="relative w-full max-w-md space-y-6">
        <div className="flex flex-col items-center gap-3 text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 border border-primary/30 glow-box">
            <Activity className="h-7 w-7 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground tracking-tight glow-green">DiaLog</h1>
            <p className="text-sm text-muted-foreground mt-1">Reverse Proxy + SIEM Platform</p>
          </div>
        </div>

        <Tabs defaultValue="login" className="w-full">
          <TabsList className="grid w-full grid-cols-2 bg-card border border-border">
            <TabsTrigger value="login" className="cursor-pointer">Sign In</TabsTrigger>
            <TabsTrigger value="setup" className="cursor-pointer">First Setup</TabsTrigger>
          </TabsList>

          <TabsContent value="login">
            <Card className="border-border bg-card/80 backdrop-blur-sm">
              <CardHeader className="pb-4">
                <CardTitle className="text-lg">Welcome back</CardTitle>
                <CardDescription>Sign in to your admin account</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleLogin} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="login-username">Username</Label>
                    <div className="relative">
                      <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                      <Input
                        id="login-username"
                        placeholder="admin"
                        className="pl-9 bg-background border-border"
                        value={loginForm.username}
                        onChange={e => setLoginForm(f => ({ ...f, username: e.target.value }))}
                        autoComplete="username"
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="login-password">Password</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                      <Input
                        id="login-password"
                        type={showPw ? 'text' : 'password'}
                        placeholder="••••••••"
                        className="pl-9 pr-9 bg-background border-border"
                        value={loginForm.password}
                        onChange={e => setLoginForm(f => ({ ...f, password: e.target.value }))}
                        autoComplete="current-password"
                      />
                      <button
                        type="button"
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground cursor-pointer transition-colors"
                        onClick={() => setShowPw(v => !v)}
                      >
                        {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>
                  <Button type="submit" className="w-full cursor-pointer" disabled={loading}>
                    {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    {loading ? 'Signing in…' : 'Sign In'}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="setup">
            <Card className="border-border bg-card/80 backdrop-blur-sm">
              <CardHeader className="pb-4">
                <CardTitle className="text-lg">Initial Setup</CardTitle>
                <CardDescription>Create the first admin account (one-time only)</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSetup} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="setup-username">Username</Label>
                    <div className="relative">
                      <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                      <Input
                        id="setup-username"
                        placeholder="admin"
                        className="pl-9 bg-background border-border"
                        value={setupForm.username}
                        onChange={e => setSetupForm(f => ({ ...f, username: e.target.value }))}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="setup-password">Password</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                      <Input
                        id="setup-password"
                        type={showPw ? 'text' : 'password'}
                        placeholder="Min. 8 characters"
                        className="pl-9 pr-9 bg-background border-border"
                        value={setupForm.password}
                        onChange={e => setSetupForm(f => ({ ...f, password: e.target.value }))}
                      />
                      <button
                        type="button"
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground cursor-pointer transition-colors"
                        onClick={() => setShowPw(v => !v)}
                      >
                        {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="setup-confirm">Confirm Password</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                      <Input
                        id="setup-confirm"
                        type={showPw ? 'text' : 'password'}
                        placeholder="Repeat password"
                        className="pl-9 bg-background border-border"
                        value={setupForm.confirm}
                        onChange={e => setSetupForm(f => ({ ...f, confirm: e.target.value }))}
                      />
                    </div>
                  </div>
                  <Button type="submit" className="w-full cursor-pointer" disabled={loading}>
                    {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    {loading ? 'Creating…' : 'Create Admin Account'}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        <p className="text-center text-xs text-muted-foreground">
          DiaLog &mdash; Production Reverse Proxy &amp; SIEM
        </p>
      </div>
    </div>
  )
}
