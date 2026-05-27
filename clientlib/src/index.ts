// MUVON browser telemetry (RUM). Ships batched events to /__muvon/rum on the
// same origin the page is served from. Not an independent SDK — it talks only
// to the muvon edge and is versioned with it.
//
// Design: self-configuring (reads its own <script> tag + window.__muvonRum),
// fail-quiet (any internal error must never break the host page), and cheap
// (sendBeacon, capped batches, drop-on-overflow). trace_id is read from the
// edge's Server-Timing header so a browser event joins http_logs.

const SDK = 'muvon-rum/0.2.0'
const MAX_BATCH_EVENTS = 50
const FLUSH_INTERVAL_MS = 5000
const ATTR_MAX_LEN = 1024

interface RumConfig {
  app?: string
  release?: string
  collector?: string // base URL; defaults to same origin
}

interface SampleConfig {
  sample_rates: Record<string, number>
  max_batch_bytes: number
}

interface MvEvent {
  event_name: string
  ts: number
  trace_id?: string
  span_id?: string
  attrs?: Record<string, string>
}

// W3C traceparent inside a Server-Timing entry: traceparent;desc="00-<t>-<s>-01".
const traceRe = /traceparent;desc="00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}"/i

let app = ''
let release = ''
let collector = ''
let sessionId = ''
let viewId = ''
let route = ''
let userId = '' // set via muvon.identify; attached to every envelope once known
let userTraits: Record<string, string> = {}
let maxBatchBytes = 65536
let sampleRates: Record<string, number> = { default: 1 }
let queue: MvEvent[] = []
let flushTimer: number | undefined
let started = false

// ---- utilities -------------------------------------------------------------

function uuid(): string {
  try {
    return crypto.randomUUID()
  } catch {
    // Pre-randomUUID browsers: good-enough non-crypto id for correlation.
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16)
    })
  }
}

// quiet wraps a callback so an instrumentation bug never throws into host code.
function quiet(fn: () => void): void {
  try {
    fn()
  } catch {
    /* swallow — telemetry must not break the page */
  }
}

function scriptConfig(): RumConfig {
  const w = window as unknown as { __muvonRum?: RumConfig }
  const cfg: RumConfig = { ...(w.__muvonRum || {}) }
  const el = document.currentScript as HTMLScriptElement | null
  if (el) {
    if (!cfg.app && el.dataset.app) cfg.app = el.dataset.app
    if (!cfg.release && el.dataset.release) cfg.release = el.dataset.release
    if (!cfg.collector && el.src) {
      try {
        cfg.collector = new URL(el.src).origin
      } catch {
        /* keep same-origin default */
      }
    }
  }
  return cfg
}

function sessionStore(): string {
  const key = 'mv_sid'
  try {
    let sid = sessionStorage.getItem(key)
    if (!sid) {
      sid = uuid()
      sessionStorage.setItem(key, sid)
    }
    return sid
  } catch {
    // Private mode / blocked storage: per-load id, still groups one page view.
    return uuid()
  }
}

function clampAttrs(attrs?: Record<string, unknown>): Record<string, string> | undefined {
  if (!attrs) return undefined
  const out: Record<string, string> = {}
  for (const k of Object.keys(attrs)) {
    const v = attrs[k]
    if (v === undefined || v === null) continue
    let s = typeof v === 'string' ? v : String(v)
    if (s.length > ATTR_MAX_LEN) s = s.slice(0, ATTR_MAX_LEN)
    out[k] = s
  }
  return Object.keys(out).length ? out : undefined
}

function sampled(eventName: string): boolean {
  const rate = eventName in sampleRates ? sampleRates[eventName] : sampleRates.default ?? 1
  if (rate >= 1) return true
  if (rate <= 0) return false
  return Math.random() < rate
}

// ---- queue + flush ---------------------------------------------------------

function emit(eventName: string, attrs?: Record<string, unknown>, trace?: { trace_id?: string; span_id?: string }): void {
  if (!sampled(eventName)) return
  const ev: MvEvent = { event_name: eventName, ts: Date.now() }
  const a = clampAttrs(attrs)
  if (a) ev.attrs = a
  if (trace?.trace_id) ev.trace_id = trace.trace_id
  if (trace?.span_id) ev.span_id = trace.span_id
  queue.push(ev)

  if (queue.length >= MAX_BATCH_EVENTS) {
    flush(false)
    return
  }
  if (flushTimer === undefined) {
    flushTimer = window.setTimeout(() => flush(false), FLUSH_INTERVAL_MS)
  }
}

function buildBody(events: MvEvent[]): string {
  const envelope: Record<string, unknown> = {
    resource: { app, release, sdk: SDK },
    session: { session_id: sessionId },
    view: { view_id: viewId, route, url_path: location.pathname },
    events,
  }
  // Identity, once muvon.identify has run. Forward-compatible: the edge
  // ignores an unknown block today; a later release can join every event to
  // a user without the client re-sending it per event.
  if (userId) envelope.user = { id: userId, ...userTraits }
  return JSON.stringify(envelope)
}

// flush ships the current queue. useBeacon=true on page hide (sendBeacon
// survives unload); otherwise a keepalive fetch so we can keep going.
function flush(useBeacon: boolean): void {
  if (flushTimer !== undefined) {
    clearTimeout(flushTimer)
    flushTimer = undefined
  }
  if (queue.length === 0) return

  // Split into <=maxBatchBytes chunks so a single beacon never exceeds the
  // edge's cap (and the browser's sendBeacon limit). text/plain avoids a
  // cross-origin preflight; the edge accepts it.
  const pending = queue
  queue = []
  let batch: MvEvent[] = []
  const send = (events: MvEvent[]) => {
    if (events.length === 0) return
    const body = buildBody(events)
    const url = collector + '/__muvon/rum'
    quiet(() => {
      if (useBeacon && navigator.sendBeacon) {
        navigator.sendBeacon(url, new Blob([body], { type: 'text/plain;charset=UTF-8' }))
      } else {
        void fetch(url, {
          method: 'POST',
          body,
          headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
          keepalive: true,
          credentials: 'omit',
        }).catch(() => {})
      }
    })
  }

  for (const ev of pending) {
    batch.push(ev)
    if (buildBody(batch).length >= maxBatchBytes) {
      const last = batch.pop()!
      send(batch)
      batch = [last]
    }
  }
  send(batch)
}

// ---- trace correlation -----------------------------------------------------

function parseTrace(serverTiming: string | null): { trace_id?: string; span_id?: string } | undefined {
  if (!serverTiming) return undefined
  const m = traceRe.exec(serverTiming)
  if (!m) return undefined
  return { trace_id: m[1].toLowerCase(), span_id: m[2].toLowerCase() }
}

// ---- instrumentation -------------------------------------------------------

function instrumentFetch(): void {
  const orig = window.fetch
  if (typeof orig !== 'function') return
  window.fetch = function (this: unknown, ...args: Parameters<typeof fetch>): Promise<Response> {
    const start = performance.now()
    return orig.apply(this, args).then(
      (res) => {
        quiet(() => {
          const trace = parseTrace(res.headers.get('Server-Timing'))
          const dur = Math.round(performance.now() - start)
          // Only record notable fetches: errors, or any with a trace to join.
          if (res.status >= 400 || trace) {
            emit('fetch', { status: String(res.status), duration_ms: dur, url: reqUrl(args[0]) }, trace)
          }
        })
        return res
      },
      (err: unknown) => {
        quiet(() => {
          const dur = Math.round(performance.now() - start)
          emit('fetch', { status: 'error', duration_ms: dur, url: reqUrl(args[0]), error: errMsg(err) })
        })
        throw err
      },
    )
  } as typeof fetch
}

function reqUrl(input: unknown): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.href
  if (input instanceof Request) return input.url
  return ''
}

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message
  return String(e)
}

function instrumentXHR(): void {
  const proto = XMLHttpRequest.prototype
  const origOpen = proto.open
  const origSend = proto.send
  proto.open = function (this: XMLHttpRequest, _method: string, url: string | URL) {
    ;(this as unknown as { __mvUrl?: string }).__mvUrl = typeof url === 'string' ? url : url.href
    // eslint-disable-next-line prefer-rest-params
    return origOpen.apply(this, arguments as unknown as Parameters<typeof origOpen>)
  }
  proto.send = function (this: XMLHttpRequest, ...sendArgs: unknown[]) {
    const start = performance.now()
    this.addEventListener('loadend', () => {
      quiet(() => {
        const trace = parseTrace(this.getResponseHeader('Server-Timing'))
        const dur = Math.round(performance.now() - start)
        const url = (this as unknown as { __mvUrl?: string }).__mvUrl || ''
        if (this.status === 0 || this.status >= 400 || trace) {
          emit('fetch', { status: this.status ? String(this.status) : 'error', duration_ms: dur, url }, trace)
        }
      })
    })
    return origSend.apply(this, sendArgs as unknown as Parameters<typeof origSend>)
  }
}

function instrumentErrors(): void {
  window.addEventListener('error', (e: ErrorEvent | Event) => {
    quiet(() => {
      const ee = e as ErrorEvent
      // Resource load failures surface as error events on the element.
      if (e.target && e.target !== window && (e.target as HTMLElement).tagName) {
        const el = e.target as HTMLElement
        const src = (el as HTMLImageElement | HTMLScriptElement).src || (el as HTMLLinkElement).href || ''
        emit('resource_error', { tag: el.tagName.toLowerCase(), url: src })
        return
      }
      emit('js_error', {
        message: ee.message || 'error',
        source: ee.filename || '',
        line: ee.lineno != null ? String(ee.lineno) : '',
        stack: ee.error instanceof Error ? ee.error.stack || '' : '',
      })
    })
  }, true)

  window.addEventListener('unhandledrejection', (e: PromiseRejectionEvent) => {
    quiet(() => {
      const reason = e.reason
      emit('unhandled_rejection', {
        message: reason instanceof Error ? reason.message : String(reason),
        stack: reason instanceof Error ? reason.stack || '' : '',
      })
    })
  })
}

function observe(type: string, cb: (entries: PerformanceEntryList) => void): void {
  quiet(() => {
    const po = new PerformanceObserver((list) => quiet(() => cb(list.getEntries())))
    // buffered surfaces entries that fired before we attached.
    po.observe({ type, buffered: true } as PerformanceObserverInit)
  })
}

function instrumentWebVitals(): void {
  // FCP / LCP — paint + largest-contentful-paint.
  observe('paint', (entries) => {
    for (const e of entries) {
      if (e.name === 'first-contentful-paint') {
        emit('web_vital', { metric: 'FCP', value: String(Math.round(e.startTime)) })
      }
    }
  })
  let lcp = 0
  observe('largest-contentful-paint', (entries) => {
    const last = entries[entries.length - 1]
    if (last) lcp = Math.round(last.startTime)
  })
  // CLS — sum of layout shifts without recent input.
  let cls = 0
  observe('layout-shift', (entries) => {
    for (const e of entries) {
      const ls = e as PerformanceEntry & { value: number; hadRecentInput: boolean }
      if (!ls.hadRecentInput) cls += ls.value
    }
  })
  // INP approximation — worst event latency observed.
  let inp = 0
  observe('event', (entries) => {
    for (const e of entries) {
      const ev = e as PerformanceEntry & { duration: number }
      if (ev.duration > inp) inp = ev.duration
    }
  })
  // TTFB from navigation timing.
  observe('navigation', (entries) => {
    const nav = entries[0] as PerformanceNavigationTiming | undefined
    if (nav) emit('web_vital', { metric: 'TTFB', value: String(Math.round(nav.responseStart)) })
  })
  // Flush the cumulative vitals (LCP/CLS/INP) once, when the page is hidden.
  const reportFinal = () => {
    if (lcp > 0) emit('web_vital', { metric: 'LCP', value: String(lcp) })
    emit('web_vital', { metric: 'CLS', value: cls.toFixed(4) })
    if (inp > 0) emit('web_vital', { metric: 'INP', value: String(Math.round(inp)) })
  }
  let reported = false
  const once = () => {
    if (reported) return
    reported = true
    quiet(reportFinal)
  }
  addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') once()
  })
  addEventListener('pagehide', once)
}

function newView(): void {
  viewId = uuid()
  route = location.pathname
  emit('route_change', { url_path: location.pathname })
}

function instrumentHistory(): void {
  const wrap = (name: 'pushState' | 'replaceState') => {
    const orig = history[name]
    history[name] = function (this: History, ...a: unknown[]) {
      const r = orig.apply(this, a as Parameters<typeof orig>)
      quiet(newView)
      return r
    } as typeof orig
  }
  wrap('pushState')
  wrap('replaceState')
  addEventListener('popstate', () => quiet(newView))
}

function instrumentLifecycle(): void {
  addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      emit('visibility', { state: 'hidden' })
      flush(true)
    }
  })
  addEventListener('pagehide', () => {
    emit('pagehide')
    flush(true)
  })
}

// data-mv-* convention: [data-mv-error] appearing in the DOM signals a
// rendered error state (e.g. a form validation message). [data-mv-track]
// fires a named custom event on click.
function instrumentDataAttrs(): void {
  const scanError = (el: Element) => {
    if (el.hasAttribute && el.hasAttribute('data-mv-error')) {
      emit('dom_error', {
        error_code: el.getAttribute('data-mv-error-code') || '',
        text: (el.textContent || '').trim().slice(0, 200),
      })
    }
  }
  quiet(() => {
    const mo = new MutationObserver((muts) => {
      quiet(() => {
        for (const m of muts) {
          m.addedNodes.forEach((n) => {
            if (n.nodeType === 1) {
              const el = n as Element
              scanError(el)
              el.querySelectorAll?.('[data-mv-error]').forEach(scanError)
            }
          })
        }
      })
    })
    mo.observe(document.documentElement, { childList: true, subtree: true })
  })

  addEventListener('click', (e) => {
    quiet(() => {
      let el = e.target as Element | null
      while (el && el !== document.documentElement) {
        if (el.hasAttribute && el.hasAttribute('data-mv-track')) {
          emit('custom', { name: el.getAttribute('data-mv-track') || '' })
          return
        }
        el = el.parentElement
      }
    })
  }, true)
}

// ---- public imperative API -------------------------------------------------

// track records a structured custom event at the call site — the imperative
// counterpart to data-mv-track. Mapped onto the existing 'custom' schema
// ({name, ...attrs}) so it reuses sampling, envelope, batching and ingest.
function track(name: string, attrs?: Record<string, unknown>): void {
  quiet(() => {
    if (!name) return
    emit('custom', { name, ...(attrs || {}) })
  })
}

// identify binds a stable id (+ optional traits) to this session: it emits an
// 'identify' event (captured like any other) and attaches a user block to
// every subsequent envelope. The consumer decides what is safe to send.
function identify(id: string, traits?: Record<string, unknown>): void {
  quiet(() => {
    if (!id) return
    userId = String(id)
    userTraits = clampAttrs(traits) || {}
    emit('identify', { user_id: userId, ...userTraits })
  })
}

// dispatch routes a verb-first call (the GA-style stub form
// muvon('track', name, attrs)) to the typed methods.
function dispatch(verb: string, args: unknown[]): void {
  if (verb === 'track') track(args[0] as string, args[1] as Record<string, unknown> | undefined)
  else if (verb === 'identify') identify(args[0] as string, args[1] as Record<string, unknown> | undefined)
}

// installPublicApi swaps the async-safe stub (window.muvon = a queueing
// function with a .q buffer) for the real API. The replacement is callable
// (muvon('track', ...)) AND exposes methods (muvon.track(...)); any calls that
// arrived before this bundle loaded are drained from the stub's queue.
function installPublicApi(): void {
  const w = window as unknown as { muvon?: { q?: ArrayLike<unknown>[] } }
  const queued: ArrayLike<unknown>[] = (w.muvon && w.muvon.q) || []
  const api = function (verb: unknown, ...rest: unknown[]): void {
    dispatch(String(verb), rest)
  } as ((...a: unknown[]) => void) & {
    track: typeof track
    identify: typeof identify
    q: ArrayLike<unknown>[]
  }
  api.track = track
  api.identify = identify
  api.q = []
  ;(w as unknown as { muvon: unknown }).muvon = api
  for (const call of queued) {
    const a = Array.from(call)
    quiet(() => dispatch(String(a[0]), a.slice(1)))
  }
}

// ---- bootstrap -------------------------------------------------------------

async function loadConfig(): Promise<void> {
  try {
    const res = await fetch(collector + '/__muvon/rum/config', { credentials: 'omit' })
    if (res.ok) {
      const cfg = (await res.json()) as Partial<SampleConfig>
      if (cfg.sample_rates && typeof cfg.sample_rates === 'object') sampleRates = cfg.sample_rates
      if (typeof cfg.max_batch_bytes === 'number' && cfg.max_batch_bytes > 0) maxBatchBytes = cfg.max_batch_bytes
    }
  } catch {
    /* keep defaults — telemetry still works without remote config */
  }
}

function start(): void {
  if (started) return
  started = true
  quiet(() => {
    const cfg = scriptConfig()
    app = cfg.app || location.hostname
    release = cfg.release || ''
    collector = (cfg.collector || location.origin).replace(/\/+$/, '')
    sessionId = sessionStore()
    viewId = uuid()
    route = location.pathname

    // Patch transports before anything else so early requests are captured.
    instrumentFetch()
    instrumentXHR()
    instrumentErrors()
    instrumentWebVitals()
    instrumentHistory()
    instrumentLifecycle()
    instrumentDataAttrs()

    emit('page_view', { referrer: document.referrer || '' })

    // Expose the imperative API (muvon.track / muvon.identify) and replay any
    // calls the page buffered through the async-safe stub before we loaded.
    installPublicApi()

    // Remote sample config can downgrade what we send; fetch it in the
    // background so startup is never blocked on it.
    void loadConfig()
  })
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start)
} else {
  start()
}
