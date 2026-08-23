package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"muvon/internal/db"
)

// rewriteCache caches compiled regexps keyed by pattern string.
var rewriteCache sync.Map // string → *regexp.Regexp

func getRewriteRegexp(pattern string) (*regexp.Regexp, error) {
	if v, ok := rewriteCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	v, _ := rewriteCache.LoadOrStore(pattern, re)
	return v.(*regexp.Regexp), nil
}

// Rewrite builds the outbound request for the reverse proxy.
//
// This is a Rewrite hook rather than a Director on purpose. With a Director,
// net/http/httputil appends the TCP peer to X-Forwarded-For *after* the hook
// returns, which the hook cannot prevent or observe. That produced a duplicated
// entry for direct clients ("1.2.3.4, 1.2.3.4") and, behind a CDN, left the CDN
// edge as the final hop — so a backend that reads the chain right-to-left
// (uvicorn, Rails, ASP.NET all do) picked the CDN as the client. The Rewrite
// hook owns the forwarding headers outright, so what we build is what is sent.
func Rewrite(target *url.URL, stripPrefix string, route db.Route, clientIP string, trustedUpstream bool) func(*httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		in, req := pr.In, pr.Out
		originalHost := in.Host // orijinal host (incoming)

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host

		path := req.URL.Path
		if stripPrefix != "" && stripPrefix != "/" {
			path = strings.TrimPrefix(path, stripPrefix)
			if path == "" {
				path = "/"
			}
		}

		if target.Path != "" && target.Path != "/" {
			path = singleJoiningSlash(target.Path, path)
		}

		// Regex URL rewriting: apply before forwarding to backend.
		if route.RewritePattern != nil && route.RewriteTo != nil {
			if re, err := getRewriteRegexp(*route.RewritePattern); err == nil {
				path = re.ReplaceAllString(path, *route.RewriteTo)
			}
		}

		req.URL.Path = path

		if target.RawQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
		}

		// Drop Accept-Encoding so the backend answers uncompressed; our own
		// middleware does the gzip.
		req.Header.Del("Accept-Encoding")

		// X-Forwarded-For is the hop chain, oldest first: keep what a trusted
		// upstream reported and append the peer this request arrived from. This
		// is the append semantics every major proxy implements (nginx's
		// $proxy_add_x_forwarded_for, Envoy, HAProxy, Cloudflare, ALB), and it
		// keeps the chain intact for auditing and for backends that count hops.
		//
		// Two details carry weight:
		//   - The peer is appended, not the resolved client IP. Appending the
		//     resolved address repeats it whenever the peer *is* the client.
		//   - A chain offered by an untrusted peer is client-controlled and is
		//     dropped outright, so a forged leftmost entry cannot reach a backend.
		//
		// The chain alone is not enough for a backend to identify the client: it
		// would have to know which hops are proxies. X-Real-IP below answers that
		// authoritatively.
		peer := peerHost(in)
		chain := peer
		if trustedUpstream {
			if prior := in.Header.Values("X-Forwarded-For"); len(prior) > 0 {
				chain = strings.Join(prior, ", ") + ", " + peer
			}
		}
		req.Header.Set("X-Forwarded-For", chain)

		// X-Real-IP is the authoritative answer: the client address this edge
		// resolved, having validated the CDN's shared secret or the configured
		// trusted-proxy list. Applications behind MUVON read this single value
		// and never have to reason about chain length or CDN address ranges.
		req.Header.Set("X-Real-IP", clientIP)

		// The inbound scheme claim is only honoured from a trusted upstream;
		// otherwise a plain-HTTP client could assert "https" and mislead a
		// backend that derives request security from it.
		req.Header.Set("X-Forwarded-Proto", schemeFor(in, trustedUpstream))
		req.Header.Set("X-Forwarded-Host", originalHost)

		// Per-route request header manipulation
		for _, h := range route.ReqHeadersDel {
			req.Header.Del(h)
		}
		for k, v := range route.ReqHeadersAdd {
			// The Host header is set through req.Host, not req.Header.
			if strings.EqualFold(k, "host") {
				req.Host = v
			} else {
				req.Header.Set(k, v)
			}
		}
	}
}

func modifyResponse(route db.Route) func(*http.Response) error {
	hasHeaders := len(route.RespHeadersDel) > 0 || len(route.RespHeadersAdd) > 0
	hasErrorPages := route.ErrorPage4xx != nil || route.ErrorPage5xx != nil
	if !hasHeaders && !hasErrorPages && route.AccelRoot == nil {
		return nil
	}
	return func(resp *http.Response) error {
		// X-Accel-Redirect: the edge owns the body — it serves the local file
		// itself (accelInterceptWriter). Discard the upstream body so the proxy
		// never blocks waiting for a body the backend declared via Content-Length
		// but did not actually send. A misbehaving backend must never hang the
		// edge; this mirrors nginx, which ignores the upstream body on X-Accel.
		if route.AccelRoot != nil && resp.Header.Get("X-Accel-Redirect") != "" {
			_ = resp.Body.Close()
			resp.Body = http.NoBody
			resp.ContentLength = 0
			resp.Header.Del("Content-Length")
		}
		for _, h := range route.RespHeadersDel {
			resp.Header.Del(h)
		}
		for k, v := range route.RespHeadersAdd {
			resp.Header.Set(k, v)
		}
		code := resp.StatusCode
		var page *string
		if code >= 500 {
			page = route.ErrorPage5xx
		} else if code >= 400 {
			page = route.ErrorPage4xx
		}
		if page != nil {
			body := []byte(*page)
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
			resp.ContentLength = int64(len(body))
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}
		return nil
	}
}

// schemeFor resolves the scheme to report upstream. TLS terminated here is
// authoritative; an inbound X-Forwarded-Proto is believed only when it comes
// from a trusted upstream.
func schemeFor(r *http.Request, trustedUpstream bool) string {
	if r.TLS != nil {
		return "https"
	}
	if trustedUpstream {
		if fp := r.Header.Get("X-Forwarded-Proto"); fp != "" {
			return fp
		}
	}
	return "http"
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
