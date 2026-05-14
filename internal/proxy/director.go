package proxy

import (
	"bytes"
	"io"
	"net/http"
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

func Director(target *url.URL, stripPrefix string, route db.Route, clientIP string) func(req *http.Request) {
	return func(req *http.Request) {
		originalHost := req.Host // orijinal host (incoming)

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

		// Accept-Encoding header'ını sil, backend plaintext dönsün
		// Gzip sıkıştırmasını biz middleware ile yapacağız
		req.Header.Del("Accept-Encoding")

		// X-Forwarded headers — clientIP zaten trusted proxy'ye göre çözüldü
		xff := clientIP
		if prior, exists := req.Header["X-Forwarded-For"]; exists {
			xff = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("X-Forwarded-Proto", schemeOf(req))
		req.Header.Set("X-Forwarded-Host", originalHost)

		// Per-route request header manipulation
		for _, h := range route.ReqHeadersDel {
			req.Header.Del(h)
		}
		for k, v := range route.ReqHeadersAdd {
			// Host header'ı req.Header ile değil req.Host ile set edilmeli
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
	if !hasHeaders && !hasErrorPages {
		return nil
	}
	return func(resp *http.Response) error {
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

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if fp := r.Header.Get("X-Forwarded-Proto"); fp != "" {
		return fp
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
