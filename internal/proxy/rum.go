package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"muvon/clientlib"
	"muvon/internal/config"
	"muvon/internal/logger"
)

// Reserved client-telemetry (RUM) ingest paths. They live under the
// muvon-owned /__muvon/ namespace so they can never collide with a tenant
// app's own routes, and are intercepted before route matching. Inert unless
// the host has opted in (hosts.rum_enabled).
const (
	rumIngestPath   = "/__muvon/rum"
	rumConfigPath   = "/__muvon/rum/config"
	rumScriptPath   = "/__muvon/rum.js"
	rumMaxBodyBytes = 64 << 10 // 64 KiB — matches the client batch cap.
	rumAttrMaxLen   = 1024     // per-attr value cap, keeps the JSONB index sane.
)

func isRUMPath(p string) bool {
	return p == rumIngestPath || p == rumConfigPath || p == rumScriptPath
}

// rumPayload is the wire shape the browser POSTs: one envelope
// (resource/session/view) plus a batch of events. Edge-stamped fields
// (client IP, host, timestamps) are never taken from this body.
type rumPayload struct {
	Resource struct {
		App     string `json:"app"`
		Release string `json:"release"`
		SDK     string `json:"sdk"`
	} `json:"resource"`
	Session struct {
		SessionID string `json:"session_id"`
	} `json:"session"`
	View struct {
		ViewID  string `json:"view_id"`
		Route   string `json:"route"`
		URLPath string `json:"url_path"`
	} `json:"view"`
	Events []rumEvent `json:"events"`
}

type rumEvent struct {
	EventName string         `json:"event_name"`
	TS        int64          `json:"ts"` // browser epoch millis
	TraceID   string         `json:"trace_id"`
	SpanID    string         `json:"span_id"`
	Attrs     map[string]any `json:"attrs"`
}

// serveRUM dispatches the reserved RUM paths. Called from ServeHTTP only when
// the host opted in.
func (h *Handler) serveRUM(w http.ResponseWriter, r *http.Request, hc *config.HostConfig) {
	rumSetCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch r.URL.Path {
	case rumScriptPath:
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("ETag", clientlib.ETag)
		if r.Header.Get("If-None-Match") == clientlib.ETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(clientlib.Bundle)
	case rumConfigPath:
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		g := h.configHolder.Get().Global
		rate := g.RUMSampleRate
		if rate <= 0 || rate > 1 {
			rate = 1
		}
		maxBytes := g.RUMMaxBatchBytes
		if maxBytes <= 0 {
			maxBytes = 65536
		}
		body, _ := json.Marshal(struct {
			SampleRates   map[string]float64 `json:"sample_rates"`
			MaxBatchBytes int                `json:"max_batch_bytes"`
		}{
			SampleRates:   map[string]float64{"default": rate},
			MaxBatchBytes: maxBytes,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	case rumIngestPath:
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Always 204 from here — telemetry is best-effort and must never
		// block or error the browser. Parse failures, an oversized body, or
		// a down pipeline simply drop the batch.
		h.ingestRUM(r, hc)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ingestRUM parses the beacon, stamps edge enrichment, and ships the batch to
// diaLOG. Errors are swallowed by design (caller always replies 204).
func (h *Handler) ingestRUM(r *http.Request, hc *config.HostConfig) {
	if h.logSink == nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, rumMaxBodyBytes))
	if err != nil || len(body) == 0 {
		return
	}
	var p rumPayload
	if json.Unmarshal(body, &p) != nil || len(p.Events) == 0 {
		return
	}

	hostID := "central"
	if h.selfKind == "agent" {
		hostID = h.selfAgentID
	}
	batch := logger.ClientEventBatch{
		App:        p.Resource.App,
		Release:    p.Resource.Release,
		SDK:        p.Resource.SDK,
		SessionID:  p.Session.SessionID,
		ViewID:     p.View.ViewID,
		Route:      p.View.Route,
		URLPath:    p.View.URLPath,
		Host:       stripPort(r.Host),
		HostID:     hostID,
		ClientIP:   clientIPFor(r, hc.Host.TrustedProxies),
		UserAgent:  r.UserAgent(),
		ReceivedAt: time.Now(),
	}
	for _, ev := range p.Events {
		if ev.EventName == "" {
			continue
		}
		item := logger.ClientEventItem{
			EventName: ev.EventName,
			TraceID:   ev.TraceID,
			SpanID:    ev.SpanID,
			Attrs:     stringifyAttrs(ev.Attrs),
		}
		if ev.TS > 0 {
			item.ClientTS = time.UnixMilli(ev.TS)
		}
		batch.Events = append(batch.Events, item)
	}
	if len(batch.Events) == 0 {
		return
	}
	h.logSink.SendClientEvents(batch)
}

// rumSetCORS makes the endpoint usable cross-origin (the SPA-on-another-host
// case where only the API is proxied through muvon). Same-origin beacons work
// without it. No credentials — telemetry ingest never reads cookies.
func rumSetCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	if origin != "*" {
		h.Add("Vary", "Origin")
	}
	h.Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Max-Age", "600")
}

// stringifyAttrs flattens arbitrary JSON attr values to strings so the worker
// can store a clean map[string]string. Mirrors parseJSONLine's intent: enable
// attrs.key=value filtering, not faithful tree reconstruction. Returns nil
// when empty so the column stays NULL.
func stringifyAttrs(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		var s string
		switch val := v.(type) {
		case string:
			s = val
		case nil:
			continue
		default:
			s = fmt.Sprintf("%v", val)
		}
		if len(s) > rumAttrMaxLen {
			s = s[:rumAttrMaxLen]
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
