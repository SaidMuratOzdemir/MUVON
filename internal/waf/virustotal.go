package waf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"muvon/internal/db"
)

// VTChecker performs asynchronous VirusTotal IP reputation checks.
type VTChecker struct {
	httpClient  *http.Client
	cache       sync.Map // ip -> *vtCacheEntry
	database    *db.DB
	apiKey      string
	scoreCont   int
	cacheTTL    time.Duration
}

type vtCacheEntry struct {
	IsMalicious    bool
	MaliciousCount int
	TotalEngines   int
	Reputation     int
	CheckedAt      time.Time
}

// NewVTChecker creates a VirusTotal checker. Pass empty apiKey to disable.
func NewVTChecker(database *db.DB, apiKey string, timeoutSec, scoreContribution, cacheTTLHours int) *VTChecker {
	if timeoutSec <= 0 {
		timeoutSec = 8
	}
	if scoreContribution <= 0 {
		scoreContribution = 30
	}
	if cacheTTLHours <= 0 {
		cacheTTLHours = 24
	}

	return &VTChecker{
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
		database:  database,
		apiKey:    apiKey,
		scoreCont: scoreContribution,
		cacheTTL:  time.Duration(cacheTTLHours) * time.Hour,
	}
}

// CheckAsync spawns a goroutine to check the IP's reputation.
// It does NOT block the request. If the IP is malicious, it adds to the IP's cumulative score.
func (vt *VTChecker) CheckAsync(ip string, ipMgr *IPStateManager, cfg *WafConfig) {
	if vt.apiKey == "" || isPrivateIP(ip) {
		return
	}

	// Check in-memory cache first
	if cached, ok := vt.cache.Load(ip); ok {
		entry := cached.(*vtCacheEntry)
		if time.Since(entry.CheckedAt) < vt.cacheTTL {
			return // Already checked recently
		}
	}

	go vt.check(ip, ipMgr, cfg)
}

func (vt *VTChecker) check(ip string, ipMgr *IPStateManager, cfg *WafConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.VTTimeoutSeconds)*time.Second)
	defer cancel()

	// Check DB cache
	dbCache, err := vt.database.GetWafVTCache(ctx, ip)
	if err == nil && time.Since(dbCache.CheckedAt) < vt.cacheTTL {
		entry := &vtCacheEntry{
			IsMalicious:    dbCache.IsMalicious,
			MaliciousCount: dbCache.MaliciousCount,
			TotalEngines:   dbCache.TotalEngines,
			Reputation:     dbCache.Reputation,
			CheckedAt:      dbCache.CheckedAt,
		}
		vt.cache.Store(ip, entry)
		if entry.IsMalicious {
			ipMgr.UpdateScore(ip, vt.scoreCont, cfg)
		}
		return
	}

	// Call VT API
	result, err := vt.queryAPI(ctx, ip)
	if err != nil {
		slog.Debug("virustotal query failed", "ip", ip, "error", err)
		return
	}

	// Store in caches
	vt.cache.Store(ip, result)
	_ = vt.database.UpsertWafVTCache(ctx, ip, result.IsMalicious,
		result.MaliciousCount, result.TotalEngines, result.Reputation)

	if result.IsMalicious {
		slog.Info("virustotal flagged IP as malicious",
			"ip", ip,
			"malicious_count", result.MaliciousCount,
			"total_engines", result.TotalEngines,
			"reputation", result.Reputation)
		ipMgr.UpdateScore(ip, vt.scoreCont, cfg)
	}
}

func (vt *VTChecker) queryAPI(ctx context.Context, ip string) (*vtCacheEntry, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", vt.apiKey)

	resp, err := vt.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limited")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	// Parse response
	var report struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				Reputation int `json:"reputation"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &report); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	stats := report.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless
	reputation := report.Data.Attributes.Reputation

	isMalicious := false
	if total > 0 {
		malRatio := float64(stats.Malicious) / float64(total)
		suspRatio := float64(stats.Suspicious) / float64(total)
		isMalicious = malRatio > 0.10 || suspRatio > 0.20 || reputation < -50
	}

	return &vtCacheEntry{
		IsMalicious:    isMalicious,
		MaliciousCount: stats.Malicious,
		TotalEngines:   total,
		Reputation:     reputation,
		CheckedAt:      time.Now(),
	}, nil
}

// isPrivateIP checks if an IP is a private/loopback/link-local address.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// UpdateConfig reconfigures the VT checker with new settings.
func (vt *VTChecker) UpdateConfig(apiKey string, timeoutSec, scoreContribution, cacheTTLHours int) {
	vt.apiKey = apiKey
	vt.scoreCont = scoreContribution
	vt.cacheTTL = time.Duration(cacheTTLHours) * time.Hour
	vt.httpClient.Timeout = time.Duration(timeoutSec) * time.Second
}
