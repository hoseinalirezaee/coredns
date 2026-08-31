// Package ratelimit provides per-client DNS request and transfer limits.
package ratelimit

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	cacheplugin "github.com/coredns/coredns/plugin/cache"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	clientQPSName        = "clientqps"
	transferLimitName    = "transferlimit"
	defaultClientRate    = 50.0
	defaultClientBurst   = 100.0
	defaultTransferRate  = 1024.0
	defaultTransferBurst = 4096.0
	maxBuckets           = 65536
	idleBucketLifetime   = 10 * time.Minute
)

type mode uint8

const (
	requestMode mode = iota
	transferMode
)

var (
	requestRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns", Subsystem: "ratelimit", Name: "request_rejects_total",
		Help: "Number of DNS requests rejected by the per-client request limiter.",
	}, []string{"server", "zone", "view"})
	transferRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns", Subsystem: "ratelimit", Name: "transfer_rejects_total",
		Help: "Number of forwarded DNS responses rejected by the per-client transfer limiter.",
	}, []string{"server", "zone", "view"})
	accountedBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns", Subsystem: "ratelimit", Name: "transfer_bytes_total",
		Help: "Forwarded DNS query and response bytes charged to client buckets.",
	}, []string{"server", "zone", "view", "direction"})
	exemptRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns", Subsystem: "ratelimit", Name: "exempt_requests_total",
		Help: "DNS requests from clients exempted from rate limiting.",
	}, []string{"server", "zone", "view"})
)

func init() {
	plugin.Register(clientQPSName, setupClientQPS)
	plugin.Register(transferLimitName, setupTransferLimit)
}

type bucket struct {
	tokens  float64
	updated time.Time
}

type limiter struct {
	Next       plugin.Handler
	name       string
	mode       mode
	rate       float64
	burst      float64
	exemptFile string
	exemptEnv  string

	mu      sync.Mutex
	buckets map[string]*bucket
	exempts *exemptionSet
}

type exemptionSet struct {
	filePath    string
	fileMod     time.Time
	lastChecked time.Time
	nets        []*net.IPNet
}

func setupClientQPS(c *caddy.Controller) error {
	return setup(c, clientQPSName, requestMode, defaultClientRate, defaultClientBurst)
}

func setupTransferLimit(c *caddy.Controller) error {
	return setup(c, transferLimitName, transferMode, defaultTransferRate, defaultTransferBurst)
}

func setup(c *caddy.Controller, name string, m mode, defaultRate, defaultBurst float64) error {
	l, err := parse(c, name, m, defaultRate, defaultBurst)
	if err != nil {
		return plugin.Error(name, err)
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		l.Next = next
		return l
	})
	return nil
}

func parse(c *caddy.Controller, name string, m mode, defaultRate, defaultBurst float64) (*limiter, error) {
	var parseErr error
	l := &limiter{
		name: name, mode: m, rate: defaultRate, burst: defaultBurst,
		exemptFile: "/etc/coredns/dns-rate-limit-exempt-cidrs.txt",
		exemptEnv:  "COREDNS_RATE_LIMIT_EXEMPT_CIDRS",
		buckets:    make(map[string]*bucket),
		exempts:    &exemptionSet{},
	}
	for c.Next() {
		if len(c.RemainingArgs()) != 0 {
			return nil, c.ArgErr()
		}
		for c.NextBlock() {
			switch strings.ToLower(c.Val()) {
			case "rate":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				if l.rate, parseErr = parsePositiveFloat(args[0]); parseErr != nil {
					return nil, c.Errf("invalid rate %q: %v", args[0], parseErr)
				}
			case "burst":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				if l.burst, parseErr = parsePositiveFloat(args[0]); parseErr != nil {
					return nil, c.Errf("invalid burst %q: %v", args[0], parseErr)
				}
			case "exempt_file":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				l.exemptFile = args[0]
			case "exempt_env":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				l.exemptEnv = args[0]
			case "action":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				if strings.ToLower(args[0]) != "refuse" {
					return nil, c.Errf("unsupported action %q; only refuse is supported", args[0])
				}
			default:
				return nil, c.Errf("unknown option %q", c.Val())
			}
		}
	}
	if l.burst < 1 {
		return nil, fmt.Errorf("burst must be at least 1")
	}
	return l, nil
}

func parsePositiveFloat(raw string) (float64, error) {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("must be greater than zero")
	}
	return value, nil
}

func (l *limiter) Name() string { return l.name }

func (l *limiter) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if l.mode == transferMode && cacheplugin.IsPrefetchContext(ctx) {
		return plugin.NextOrFailure(l.name, l.Next, ctx, w, r)
	}

	state := request.Request{W: w, Req: r}
	server := metrics.WithServer(ctx)
	zone := ""
	view := metrics.WithView(ctx)
	if l.isExempt(state.IP()) {
		exemptRequests.WithLabelValues(server, zone, view).Inc()
		return plugin.NextOrFailure(l.name, l.Next, ctx, w, r)
	}

	key := state.IP()
	if l.mode == requestMode {
		if !l.allow(key, 1, time.Now()) {
			requestRejected.WithLabelValues(server, zone, view).Inc()
			writeRefused(w, r)
			return dns.RcodeSuccess, nil
		}
		return plugin.NextOrFailure(l.name, l.Next, ctx, w, r)
	}

	queryBytes := r.Len()
	if !l.allow(key, float64(queryBytes), time.Now()) {
		transferRejected.WithLabelValues(server, zone, view).Inc()
		writeRefused(w, r)
		return dns.RcodeSuccess, nil
	}
	accountedBytes.WithLabelValues(server, zone, view, "query").Add(float64(queryBytes))
	return plugin.NextOrFailure(l.name, l.Next, ctx, &responseWriter{
		ResponseWriter: w, limiter: l, key: key, server: server, zone: zone, view: view, req: r,
	}, r)
}

func (l *limiter) allow(key string, cost float64, now time.Time) bool {
	if cost <= 0 || cost > l.burst {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) >= maxBuckets {
		l.evictOldestLocked(now)
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, updated: now}
		l.buckets[key] = b
	}
	if elapsed := now.Sub(b.updated).Seconds(); elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
		b.updated = now
	}
	if b.tokens < cost {
		return false
	}
	b.tokens -= cost
	return true
}

func (l *limiter) evictOldestLocked(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for key, b := range l.buckets {
		if now.Sub(b.updated) > idleBucketLifetime {
			delete(l.buckets, key)
			continue
		}
		if oldestKey == "" || b.updated.Before(oldest) {
			oldestKey, oldest = key, b.updated
		}
	}
	if len(l.buckets) >= maxBuckets && oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}

func (l *limiter) isExempt(rawIP string) bool {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil {
		return false
	}
	set := l.loadExemptions()
	for _, network := range set.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (l *limiter) loadExemptions() *exemptionSet {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.exempts.filePath == l.exemptFile && now.Sub(l.exempts.lastChecked) < time.Second {
		return l.exempts
	}
	info, err := os.Stat(l.exemptFile)
	mod := time.Time{}
	if err == nil {
		mod = info.ModTime()
	}
	if l.exempts.filePath == l.exemptFile && l.exempts.fileMod.Equal(mod) {
		return l.exempts
	}
	set, err := readExemptions(l.exemptFile, os.Getenv(l.exemptEnv))
	if err != nil {
		l.exempts.lastChecked = now
		return l.exempts
	}
	set.filePath, set.fileMod, set.lastChecked = l.exemptFile, mod, now
	l.exempts = set
	return set
}

func readExemptions(path, env string) (*exemptionSet, error) {
	set := &exemptionSet{}
	if data, err := os.ReadFile(path); err == nil {
		for lineNo, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			if line == "" {
				continue
			}
			if err := addNetwork(set, line); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, lineNo+1, err)
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	for _, value := range strings.Fields(env) {
		if err := addNetwork(set, value); err != nil {
			return nil, fmt.Errorf("%s: %w", value, err)
		}
	}
	return set, nil
}

func addNetwork(set *exemptionSet, value string) error {
	if !strings.Contains(value, "/") {
		ip := net.ParseIP(value)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR %q", value)
		}
		bits := 128
		if ip.To4() != nil {
			bits = 32
			ip = ip.To4()
		}
		value = fmt.Sprintf("%s/%d", ip, bits)
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR %q", value)
	}
	set.nets = append(set.nets, network)
	return nil
}

func writeRefused(w dns.ResponseWriter, r *dns.Msg) {
	response := new(dns.Msg).SetRcode(r, dns.RcodeRefused)
	_ = w.WriteMsg(response)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

type responseWriter struct {
	dns.ResponseWriter
	limiter *limiter
	key     string
	server  string
	zone    string
	view    string
	req     *dns.Msg
}

func (w *responseWriter) WriteMsg(msg *dns.Msg) error {
	size := msg.Len()
	if !w.limiter.allow(w.key, float64(size), time.Now()) {
		transferRejected.WithLabelValues(w.server, w.zone, w.view).Inc()
		writeRefused(w.ResponseWriter, w.req)
		return nil
	}
	accountedBytes.WithLabelValues(w.server, w.zone, w.view, "response").Add(float64(size))
	return w.ResponseWriter.WriteMsg(msg)
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.limiter.allow(w.key, float64(len(data)), time.Now()) {
		writeRefused(w.ResponseWriter, w.req)
		return len(data), nil
	}
	accountedBytes.WithLabelValues(w.server, w.zone, w.view, "response").Add(float64(len(data)))
	return w.ResponseWriter.Write(data)
}
