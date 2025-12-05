package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

// Protocol defines the DNS protocol type
type Protocol string

const (
	// ProtocolPlain is plain DNS over UDP/TCP
	ProtocolPlain Protocol = "plain"
	// ProtocolDoT is DNS over TLS
	ProtocolDoT Protocol = "dot"
	// ProtocolDoH is DNS over HTTPS
	ProtocolDoH Protocol = "doh"
)

// fallbackRoundTripper implements a RoundTripper that tries HTTP/3 first, then falls back to HTTP/2/1.1
type fallbackRoundTripper struct {
	http3Transport      *http3.RoundTripper
	http2Transport      *http.Transport
	http3FailedAt       time.Time
	retryHTTP3After     time.Duration
	http3AttemptTimeout time.Duration // HTTP/3 尝试超时时间
	mutex               sync.RWMutex
}

// RoundTrip implements the RoundTripper interface
func (rt *fallbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if we should skip HTTP/3 attempt
	shouldSkipHTTP3 := rt.shouldSkipHTTP3()
	if !shouldSkipHTTP3 {
		// First try HTTP/3 with a shorter timeout to allow fallback
		http3Timeout := rt.http3AttemptTimeout
		if http3Timeout == 0 {
			http3Timeout = 2 * time.Second // Default value if not set
		}
		http3Ctx, http3Cancel := context.WithTimeout(req.Context(), http3Timeout)
		defer http3Cancel()

		// Clone request with shorter timeout context
		http3Req := req.Clone(http3Ctx)

		// Try HTTP/3
		resp, err := rt.http3Transport.RoundTrip(http3Req)
		if err == nil {
			// Reset failed timer on success
			rt.resetHTTP3Failed()
			return resp, nil
		}
		// Record HTTP/3 failure
		rt.recordHTTP3Failed()
	}

	// Fall back to HTTP/2/1.1 with original context
	resp, err := rt.http2Transport.RoundTrip(req)
	return resp, err
}

// shouldSkipHTTP3 checks if we should skip HTTP/3 attempt
func (rt *fallbackRoundTripper) shouldSkipHTTP3() bool {
	rt.mutex.RLock()
	defer rt.mutex.RUnlock()

	if rt.http3FailedAt.IsZero() {
		return false // Never failed before, try HTTP/3
	}

	// Check if we should retry HTTP/3
	retryAfter := rt.http3FailedAt.Add(rt.retryHTTP3After)
	return time.Now().Before(retryAfter)
}

// recordHTTP3Failed records HTTP/3 failure time
func (rt *fallbackRoundTripper) recordHTTP3Failed() {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	// Set default retry interval if not already set
	if rt.retryHTTP3After == 0 {
		rt.retryHTTP3After = 30 * time.Second // Retry HTTP/3 every 30 seconds
	}

	// Only update if it's been more than 1 second since last failure
	if time.Since(rt.http3FailedAt) > time.Second {
		rt.http3FailedAt = time.Now()
	}
}

// resetHTTP3Failed resets HTTP/3 failure timer on success
func (rt *fallbackRoundTripper) resetHTTP3Failed() {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	if !rt.http3FailedAt.IsZero() {
		rt.http3FailedAt = time.Time{}
	}
}

// CloseIdleConnections closes idle connections for both transports
func (rt *fallbackRoundTripper) CloseIdleConnections() {
	rt.http3Transport.Close()
	rt.http2Transport.CloseIdleConnections()
}

// Config represents the upstream DNS client configuration
type Config struct {
	Addr                string        `yaml:"addr"`
	Protocol            Protocol      `yaml:"protocol"`
	Timeout             time.Duration `yaml:"timeout"`
	Retry               int           `yaml:"retry"`
	Bootstrap           []string      `yaml:"bootstrap"`
	TLSConfig           TLSConfig     `yaml:"tls_config"`
	HTTP3Support        bool          `yaml:"http3"`                           // Whether the server supports HTTP/3
	HTTP3AttemptTimeout time.Duration `yaml:"http3_attempt_timeout,omitempty"` // HTTP/3 尝试超时时间
	HTTP3RetryInterval  time.Duration `yaml:"http3_retry_interval,omitempty"`  // HTTP/3 失败后的重试间隔
}

// TLSConfig represents the TLS configuration for DoT and DoH
type TLSConfig struct {
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
	ServerName         string   `yaml:"server_name"`
	CipherSuites       []string `yaml:"cipher_suites"`
	MinVersion         string   `yaml:"min_version"`
	MaxVersion         string   `yaml:"max_version"`
}

// Client is the upstream DNS client interface
type Client interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
	Close() error
	Config() *Config
}

// client implements the Client interface
type client struct {
	config             *Config
	plainClient        *dns.Client
	dotClient          *dns.Client
	dohClient          *http.Client
	dohURL             *url.URL
	dohServerURL       *url.URL
	bootstrapResolvers []*dns.Client
	mutex              sync.RWMutex
	closed             bool
}

// NewClient creates a new upstream DNS client
func NewClient(config *Config) (Client, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}

	c := &client{
		config: config,
	}

	if err := c.init(); err != nil {
		return nil, err
	}

	return c, nil
}

// init initializes the client
func (c *client) init() error {
	// Initialize clients based on protocol
	switch c.config.Protocol {
	case ProtocolPlain:
		return c.initPlainClient()
	case ProtocolDoT:
		// Check if DoT address is an IP
		addr := c.config.Addr
		// Remove port if present
		if idx := strings.LastIndex(addr, ":"); idx != -1 {
			addr = addr[:idx]
		}
		// Only initialize bootstrap resolvers if addr is not an IP
		if net.ParseIP(addr) == nil {
			if err := c.initBootstrapResolvers(); err != nil {
				return err
			}
		}
		return c.initDoTClient()
	case ProtocolDoH:
		// DoH client doesn't need bootstrap resolvers for IP addresses
		// Skip bootstrap resolver initialization for DoH
		return c.initDoHClient()
	default:
		return fmt.Errorf("unsupported protocol: %s", c.config.Protocol)
	}
}

// initBootstrapResolvers initializes bootstrap resolvers for DoT/DoH hostname resolution
func (c *client) initBootstrapResolvers() error {
	c.bootstrapResolvers = make([]*dns.Client, 0, len(c.config.Bootstrap))

	for range c.config.Bootstrap {
		bootstrapClient := &dns.Client{
			Net:     "udp",
			Timeout: c.config.Timeout,
		}
		c.bootstrapResolvers = append(c.bootstrapResolvers, bootstrapClient)
	}

	// Add default bootstrap resolvers if none provided
	if len(c.bootstrapResolvers) == 0 {
		c.bootstrapResolvers = append(c.bootstrapResolvers, &dns.Client{
			Net:     "udp",
			Timeout: c.config.Timeout,
		})
	}

	return nil
}

// initPlainClient initializes the plain DNS client
func (c *client) initPlainClient() error {
	c.plainClient = &dns.Client{
		Net:     "udp",
		Timeout: c.config.Timeout,
	}
	return nil
}

// initDoTClient initializes the DNS over TLS client
func (c *client) initDoTClient() error {
	// Configure TLS
	tlsConfig, err := c.buildTLSConfig()
	if err != nil {
		return err
	}

	// Create a custom dialer that prefers IPv4
	dialer := &net.Dialer{
		Timeout:   c.config.Timeout,
		KeepAlive: 30 * time.Second,
		DualStack: false, // Disable dual stack to prefer IPv4
	}

	c.dotClient = &dns.Client{
		Net:       "tcp-tls",
		Timeout:   c.config.Timeout,
		TLSConfig: tlsConfig,
		Dialer:    dialer,
	}
	return nil
}

// initDoHClient initializes the DNS over HTTPS client
func (c *client) initDoHClient() error {
	// Parse DoH URL
	u, err := url.Parse(c.config.Addr)
	if err != nil {
		return fmt.Errorf("invalid DoH URL: %w", err)
	}

	c.dohURL = u

	// Build server URL for POST requests
	serverURL := &url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   u.Path,
	}
	c.dohServerURL = serverURL

	// Configure TLS
	tlsConfig, err := c.buildTLSConfig()
	if err != nil {
		return err
	}

	// Create HTTP client based on HTTP3Support flag
	var httpClient *http.Client
	if c.config.HTTP3Support {
		// Server supports HTTP3, enable HTTP3 with fallback
		http3Transport := &http3.RoundTripper{
			TLSClientConfig: tlsConfig,
		}

		// Create HTTP/2 and HTTP/1.1 transport
		http2Transport := &http.Transport{
			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		// Create fallback transport that tries HTTP/3 first, then falls back to HTTP/2/1.1
		fallbackTransport := &fallbackRoundTripper{
			http3Transport:      http3Transport,
			http2Transport:      http2Transport,
			retryHTTP3After:     c.config.HTTP3RetryInterval,
			http3AttemptTimeout: c.config.HTTP3AttemptTimeout,
		}

		// Create HTTP client with fallback transport
		httpClient = &http.Client{
			Timeout:   c.config.Timeout,
			Transport: fallbackTransport,
		}
	} else {
		// Server does not support HTTP3, use HTTP/2 and HTTP/1.1 only
		http2Transport := &http.Transport{
			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		httpClient = &http.Client{
			Timeout:   c.config.Timeout,
			Transport: http2Transport,
		}
	}

	c.dohClient = httpClient
	return nil
}

// parseTLSVersion parses TLS version string to tls.Version* and returns whether it was explicitly set
func parseTLSVersion(version string) (uint16, bool) {
	switch strings.ToLower(version) {
	case "":
		return 0, false // Not explicitly set, use default
	case "1.2":
		return tls.VersionTLS12, true
	case "1.3":
		return tls.VersionTLS13, true
	default:
		return 0, false // Invalid version, use default
	}
}

// buildTLSConfig builds the TLS configuration
func (c *client) buildTLSConfig() (*tls.Config, error) {
	// Parse TLS versions
	minVersion, minSet := parseTLSVersion(c.config.TLSConfig.MinVersion)
	maxVersion, maxSet := parseTLSVersion(c.config.TLSConfig.MaxVersion)

	// Parse cipher suites
	cipherSuites, err := parseCipherSuites(c.config.TLSConfig.CipherSuites)
	if err != nil {
		return nil, err
	}

	// Set default server name from URL if not provided
	serverName := c.config.TLSConfig.ServerName

	if serverName == "" {
		switch c.config.Protocol {
		case ProtocolDoT:
			// Extract server name from DoT address (e.g., dns.cloudflare.com:853)
			serverName = strings.Split(c.config.Addr, ":")[0]
		case ProtocolDoH:
			// Extract server name from DoH URL
			u, err := url.Parse(c.config.Addr)
			if err == nil {
				serverName = u.Hostname()
			}
		}
	}

	// Create TLS config with secure defaults
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: c.config.TLSConfig.InsecureSkipVerify,
		CipherSuites:       cipherSuites,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		SessionTicketsDisabled: true,
		Renegotiation:          tls.RenegotiateNever,
	}

	// Only set MinVersion if explicitly specified
	if minSet {
		cfg.MinVersion = minVersion
	}

	// Only set MaxVersion if explicitly specified
	if maxSet {
		cfg.MaxVersion = maxVersion
	}

	return cfg, nil
}

// parseCipherSuites returns secure default cipher suites
func parseCipherSuites(_ []string) ([]uint16, error) {
	// Use secure default cipher suites regardless of input
	return []uint16{
		// TLS 1.3 cipher suites
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		// TLS 1.2 cipher suites
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}, nil
}

// Exchange sends a DNS query and returns the response
func (c *client) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	c.mutex.RLock()
	if c.closed {
		c.mutex.RUnlock()
		return nil, errors.New("client is closed")
	}
	c.mutex.RUnlock()

	var resp *dns.Msg
	var err error

	// Create a copy of the original message
	originalMsg := m.Copy()

	// First try with EDNS
	resp, err = c.exchangeWithRetry(ctx, originalMsg, true)
	if err == nil && resp != nil && resp.Rcode != dns.RcodeFormatError && resp.Rcode != dns.RcodeServerFailure {
		return resp, nil
	}

	// If EDNS failed, try without EDNS
	resp, err = c.exchangeWithRetry(ctx, originalMsg, false)
	if err == nil && resp != nil {
		return resp, nil
	}

	return resp, err
}

// exchangeWithRetry sends a DNS query with retry logic
func (c *client) exchangeWithRetry(ctx context.Context, m *dns.Msg, useEDNS bool) (*dns.Msg, error) {
	// Implement retry logic with exponential backoff
	for i := 0; i <= c.config.Retry; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Create a copy of the message for each attempt
		msgCopy := m.Copy()

		// Set EDNS if requested
		if useEDNS {
			msgCopy.SetEdns0(4096, true)
		}

		resp, err := c.exchangeOnce(ctx, msgCopy)
		if err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure {
			return resp, nil
		}

		// Retry with exponential backoff
		if i < c.config.Retry {
			delay := time.Duration((1<<i)*100) * time.Millisecond
			delay += time.Duration(rand.Intn(100)) * time.Millisecond // Add jitter
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return nil, errors.New("all retries failed")
}

// exchangeOnce sends a DNS query once without retry
func (c *client) exchangeOnce(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	switch c.config.Protocol {
	case ProtocolPlain:
		return c.exchangePlain(ctx, m)
	case ProtocolDoT:
		return c.exchangeDoT(ctx, m)
	case ProtocolDoH:
		return c.exchangeDoH(ctx, m)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", c.config.Protocol)
	}
}

// exchangePlain sends a plain DNS query
func (c *client) exchangePlain(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	resp, _, err := c.plainClient.ExchangeContext(ctx, m, c.config.Addr)
	return resp, err
}

// exchangeDoT sends a DNS over TLS query
func (c *client) exchangeDoT(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// Check if we need to resolve the DoT server address
	addr := c.config.Addr

	// Extract hostname from address (e.g., dns.google:853 -> dns.google)
	hostname := addr
	if idx := strings.LastIndex(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}

	// If hostname is not an IP, resolve it using bootstrap resolvers
	if net.ParseIP(hostname) == nil {
		// Resolve the hostname to IP addresses using bootstrap resolvers
		resolvedAddr, err := c.resolveHostname(ctx, hostname)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve DoT server address %s: %w", hostname, err)
		}

		// Replace hostname with resolved IP in the address
		if idx := strings.LastIndex(addr, ":"); idx != -1 {
			addr = resolvedAddr + addr[idx:]
		} else {
			addr = resolvedAddr
		}
	}

	// Send the DoT query using the resolved address
	resp, _, err := c.dotClient.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, fmt.Errorf("DoT query to %s failed: %w", addr, err)
	}
	return resp, nil
}

// resolveHostname resolves a hostname to IP address using bootstrap resolvers
func (c *client) resolveHostname(ctx context.Context, hostname string) (string, error) {
	// Create a DNS query for A record
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{
				Name:   hostname + ".",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	// Try all bootstrap resolvers
	for i, bootstrapResolver := range c.bootstrapResolvers {
		// Get bootstrap DNS address
		bootstrapAddr := c.config.Bootstrap[i%len(c.config.Bootstrap)]

		// Send query
		resp, _, err := bootstrapResolver.ExchangeContext(ctx, m, bootstrapAddr)
		if err != nil {
			continue
		}

		// Check if response is valid
		if resp != nil && resp.Rcode == dns.RcodeSuccess {
			// Return first A record
			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.A); ok {
					return a.A.String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("failed to resolve %s using bootstrap resolvers", hostname)
}

// exchangeDoH sends a DNS over HTTPS query
func (c *client) exchangeDoH(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// Marshal DNS message to binary
	data, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Create POST request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.dohServerURL.String(), bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create DoH request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "PuraDNS/1.0")

	// Send request
	resp, err := c.dohClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request to %s failed: %w", c.dohServerURL.String(), err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request failed with status: %s", resp.Status)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response body: %w", err)
	}

	// Unmarshal DNS message
	msg := &dns.Msg{}
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DoH response: %w", err)
	}

	return msg, nil
}

// Close closes the client
func (c *client) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true

	// Close HTTP client if it has a CloseIdleConnections method
	if c.dohClient != nil {
		if closer, ok := c.dohClient.Transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}

	return nil
}

// Config returns the client configuration
func (c *client) Config() *Config {
	return c.config
}

// Pool is a pool of upstream DNS clients
type Pool struct {
	clients      []Client
	mutex        sync.RWMutex
	closed       bool
	healthCheck  time.Duration
	healthCtx    context.Context
	healthCancel context.CancelFunc
}

// PoolConfig represents the upstream DNS client pool configuration
type PoolConfig struct {
	Clients     []*Config     `yaml:"clients"`
	HealthCheck time.Duration `yaml:"health_check"`
}

// NewPool creates a new upstream DNS client pool
func NewPool(config *PoolConfig) (*Pool, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}

	p := &Pool{
		clients:     make([]Client, 0, len(config.Clients)),
		healthCheck: config.HealthCheck,
	}

	// Create clients
	for _, clientConfig := range config.Clients {
		client, err := NewClient(clientConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create client: %w", err)
		}
		p.clients = append(p.clients, client)
	}

	// Start health check if configured
	if p.healthCheck > 0 {
		p.healthCtx, p.healthCancel = context.WithCancel(context.Background())
		go p.runHealthCheck()
	}

	return p, nil
}

// Exchange sends a DNS query to the pool and returns the response
func (p *Pool) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	p.mutex.RLock()
	if p.closed {
		p.mutex.RUnlock()
		return nil, errors.New("pool is closed")
	}

	clients := make([]Client, len(p.clients))
	copy(clients, p.clients)
	p.mutex.RUnlock()

	if len(clients) == 0 {
		return nil, errors.New("no clients in pool")
	}

	// Shuffle clients to distribute load
	rand.Shuffle(len(clients), func(i, j int) {
		clients[i], clients[j] = clients[j], clients[i]
	})

	var lastErr error
	// Try all clients until one succeeds
	for _, client := range clients {
		resp, err := client.Exchange(ctx, m)
		if err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure {
			return resp, nil
		}
		lastErr = err
	}

	// All clients failed
	return nil, lastErr
}

// Close closes the pool and all clients
func (p *Pool) Close() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true

	// Cancel health check
	if p.healthCancel != nil {
		p.healthCancel()
	}

	// Close all clients
	for _, client := range p.clients {
		client.Close()
	}

	return nil
}

// Clients returns the list of clients in the pool
func (p *Pool) Clients() []Client {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	clients := make([]Client, len(p.clients))
	copy(clients, p.clients)
	return clients
}

// runHealthCheck runs the health check for the pool
func (p *Pool) runHealthCheck() {
	ticker := time.NewTicker(p.healthCheck)
	defer ticker.Stop()

	for {
		select {
		case <-p.healthCtx.Done():
			return
		case <-ticker.C:
			p.checkHealth()
		}
	}
}

// checkHealth checks the health of all clients in the pool
func (p *Pool) checkHealth() {
	p.mutex.RLock()
	clients := make([]Client, len(p.clients))
	copy(clients, p.clients)
	p.mutex.RUnlock()

	for _, client := range clients {
		go p.checkClientHealth(client)
	}
}

// checkClientHealth checks the health of a single client
func (p *Pool) checkClientHealth(client Client) {
	// Create a simple DNS query to check health
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{
				Name:   "cloudflare.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Send query with retry
	var resp *dns.Msg
	var err error
	for i := 0; i < 2; i++ {
		resp, err = client.Exchange(ctx, m)
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			break
		}
		// Wait a bit before retrying
		time.Sleep(500 * time.Millisecond)
	}

	// Don't remove client from pool immediately
	// This prevents the pool from becoming empty due to temporary network issues
}
