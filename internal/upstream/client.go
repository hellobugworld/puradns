package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
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

// Config represents the upstream DNS client configuration
type Config struct {
	Addr      string        `yaml:"addr"`
	Protocol  Protocol      `yaml:"protocol"`
	Timeout   time.Duration `yaml:"timeout"`
	Retry     int           `yaml:"retry"`
	Bootstrap []string      `yaml:"bootstrap"`
	TLSConfig TLSConfig     `yaml:"tls_config"`
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

	// Create HTTP client with reliable transport settings
	// Use standard http.Transport which supports both HTTP/1.1 and HTTP/2
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
		},
		Timeout: c.config.Timeout,
	}

	c.dohClient = httpClient
	return nil
}

// buildTLSConfig builds the TLS configuration
func (c *client) buildTLSConfig() (*tls.Config, error) {
	// Parse TLS versions
	minVersion, err := parseTLSVersion(c.config.TLSConfig.MinVersion)
	if err != nil {
		return nil, err
	}

	maxVersion, err := parseTLSVersion(c.config.TLSConfig.MaxVersion)
	if err != nil {
		return nil, err
	}

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
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
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

	return cfg, nil
}

// parseTLSVersion parses TLS version string to tls.Version*
func parseTLSVersion(version string) (uint16, error) {
	switch strings.ToLower(version) {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}
}

// parseCipherSuites parses cipher suite strings to tls.CipherSuite IDs
func parseCipherSuites(suites []string) ([]uint16, error) {
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

	// Implement retry logic with exponential backoff
	for i := 0; i <= c.config.Retry; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err = c.exchangeOnce(ctx, m)
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

	return resp, err
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
	resp, _, err := c.dotClient.ExchangeContext(ctx, m, c.config.Addr)
	return resp, err
}

// exchangeDoH sends a DNS over HTTPS query
func (c *client) exchangeDoH(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// Marshal DNS message to binary
	data, err := m.Pack()
	if err != nil {
		return nil, err
	}

	// Use only POST method for reliability
	useGET := false

	var req *http.Request
	var err2 error

	if useGET {
		// Use GET method
		reqURL := *c.dohURL
		reqURL.RawQuery = "dns=" + hex.EncodeToString(data)
		req, err2 = http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	} else {
		// Use POST method
		req, err2 = http.NewRequestWithContext(ctx, http.MethodPost, c.dohServerURL.String(), bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/dns-message")
	}

	if err2 != nil {
		return nil, err2
	}

	// Set common headers
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "PuraDNS/1.0")

	// Send request
	resp, err := c.dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request failed with status: %s", resp.Status)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Unmarshal DNS message
	msg := &dns.Msg{}
	if err := msg.Unpack(body); err != nil {
		return nil, err
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
