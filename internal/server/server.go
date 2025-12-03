package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hellobugworld/puradns/internal/cache"
	"github.com/hellobugworld/puradns/internal/diverter"
	"github.com/hellobugworld/puradns/internal/pool"
	"github.com/hellobugworld/puradns/internal/resources"
	"github.com/hellobugworld/puradns/internal/upstream"
	"github.com/miekg/dns"
)

// Config represents the DNS server configuration
type Config struct {
	ListenAddr               string                   `yaml:"listen_addr"`
	ListenAddrTCP            string                   `yaml:"listen_addr_tcp"`
	UpstreamDomestic         *upstream.PoolConfig     `yaml:"upstream_domestic"`
	UpstreamForeign          *upstream.PoolConfig     `yaml:"upstream_foreign"`
	CacheConfig              *cache.GroupCacheConfig  `yaml:"cache_config"`
	QueryTimeout             time.Duration            `yaml:"query_timeout"`
	MaxRetries               int                      `yaml:"max_retries"`
	PreRefreshEnabled        bool                     `yaml:"pre_refresh_enabled"`
	PreRefreshThreshold      float64                  `yaml:"pre_refresh_threshold"`
	PreRefreshInterval       time.Duration            `yaml:"pre_refresh_interval"`
	PreRefreshMaxConcurrency int                      `yaml:"pre_refresh_max_concurrency"`
	PreRefreshRetryCount     int                      `yaml:"pre_refresh_retry_count"`
	ResourceConfig           resources.ResourceConfig `yaml:"resource_config"`
	// GoroutinePool配置
	GoroutinePoolSize  int `yaml:"goroutinepool_size"`
	GoroutineQueueSize int `yaml:"goroutinepool_queue_size"`
}

// Server is the DNS server implementation
type Server struct {
	config           *Config
	udpServer        *dns.Server
	tcpServer        *dns.Server
	domesticPool     *upstream.Pool
	foreignPool      *upstream.Pool
	cacheManager     *cache.GroupCache
	diverter         diverter.Diverter
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	closed           bool
	mutex            sync.RWMutex
	preRefreshTicker *time.Ticker
	preRefreshWg     sync.WaitGroup
	// Goroutine池
	workerPool *pool.GoroutinePool
	// 对象池，用于内存优化
	msgPool  sync.Pool // 复用dns.Msg对象
	chanPool sync.Pool // 复用用于缓存查询的通道对象
}

// NewServer creates a new DNS server
func NewServer(config *Config) (*Server, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}

	if err := s.init(); err != nil {
		cancel()
		return nil, err
	}

	return s, nil
}

// init initializes the server components
func (s *Server) init() error {
	// Initialize cache manager
	if err := s.initCache(); err != nil {
		return err
	}

	// Initialize upstream pools
	if err := s.initUpstreamPools(); err != nil {
		return err
	}

	// Initialize diverter
	if err := s.initDiverter(); err != nil {
		return err
	}

	// Initialize goroutine pool
	if err := s.initGoroutinePool(); err != nil {
		return err
	}

	// Initialize object pools
	s.initObjectPools()

	// Initialize DNS servers
	if err := s.initDNSServers(); err != nil {
		return err
	}

	return nil
}

// initObjectPools initializes the object pools for memory optimization
func (s *Server) initObjectPools() {
	// 初始化DNS消息对象池
	s.msgPool = sync.Pool{
		New: func() interface{} {
			return new(dns.Msg)
		},
	}

	// 初始化通道对象池
	s.chanPool = sync.Pool{
		New: func() interface{} {
			return make(chan *dns.Msg, 1)
		},
	}
}

// getMsgFromPool 从对象池获取DNS消息对象
func (s *Server) getMsgFromPool() *dns.Msg {
	return s.msgPool.Get().(*dns.Msg)
}

// putMsgToPool 将DNS消息对象放回对象池
func (s *Server) putMsgToPool(msg *dns.Msg) {
	// 重置消息，避免内存泄漏
	msg.Id = 0
	msg.Response = false
	msg.Opcode = dns.OpcodeQuery
	msg.Authoritative = false
	msg.Truncated = false
	msg.RecursionDesired = false
	msg.RecursionAvailable = false
	msg.Zero = false
	msg.AuthenticatedData = false
	msg.CheckingDisabled = false
	msg.Rcode = dns.RcodeSuccess
	msg.Question = nil
	msg.Answer = nil
	msg.Ns = nil
	msg.Extra = nil
	// 将重置后的消息放回对象池
	s.msgPool.Put(msg)
}

// getChanFromPool 从对象池获取通道对象
func (s *Server) getChanFromPool() chan *dns.Msg {
	return s.chanPool.Get().(chan *dns.Msg)
}

// putChanToPool 将通道对象放回对象池
func (s *Server) putChanToPool(ch chan *dns.Msg) {
	// 清空通道
	select {
	case <-ch:
	default:
	}
	// 将通道放回对象池
	s.chanPool.Put(ch)
}

// initGoroutinePool initializes the goroutine pool
func (s *Server) initGoroutinePool() error {
	// Set default values if not configured
	poolSize := s.config.GoroutinePoolSize
	if poolSize <= 0 {
		poolSize = 100 // Default pool size
	}

	queueSize := s.config.GoroutineQueueSize
	if queueSize <= 0 {
		queueSize = 1000 // Default queue size
	}

	// Create goroutine pool
	s.workerPool = pool.NewGoroutinePool(poolSize, queueSize)
	log.Printf("Initialized goroutine pool with %d workers and queue size %d", poolSize, queueSize)
	return nil
}

// initCache initializes the cache manager
func (s *Server) initCache() error {
	cacheManager := cache.NewGroupCache(*s.config.CacheConfig)
	s.cacheManager = cacheManager
	return nil
}

// initUpstreamPools initializes the upstream client pools
func (s *Server) initUpstreamPools() error {
	// Initialize domestic pool if configured
	if s.config.UpstreamDomestic != nil {
		domesticPool, err := upstream.NewPool(s.config.UpstreamDomestic)
		if err != nil {
			return fmt.Errorf("failed to create domestic upstream pool: %w", err)
		}
		s.domesticPool = domesticPool
	}

	// Initialize foreign pool if configured
	if s.config.UpstreamForeign != nil {
		foreignPool, err := upstream.NewPool(s.config.UpstreamForeign)
		if err != nil {
			return fmt.Errorf("failed to create foreign upstream pool: %w", err)
		}
		s.foreignPool = foreignPool
	}

	return nil
}

// initDiverter initializes the diverter
func (s *Server) initDiverter() error {
	// Create resource manager with config from server config
	resourceManager, err := resources.NewManager(s.config.ResourceConfig)
	if err != nil {
		return fmt.Errorf("failed to create resource manager: %w", err)
	}

	// Create diverter
	s.diverter = diverter.NewDiverter(diverter.Config{
		ResourceManager: resourceManager,
	})
	return nil
}

// initDNSServers initializes the UDP and TCP DNS servers
func (s *Server) initDNSServers() error {
	// Create request handler
	handler := s.handleDNSRequest

	// Initialize UDP server
	s.udpServer = &dns.Server{
		Addr:    s.config.ListenAddr,
		Net:     "udp",
		Handler: dns.HandlerFunc(handler),
		UDPSize: 65535,
	}

	// Initialize TCP server
	s.tcpServer = &dns.Server{
		Addr:    s.config.ListenAddrTCP,
		Net:     "tcp",
		Handler: dns.HandlerFunc(handler),
	}

	return nil
}

// Start starts the DNS server
func (s *Server) Start() error {
	s.mutex.RLock()
	if s.closed {
		s.mutex.RUnlock()
		return errors.New("server is closed")
	}
	s.mutex.RUnlock()

	// Start UDP server
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("Starting UDP DNS server on %s", s.config.ListenAddr)
		if err := s.udpServer.ListenAndServe(); err != nil {
			log.Printf("UDP DNS server error: %v", err)
		}
	}()

	// Start TCP server
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("Starting TCP DNS server on %s", s.config.ListenAddrTCP)
		if err := s.tcpServer.ListenAndServe(); err != nil {
			log.Printf("TCP DNS server error: %v", err)
		}
	}()

	// Start pre-refresh if enabled
	if s.config.PreRefreshEnabled {
		s.startPreRefresh()
	}

	return nil
}

// Stop stops the DNS server
func (s *Server) Stop() {
	s.mutex.Lock()
	if s.closed {
		s.mutex.Unlock()
		return
	}
	s.closed = true
	s.mutex.Unlock()

	// Cancel context
	s.cancel()

	// Stop pre-refresh if running
	if s.preRefreshTicker != nil {
		s.preRefreshTicker.Stop()
	}

	// Close goroutine pool
	if s.workerPool != nil {
		s.workerPool.Close()
		log.Println("Goroutine pool closed")
	}

	// Shutdown DNS servers
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.udpServer.ShutdownContext(ctx); err != nil {
		log.Printf("Error shutting down UDP server: %v", err)
	}

	if err := s.tcpServer.ShutdownContext(ctx); err != nil {
		log.Printf("Error shutting down TCP server: %v", err)
	}

	// Close upstream pools
	if s.domesticPool != nil {
		s.domesticPool.Close()
	}

	if s.foreignPool != nil {
		s.foreignPool.Close()
	}

	// Wait for all goroutines to exit
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		s.preRefreshWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All servers stopped gracefully")
	case <-time.After(10 * time.Second):
		log.Println("Timeout waiting for servers to stop")
	}
}

// handleDNSRequest handles DNS requests by submitting to goroutine pool
func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	// 复制请求和响应写入器，避免并发问题
	rCopy := r.Copy()

	// 将请求处理提交到goroutine池
	err := s.workerPool.Submit(func() {
		s.handleDNSRequestInternal(w, rCopy)
	})

	if err != nil {
		log.Printf("Failed to submit DNS request to worker pool: %v", err)
		s.sendEmptyResponse(w, r, dns.RcodeServerFailure)
	}
}

// handleDNSRequestInternal handles DNS requests internally
func (s *Server) handleDNSRequestInternal(w dns.ResponseWriter, r *dns.Msg) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(s.ctx, s.config.QueryTimeout)
	defer cancel()

	// Validate request
	if r == nil || len(r.Question) == 0 {
		log.Println("Invalid DNS request")
		s.sendEmptyResponse(w, r, dns.RcodeFormatError)
		return
	}

	q := r.Question[0]
	log.Printf("Received DNS query: %s %s from %s", dns.TypeToString[q.Qtype], q.Name, w.RemoteAddr())

	// Determine query group first to optimize cache lookup
	group, err := s.determineQueryGroup(q.Name)
	if err != nil {
		log.Printf("Error determining query group: %v", err)
		s.sendEmptyResponse(w, r, dns.RcodeServerFailure)
		return
	}

	// Check cache first, prioritize based on query group
	cacheKey := s.getCacheKey(q)
	var cachedResp *dns.Msg
	var found bool

	// 根据分流决策决定缓存查询策略
	if group == "domestic" {
		// domestic组：只查询国内缓存
		if cachedResp, found = s.cacheManager.GetDomestic().Get(cacheKey); found {
			log.Printf("Cache hit for %s %s in domestic cache", dns.TypeToString[q.Qtype], q.Name)
			s.sendResponse(w, r, cachedResp)
			return
		}
		log.Printf("Cache miss for %s %s in domestic cache", dns.TypeToString[q.Qtype], q.Name)
	} else if group == "foreign" {
		// foreign组：只查询国外缓存
		if cachedResp, found = s.cacheManager.GetForeign().Get(cacheKey); found {
			log.Printf("Cache hit for %s %s in foreign cache", dns.TypeToString[q.Qtype], q.Name)
			s.sendResponse(w, r, cachedResp)
			return
		}
		log.Printf("Cache miss for %s %s in foreign cache", dns.TypeToString[q.Qtype], q.Name)
	} else {
		// "both" group: 同时查询两个缓存，返回先命中的结果
		domesticChan := s.getChanFromPool()
		foreignChan := s.getChanFromPool()
		defer func() {
			// 关闭通道
			close(domesticChan)
			close(foreignChan)
			// 将通道放回对象池
			s.putChanToPool(domesticChan)
			s.putChanToPool(foreignChan)
		}()

		// 并发查询两个缓存
		go func() {
			if resp, found := s.cacheManager.GetDomestic().Get(cacheKey); found {
				domesticChan <- resp
			}
		}()

		go func() {
			if resp, found := s.cacheManager.GetForeign().Get(cacheKey); found {
				foreignChan <- resp
			}
		}()

		// 等待任一缓存返回结果
		select {
		case resp := <-domesticChan:
			if resp != nil {
				log.Printf("Cache hit for %s %s in domestic cache", dns.TypeToString[q.Qtype], q.Name)
				s.sendResponse(w, r, resp)
				return
			}
		case resp := <-foreignChan:
			if resp != nil {
				log.Printf("Cache hit for %s %s in foreign cache", dns.TypeToString[q.Qtype], q.Name)
				s.sendResponse(w, r, resp)
				return
			}
		}

		log.Printf("Cache miss for %s %s in both caches", dns.TypeToString[q.Qtype], q.Name)
	}

	// 所有缓存都未命中，向上游发起请求
	log.Printf("All cache missed, querying upstream for %s %s", dns.TypeToString[q.Qtype], q.Name)

	// Perform DNS query
	resp, err := s.performQuery(ctx, r, group)
	if err != nil {
		log.Printf("DNS query failed: %v", err)
		s.sendEmptyResponse(w, r, dns.RcodeServerFailure)
		return
	}

	// Validate and cache response
	if err := s.validateAndCacheResponse(q, resp, group); err != nil {
		log.Printf("Error validating or caching response: %v", err)
	}

	// Send response to client
	s.sendResponse(w, r, resp)
}

// getCacheKey generates a cache key for the DNS query
func (s *Server) getCacheKey(q dns.Question) string {
	// Basic cache key with domain, type, and class
	return fmt.Sprintf("%s|%d|%d", q.Name, q.Qtype, q.Qclass)
}

// determineQueryGroup determines which group (domestic/foreign) to use for the query
func (s *Server) determineQueryGroup(domain string) (string, error) {
	// Use diverter to determine group
	decision := s.diverter.Decide(domain)

	var group string
	switch decision {
	case diverter.DecisionDomestic:
		group = "domestic"
	case diverter.DecisionForeign:
		group = "foreign"
	case diverter.DecisionBoth:
		group = "both"
	default:
		group = "both"
	}

	log.Printf("Diverter decision for %s: %s", domain, group)
	return group, nil
}

// performQuery performs the DNS query using the appropriate upstream pool
func (s *Server) performQuery(ctx context.Context, r *dns.Msg, group string) (*dns.Msg, error) {
	var pool *upstream.Pool

	// Select upstream pool based on group
	switch group {
	case "domestic":
		pool = s.domesticPool
	case "foreign":
		pool = s.foreignPool
	default:
		// For unknown groups, query both pools and return the best result
		return s.queryBothPools(ctx, r)
	}

	// Check if pool is available
	if pool == nil {
		return nil, fmt.Errorf("no upstream pool available for group: %s", group)
	}

	// Set DO bit for DNSSEC support
	r.SetEdns0(4096, true)

	// Query single pool
	return pool.Exchange(ctx, r)
}

// queryBothPools queries both domestic and foreign pools and returns the best result
func (s *Server) queryBothPools(ctx context.Context, r *dns.Msg) (*dns.Msg, error) {
	// Create channels for results
	domesticChan := make(chan *dns.Msg, 1)
	foreignChan := make(chan *dns.Msg, 1)
	errorChan := make(chan error, 2)
	queryCount := 0

	// Set DO bit for DNSSEC support
	r.SetEdns0(4096, true)

	// Query domestic pool if available
	if s.domesticPool != nil {
		queryCount++
		go func() {
			// Create a copy of the message for each query
			msgCopy := r.Copy()
			resp, err := s.domesticPool.Exchange(ctx, msgCopy)
			if err != nil {
				errorChan <- fmt.Errorf("domestic query failed: %w", err)
				return
			}
			domesticChan <- resp
		}()
	}

	// Query foreign pool if available
	if s.foreignPool != nil {
		queryCount++
		go func() {
			// Create a copy of the message for each query
			msgCopy := r.Copy()
			resp, err := s.foreignPool.Exchange(ctx, msgCopy)
			if err != nil {
				errorChan <- fmt.Errorf("foreign query failed: %w", err)
				return
			}
			foreignChan <- resp
		}()
	}

	// Wait for results
	var domesticResp, foreignResp *dns.Msg
	var errors []error

	for i := 0; i < queryCount; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case resp := <-domesticChan:
			domesticResp = resp
		case resp := <-foreignChan:
			foreignResp = resp
		case err := <-errorChan:
			errors = append(errors, err)
		}
	}

	// Process results
	if domesticResp != nil && foreignResp != nil {
		// Both pools returned results, validate and select the best one
		return s.selectBestResult(domesticResp, foreignResp)
	} else if domesticResp != nil {
		// Only domestic pool returned result
		return domesticResp, nil
	} else if foreignResp != nil {
		// Only foreign pool returned result
		return foreignResp, nil
	} else {
		// Both pools failed or no pools available
		if len(errors) > 0 {
			return nil, errors[0]
		}
		return nil, fmt.Errorf("no upstream pools available")
	}
}

// selectBestResult selects the best result between domestic and foreign responses
func (s *Server) selectBestResult(domesticResp, foreignResp *dns.Msg) (*dns.Msg, error) {
	// If domestic response is successful and contains valid IPs, use it
	if domesticResp.Rcode == dns.RcodeSuccess && s.isValidDomesticResponse(domesticResp) {
		return domesticResp, nil
	}

	// Otherwise use foreign response
	return foreignResp, nil
}

// isValidDomesticResponse checks if the domestic response is valid (not polluted)
func (s *Server) isValidDomesticResponse(resp *dns.Msg) bool {
	// Basic validation for now
	if resp == nil {
		return false
	}

	// Check if response is successful
	if resp.Rcode != dns.RcodeSuccess {
		return false
	}

	// Check if response contains at least one answer
	if len(resp.Answer) == 0 {
		return false
	}

	// Validate each IP in the response
	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.A:
			// Check IPv4 address
			if !s.diverter.IsChinaIP(record.A) {
				log.Printf("Invalid domestic response: IPv4 %s is not in China IP range", record.A)
				return false
			}
		case *dns.AAAA:
			// Check IPv6 address
			if !s.diverter.IsChinaIP(record.AAAA) {
				log.Printf("Invalid domestic response: IPv6 %s is not in China IP range", record.AAAA)
				return false
			}
		// For other record types, no IP validation needed
		default:
			continue
		}
	}

	return true
}

// validateAndCacheResponse validates the response and caches it
func (s *Server) validateAndCacheResponse(q dns.Question, resp *dns.Msg, group string) error {
	if resp == nil {
		return errors.New("nil response")
	}

	// Only cache successful responses
	if resp.Rcode != dns.RcodeSuccess {
		return nil
	}

	// Cache the response in the appropriate cache
	cacheKey := s.getCacheKey(q)
	switch group {
	case "domestic":
		s.cacheManager.GetDomestic().Set(cacheKey, resp)
	case "foreign":
		s.cacheManager.GetForeign().Set(cacheKey, resp)
	default:
		// Cache in both caches for "both" group
		s.cacheManager.GetDomestic().Set(cacheKey, resp)
		s.cacheManager.GetForeign().Set(cacheKey, resp)
	}

	log.Printf("Cached response for %s %s", dns.TypeToString[q.Qtype], q.Name)

	return nil
}

// sendResponse sends the DNS response to the client
func (s *Server) sendResponse(w dns.ResponseWriter, r, resp *dns.Msg) {
	// Set response ID to match request ID
	resp.MsgHdr.Id = r.MsgHdr.Id
	resp.MsgHdr.Opcode = r.MsgHdr.Opcode
	resp.MsgHdr.RecursionDesired = r.MsgHdr.RecursionDesired
	resp.MsgHdr.RecursionAvailable = true
	resp.MsgHdr.CheckingDisabled = r.MsgHdr.CheckingDisabled
	resp.MsgHdr.Zero = r.MsgHdr.Zero
	resp.MsgHdr.AuthenticatedData = r.MsgHdr.AuthenticatedData

	// Send response
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("Error sending DNS response: %v", err)
	}
}

// sendEmptyResponse sends an empty response with the given RCODE
func (s *Server) sendEmptyResponse(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	resp := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 r.MsgHdr.Id,
			Opcode:             r.MsgHdr.Opcode,
			Rcode:              rcode,
			RecursionDesired:   r.MsgHdr.RecursionDesired,
			RecursionAvailable: true,
		},
		Question: r.Question,
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("Error sending empty DNS response: %v", err)
	}
}

// startPreRefresh starts the pre-refresh process
func (s *Server) startPreRefresh() {
	s.preRefreshTicker = time.NewTicker(s.config.PreRefreshInterval)
	s.preRefreshWg.Add(1)

	go func() {
		defer s.preRefreshWg.Done()
		log.Printf("Starting pre-refresh with interval %v, threshold %.2f", s.config.PreRefreshInterval, s.config.PreRefreshThreshold)

		for {
			select {
			case <-s.ctx.Done():
				log.Println("Stopping pre-refresh")
				return
			case <-s.preRefreshTicker.C:
				s.performPreRefresh()
			}
		}
	}()
}

// performPreRefresh performs the pre-refresh process
func (s *Server) performPreRefresh() {
	// Get expiring keys from both caches
	domesticExpiringKeys := s.cacheManager.GetDomestic().GetExpiringKeys(s.config.PreRefreshThreshold)
	foreignExpiringKeys := s.cacheManager.GetForeign().GetExpiringKeys(s.config.PreRefreshThreshold)

	// Combine and deduplicate keys
	expiringKeys := make(map[string]string)
	for _, key := range domesticExpiringKeys {
		expiringKeys[key] = "domestic"
	}
	for _, key := range foreignExpiringKeys {
		expiringKeys[key] = "foreign"
	}

	if len(expiringKeys) == 0 {
		log.Println("No expiring keys to pre-refresh")
		return
	}

	// Limit the number of keys processed per run to avoid blocking
	maxKeysPerRun := 1000
	if len(expiringKeys) > maxKeysPerRun {
		// Only process the first maxKeysPerRun keys
		temp := make(map[string]string, maxKeysPerRun)
		count := 0
		for k, v := range expiringKeys {
			if count >= maxKeysPerRun {
				break
			}
			temp[k] = v
			count++
		}
		expiringKeys = temp
	}

	log.Printf("Found %d expiring keys, will pre-refresh %d keys in background", len(expiringKeys), len(expiringKeys))

	// Use a semaphore to control concurrency
	sem := make(chan struct{}, s.config.PreRefreshMaxConcurrency)

	// Run pre-refresh in background without waiting
	go func() {
		var wg sync.WaitGroup
		for key, group := range expiringKeys {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore

			go func(key, group string) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore

				s.preRefreshKey(key, group)
			}(key, group)
		}
		wg.Wait()
		log.Printf("Background pre-refresh completed for %d keys", len(expiringKeys))
	}()
}

// preRefreshKey pre-refreshes a single cache key
func (s *Server) preRefreshKey(key, group string) {
	// Parse cache key to get domain and query type
	// Cache key format: "domain|type|class"
	parts := strings.Split(key, "|")
	if len(parts) != 3 {
		log.Printf("Invalid cache key format: %s", key)
		return
	}

	domain := parts[0]
	typeStr := parts[1]
	classStr := parts[2]

	// Parse query type
	qtype, err := strconv.Atoi(typeStr)
	if err != nil {
		log.Printf("Failed to parse query type from key %s: %v", key, err)
		return
	}

	// Parse query class
	qclass, err := strconv.Atoi(classStr)
	if err != nil {
		log.Printf("Failed to parse query class from key %s: %v", key, err)
		return
	}

	// Create a DNS query message
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{
				Name:   domain,
				Qtype:  uint16(qtype),
				Qclass: uint16(qclass),
			},
		},
	}

	// Set DO bit for DNSSEC
	m.SetEdns0(4096, true)

	// Determine which pool to use
	var pool *upstream.Pool
	switch group {
	case "domestic":
		pool = s.domesticPool
	case "foreign":
		pool = s.foreignPool
	default:
		log.Printf("Unknown group %s for key %s", group, key)
		return
	}

	if pool == nil {
		log.Printf("No upstream pool available for group %s", group)
		return
	}

	// Refresh the cache entry with retry
	var resp *dns.Msg
	var err2 error
	for i := 0; i < s.config.PreRefreshRetryCount; i++ {
		ctx, cancel := context.WithTimeout(s.ctx, s.config.QueryTimeout)
		resp, err2 = pool.Exchange(ctx, m)
		cancel()

		if err2 == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			// Cache the new response
			cacheKey := s.getCacheKey(m.Question[0])
			switch group {
			case "domestic":
				s.cacheManager.GetDomestic().Set(cacheKey, resp)
			case "foreign":
				s.cacheManager.GetForeign().Set(cacheKey, resp)
			}
			log.Printf("Successfully pre-refreshed %s %s", dns.TypeToString[m.Question[0].Qtype], domain)
			return
		}

		// Wait before retrying
		time.Sleep(500 * time.Millisecond)
	}

	log.Printf("Failed to pre-refresh %s %s after %d attempts: %v", dns.TypeToString[m.Question[0].Qtype], domain, s.config.PreRefreshRetryCount, err2)
}

// Addr returns the server's listening address
func (s *Server) Addr() string {
	return s.config.ListenAddr
}

// Close closes the server and releases resources
func (s *Server) Close() error {
	s.Stop()
	return nil
}
