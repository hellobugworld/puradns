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
	PreRefreshMaxKeysPerRun  int                      `yaml:"pre_refresh_max_keys_per_run"` // 每次预刷新处理的最大键数量
	ResourceConfig           resources.ResourceConfig `yaml:"resource_config"`
	// GoroutinePool配置
	GoroutinePoolSize  int `yaml:"goroutinepool_size"`
	GoroutineQueueSize int `yaml:"goroutinepool_queue_size"`
}

// 定义常量，替换硬编码字符串
const (
	GroupDomestic = "domestic"
	GroupForeign  = "foreign"
	GroupBoth     = "both"
)

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
	// 并发控制
	reqLimiter chan struct{} // 请求限流通道
}

// NewServer creates a new DNS server
func NewServer(config *Config) (*Server, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:     config,
		ctx:        ctx,
		cancel:     cancel,
		reqLimiter: make(chan struct{}, config.GoroutinePoolSize*2), // 最大并发请求数为goroutine池大小的2倍
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
		if err := s.udpServer.ListenAndServe(); err != nil {
			// Log server errors
			log.Printf("UDP DNS server error: %v", err)
		}
	}()

	// Start TCP server
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.tcpServer.ListenAndServe(); err != nil {
			// Log server errors
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

	// 请求限流
	select {
	case s.reqLimiter <- struct{}{}:
		// 成功获取令牌，继续处理
	default:
		// 限流，返回服务器繁忙
		s.sendEmptyResponse(w, r, dns.RcodeServerFailure)
		return
	}

	// 将请求处理提交到goroutine池
	err := s.workerPool.Submit(func() {
		defer func() {
			// 释放令牌
			<-s.reqLimiter
		}()
		s.handleDNSRequestInternal(w, rCopy)
	})

	if err != nil {
		// 释放令牌
		<-s.reqLimiter
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
		s.sendEmptyResponse(w, r, dns.RcodeFormatError)
		return
	}

	q := r.Question[0]

	// Determine query group first to optimize cache lookup
	group, err := s.determineQueryGroup(q.Name)
	if err != nil {
		s.sendEmptyResponse(w, r, dns.RcodeServerFailure)
		return
	}

	// Check cache first, prioritize based on query group
	cacheKey := s.getCacheKey(q)
	var cachedResp *dns.Msg
	var found bool

	// 根据分流决策决定缓存查询策略
	switch group {
	case GroupDomestic:
		// domestic组：只查询国内缓存
		if cachedResp, found = s.cacheManager.GetDomestic().Get(cacheKey); found {
			s.sendResponse(w, r, cachedResp)
			return
		}
	case GroupForeign:
		// foreign组：只查询国外缓存
		if cachedResp, found = s.cacheManager.GetForeign().Get(cacheKey); found {
			s.sendResponse(w, r, cachedResp)
			return
		}
	case GroupBoth:
		// "both" group: 优先查询国内缓存，再查询国外缓存
		// 国内缓存查询
		if cachedResp, found = s.cacheManager.GetDomestic().Get(cacheKey); found {
			s.sendResponse(w, r, cachedResp)
			return
		}
		// 国外缓存查询
		if cachedResp, found = s.cacheManager.GetForeign().Get(cacheKey); found {
			s.sendResponse(w, r, cachedResp)
			return
		}
	}

	// 所有缓存都未命中，向上游发起请求
	resp, err := s.performQuery(ctx, r, group)
	if err != nil {
		s.sendEmptyResponse(w, r, dns.RcodeServerFailure)
		return
	}

	// Validate and cache response
	if err := s.validateAndCacheResponse(q, resp, group); err != nil {
		// 缓存失败不影响响应返回
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
		group = GroupDomestic
	case diverter.DecisionForeign:
		group = GroupForeign
	case diverter.DecisionBoth:
		group = GroupBoth
	default:
		group = GroupBoth
	}

	return group, nil
}

// performQuery performs the DNS query using the appropriate upstream pool
func (s *Server) performQuery(ctx context.Context, r *dns.Msg, group string) (*dns.Msg, error) {
	var pool *upstream.Pool

	// Select upstream pool based on group
	switch group {
	case GroupDomestic:
		pool = s.domesticPool
	case GroupForeign:
		pool = s.foreignPool
	case GroupBoth:
		// For both groups, query both pools and return the best result
		return s.queryBothPools(ctx, r)
	default:
		// For unknown groups, query both pools and return the best result
		return s.queryBothPools(ctx, r)
	}

	// Check if pool is available
	if pool == nil {
		return nil, fmt.Errorf("no upstream pool available for group: %s", group)
	}

	// Create independent context for single pool queries to avoid main context timeout issues
	queryCtx, queryCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer queryCancel()

	// Use a buffered channel to avoid goroutine leak
	resultChan := make(chan struct {
		resp *dns.Msg
		err  error
	}, 1)

	// Perform DNS query in a separate goroutine to avoid blocking
	go func() {
		resp, err := pool.Exchange(queryCtx, r)
		resultChan <- struct {
			resp *dns.Msg
			err  error
		}{resp, err}
	}()

	// Wait for result or context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-queryCtx.Done():
		return nil, queryCtx.Err()
	case result := <-resultChan:
		return result.resp, result.err
	}
}

// queryBothPools queries both domestic and foreign pools and returns the best result
func (s *Server) queryBothPools(ctx context.Context, r *dns.Msg) (*dns.Msg, error) {
	// Set DO bit for DNSSEC support
	r.SetEdns0(4096, true)

	// 为国内DNS查询创建独立的上下文，避免被主上下文超时影响
	domesticCtx, domesticCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer domesticCancel()

	// 优先查询国内DNS
	if s.domesticPool != nil {
		msgCopy := r.Copy()
		resp, err := s.domesticPool.Exchange(domesticCtx, msgCopy)
		if err == nil && resp != nil {
			// 国内DNS查询成功，验证结果
			if resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError {
				// 结果有效，直接返回（包括NXDOMAIN）
				return resp, nil
			}
		}
	}

	// 国内DNS查询失败或结果无效，查询国外DNS
	if s.foreignPool != nil {
		msgCopy := r.Copy()
		resp, err := s.foreignPool.Exchange(ctx, msgCopy)
		if err == nil && resp != nil {
			// 国外DNS查询成功，返回结果（包括NXDOMAIN）
			return resp, nil
		}
	}

	// 所有DNS查询都失败
	return nil, fmt.Errorf("all upstream DNS queries failed")
}

// 注意：以下函数已被queryBothPools的新实现替代，不再使用
// selectBestResult selects the best result between domestic and foreign responses
// isValidDomesticResponse checks if the domestic response is valid (not polluted)

// validateAndCacheResponse validates the response and caches it
func (s *Server) validateAndCacheResponse(q dns.Question, resp *dns.Msg, group string) error {
	if resp == nil {
		return errors.New("nil response")
	}

	// Cache successful responses and NXDOMAIN responses
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return nil
	}

	// Cache the response in the appropriate cache
	cacheKey := s.getCacheKey(q)
	switch group {
	case GroupDomestic:
		s.cacheManager.GetDomestic().Set(cacheKey, resp)
	case GroupForeign:
		s.cacheManager.GetForeign().Set(cacheKey, resp)
	case GroupBoth:
		// Cache in both caches for "both" group
		s.cacheManager.GetDomestic().Set(cacheKey, resp)
		s.cacheManager.GetForeign().Set(cacheKey, resp)
	default:
		// Cache in both caches for unknown group
		s.cacheManager.GetDomestic().Set(cacheKey, resp)
		s.cacheManager.GetForeign().Set(cacheKey, resp)
	}

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
	// 从对象池获取DNS消息对象
	resp := s.getMsgFromPool()
	defer s.putMsgToPool(resp) // 使用完毕后放回对象池

	// 设置响应头
	resp.MsgHdr.Id = r.MsgHdr.Id
	resp.MsgHdr.Opcode = r.MsgHdr.Opcode
	resp.MsgHdr.Rcode = rcode
	resp.MsgHdr.RecursionDesired = r.MsgHdr.RecursionDesired
	resp.MsgHdr.RecursionAvailable = true
	resp.Question = r.Question

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

		for {
			select {
			case <-s.ctx.Done():

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
		expiringKeys[key] = GroupDomestic
	}
	for _, key := range foreignExpiringKeys {
		expiringKeys[key] = GroupForeign
	}

	if len(expiringKeys) == 0 {

		return
	}

	// Limit the number of keys processed per run to avoid blocking
	maxKeysPerRun := s.config.PreRefreshMaxKeysPerRun
	if maxKeysPerRun <= 0 {
		maxKeysPerRun = 1000 // 默认值
	}
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

	}()
}

// preRefreshKey pre-refreshes a single cache key
func (s *Server) preRefreshKey(key, group string) {
	// Parse cache key to get domain and query type
	// Cache key format: "domain|type|class"
	parts := strings.Split(key, "|")
	if len(parts) != 3 {

		return
	}

	domain := parts[0]
	typeStr := parts[1]
	classStr := parts[2]

	// Parse query type
	qtype, err := strconv.Atoi(typeStr)
	if err != nil {

		return
	}

	// Parse query class
	qclass, err := strconv.Atoi(classStr)
	if err != nil {

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
	case GroupDomestic:
		pool = s.domesticPool
	case GroupForeign:
		pool = s.foreignPool
	default:

		return
	}

	if pool == nil {

		return
	}

	// Refresh the cache entry with retry
	var resp *dns.Msg
	var err2 error
	for i := 0; i < s.config.PreRefreshRetryCount; i++ {
		ctx, cancel := context.WithTimeout(s.ctx, s.config.QueryTimeout)
		resp, err2 = pool.Exchange(ctx, m)
		cancel()

		if err2 == nil && resp != nil && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
			// Cache the new response
			cacheKey := s.getCacheKey(m.Question[0])
			switch group {
			case GroupDomestic:
				s.cacheManager.GetDomestic().Set(cacheKey, resp)
			case GroupForeign:
				s.cacheManager.GetForeign().Set(cacheKey, resp)
			}

			return
		}

		// Wait before retrying
		time.Sleep(500 * time.Millisecond)
	}

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
