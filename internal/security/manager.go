package security

import (
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/hellobugworld/puradns/internal/errors"
)

// Config 安全配置
type Config struct {
	MaxQueriesPerSecond  int
	MaxResponseSize      int
	EnableDNSSEC         bool
	EnableQueryLogging   bool
	TrustedUpstreams     []string
	RestrictedQueryTypes []uint16
}

// Manager 安全管理器接口
type Manager interface {
	// CheckQuerySafety 检查查询是否安全
	CheckQuerySafety(query *dns.Msg, clientAddr string) error
	// ValidateResponse 验证上游响应
	ValidateResponse(response *dns.Msg, upstream string) error
}

// manager 安全管理器实现
type manager struct {
	config           Config
	rateLimiter      *RateLimiter
	trustedUpstreams map[string]bool
	restrictedTypes  map[uint16]bool
}

// NewManager 创建安全管理器
func NewManager(config Config) Manager {
	// 初始化可信上游服务器集合
	trustedUpstreams := make(map[string]bool)
	for _, upstream := range config.TrustedUpstreams {
		trustedUpstreams[upstream] = true
	}

	// 初始化受限查询类型集合
	restrictedTypes := make(map[uint16]bool)
	for _, qtype := range config.RestrictedQueryTypes {
		restrictedTypes[qtype] = true
	}

	return &manager{
		config:           config,
		rateLimiter:      NewRateLimiter(config.MaxQueriesPerSecond),
		trustedUpstreams: trustedUpstreams,
		restrictedTypes:  restrictedTypes,
	}
}

// CheckQuerySafety 检查查询是否安全
func (m *manager) CheckQuerySafety(query *dns.Msg, clientAddr string) error {
	// 检查查询速率
	if !m.rateLimiter.Allow(clientAddr) {
		return errors.NewSecurityError("query rate limit exceeded", nil)
	}

	// 检查查询类型是否受限
	if len(query.Question) > 0 {
		qtype := query.Question[0].Qtype
		if m.restrictedTypes[qtype] {
			return errors.NewSecurityError("restricted query type", nil)
		}
	}

	// 检查查询大小
	if query.Len() > 512 && query.IsEdns0() == nil {
		return errors.NewProtocolError("query too large for UDP without EDNS0", nil)
	}

	return nil
}

// ValidateResponse 验证上游响应
func (m *manager) ValidateResponse(response *dns.Msg, upstream string) error {
	// 检查上游是否可信
	if !m.trustedUpstreams[upstream] {
		return errors.NewSecurityError("untrusted upstream server", nil)
	}

	// 检查响应大小
	if response.Len() > m.config.MaxResponseSize {
		return errors.NewProtocolError("response too large", nil)
	}

	// 检查响应格式
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		// 记录非标准响应码，但不拒绝
		return nil
	}

	return nil
}

// RateLimiter 速率限制器
type RateLimiter struct {
	clientBuckets   sync.Map
	maxRate         int
	cleanupInterval time.Duration
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter(maxRate int) *RateLimiter {
	rl := &RateLimiter{
		maxRate:         maxRate,
		cleanupInterval: 5 * time.Minute,
	}

	// 启动清理协程
	go rl.cleanup()

	return rl
}

// Allow 检查是否允许查询
func (rl *RateLimiter) Allow(clientAddr string) bool {
	// 获取或创建客户端令牌桶
	bucket, _ := rl.clientBuckets.LoadOrStore(clientAddr, NewTokenBucket(rl.maxRate, rl.maxRate))

	tokenBucket := bucket.(*TokenBucket)
	return tokenBucket.Take(1)
}

// cleanup 清理过期令牌桶
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.clientBuckets.Range(func(key, value interface{}) bool {
			clientAddr := key.(string)
			bucket := value.(*TokenBucket)

			// 如果令牌桶长时间未使用，则删除
			if time.Since(bucket.LastUsed()) > rl.cleanupInterval {
				rl.clientBuckets.Delete(clientAddr)
			}

			return true
		})
	}
}

// TokenBucket 令牌桶实现
type TokenBucket struct {
	capacity   int
	rate       int
	tokens     int
	lastUpdate time.Time
	lastUsed   time.Time
	mu         sync.Mutex
}

// NewTokenBucket 创建令牌桶
func NewTokenBucket(capacity, rate int) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		rate:       rate,
		tokens:     capacity,
		lastUpdate: time.Now(),
		lastUsed:   time.Now(),
	}
}

// Take 获取令牌
func (tb *TokenBucket) Take(count int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// 更新最后使用时间
	tb.lastUsed = time.Now()

	// 计算新增令牌数
	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	newTokens := int(elapsed * float64(tb.rate))

	// 更新令牌数
	tb.tokens += newTokens
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	// 更新最后更新时间
	tb.lastUpdate = now

	// 检查是否有足够令牌
	if tb.tokens >= count {
		tb.tokens -= count
		return true
	}

	return false
}

// LastUsed 获取最后使用时间
func (tb *TokenBucket) LastUsed() time.Time {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.lastUsed
}
