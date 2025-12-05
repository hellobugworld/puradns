package cache

import (
	"container/list"
	"context"
	"hash/fnv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Cache DNS缓存接口
type Cache interface {
	// Get 获取缓存项
	Get(key string) (*dns.Msg, bool)
	// Set 设置缓存项
	Set(key string, msg *dns.Msg)
	// Delete 删除缓存项
	Delete(key string)
	// Clear 清空缓存
	Clear()
	// Len 获取缓存大小
	Len() int
	// GetExpiringKeys 获取即将过期的键
	GetExpiringKeys(threshold float64) []string
	// Stats 获取缓存统计信息
	Stats() CacheStats
}

// Config 缓存配置
type Config struct {
	Capacity  int
	MaxTTL    time.Duration
	MinTTL    time.Duration // 最小TTL，可选
	CustomTTL time.Duration // 自定义TTL，可选，优先级高于DNS响应中的TTL
	MaxMemory int64
}

// CacheEntry 缓存条目
type CacheEntry struct {
	Response    *dns.Msg
	ExpiresAt   time.Time
	OriginalTTL time.Duration // 原始TTL，用于预刷新计算
	Key         string
	Element     *list.Element
}

// lruCache LRU缓存实现
type lruCache struct {
	capacity      int
	maxTTL        time.Duration
	minTTL        time.Duration // 最小TTL
	customTTL     time.Duration // 自定义TTL
	maxMemory     int64
	currentMemory int64
	cache         map[string]*CacheEntry
	list          *list.List
	mutex         sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	stats         CacheStats
}

// CacheStats 缓存统计信息
type CacheStats struct {
	Hits        int64
	Misses      int64
	Evictions   int64
	Expirations int64
	MemoryUsage int64
	EntryCount  int64
}

// 下一个2的幂
func nextPowerOfTwo(n int) int {
	if n <= 0 {
		return 1
	}
	// 将n减1，然后取或运算，最后加1
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}

// shardedCache 分片缓存实现
// 将缓存分为多个分片，每个分片有自己的锁，减少锁竞争
// 每个分片都是一个独立的lruCache实例
// 使用fnv-1a哈希算法将key均匀分布到不同的分片

type shardedCache struct {
	shards    []Cache
	numShards int
	shardMask uint32
}

// NewShardedCache 创建分片缓存实例
func NewShardedCache(config Config, numShards int) Cache {
	if numShards <= 0 {
		numShards = 256 // 默认256个分片
	}
	// 确保numShards是2的幂，便于使用位运算快速定位分片
	numShards = nextPowerOfTwo(numShards)

	shards := make([]Cache, numShards)
	for i := 0; i < numShards; i++ {
		// 每个分片都是一个独立的lruCache实例
		ctx, cancel := context.WithCancel(context.Background())
		shards[i] = &lruCache{
			capacity:      config.Capacity / numShards, // 平均分配容量
			maxTTL:        config.MaxTTL,
			minTTL:        config.MinTTL,
			customTTL:     config.CustomTTL,
			maxMemory:     config.MaxMemory / int64(numShards),
			currentMemory: 0,
			cache:         make(map[string]*CacheEntry),
			list:          list.New(),
			ctx:           ctx,
			cancel:        cancel,
			stats:         CacheStats{},
		}
		// 启动后台过期检查
		go shards[i].(*lruCache).backgroundExpiryCheck()
	}

	return &shardedCache{
		shards:    shards,
		numShards: numShards,
		shardMask: uint32(numShards - 1),
	}
}

// getShardIndex 根据key计算分片索引
func (sc *shardedCache) getShardIndex(key string) int {
	// 使用fnv-1a哈希算法计算key的哈希值
	hash := fnv.New32a()
	hash.Write([]byte(key))
	// 使用位运算快速定位分片，避免取模运算的开销
	return int(hash.Sum32() & sc.shardMask)
}

// Get 获取缓存项
func (sc *shardedCache) Get(key string) (*dns.Msg, bool) {
	shardIndex := sc.getShardIndex(key)
	return sc.shards[shardIndex].Get(key)
}

// Set 设置缓存项
func (sc *shardedCache) Set(key string, msg *dns.Msg) {
	shardIndex := sc.getShardIndex(key)
	sc.shards[shardIndex].Set(key, msg)
}

// Delete 删除缓存项
func (sc *shardedCache) Delete(key string) {
	shardIndex := sc.getShardIndex(key)
	sc.shards[shardIndex].Delete(key)
}

// Clear 清空缓存
func (sc *shardedCache) Clear() {
	// 清空所有分片
	for _, shard := range sc.shards {
		shard.Clear()
	}
}

// Len 获取缓存大小
func (sc *shardedCache) Len() int {
	// 计算所有分片的总大小
	var total int
	for _, shard := range sc.shards {
		total += shard.Len()
	}
	return total
}

// GetExpiringKeys 获取即将过期的键
func (sc *shardedCache) GetExpiringKeys(threshold float64) []string {
	// 获取所有分片的即将过期的键
	var expiringKeys []string
	for _, shard := range sc.shards {
		keys := shard.GetExpiringKeys(threshold)
		expiringKeys = append(expiringKeys, keys...)
	}
	return expiringKeys
}

// Stats 获取缓存统计信息
func (sc *shardedCache) Stats() CacheStats {
	// 合并所有分片的统计信息
	var totalStats CacheStats
	for _, shard := range sc.shards {
		stats := shard.Stats()
		totalStats.Hits += stats.Hits
		totalStats.Misses += stats.Misses
		totalStats.Evictions += stats.Evictions
		totalStats.Expirations += stats.Expirations
		totalStats.MemoryUsage += stats.MemoryUsage
		totalStats.EntryCount += stats.EntryCount
	}
	return totalStats
}

// NewCache 创建缓存实例
func NewCache(config Config) Cache {
	// 默认使用256个分片创建分片缓存
	return NewShardedCache(config, 256)
}

// Get 获取缓存项
func (c *lruCache) Get(key string) (*dns.Msg, bool) {
	// 先尝试只读检查
	c.mutex.RLock()
	entry, ok := c.cache[key]
	if !ok {
		c.stats.Misses++
		c.mutex.RUnlock()
		return nil, false
	}

	// 检查是否过期
	if time.Now().After(entry.ExpiresAt) {
		c.mutex.RUnlock()
		// 需要写锁来删除过期条目
		c.mutex.Lock()
		defer c.mutex.Unlock()
		// 再次检查，防止并发删除
		if entry, ok := c.cache[key]; ok && time.Now().After(entry.ExpiresAt) {
			c.removeEntry(entry)
			c.stats.Expirations++
			c.stats.Misses++
			return nil, false
		}
		// 条目可能已经被其他goroutine更新或删除
		return nil, false
	}

	// 需要写锁来更新LRU位置
	c.mutex.RUnlock()
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// 再次检查，防止并发修改
	if entry, ok := c.cache[key]; ok && !time.Now().After(entry.ExpiresAt) {
		// 更新LRU位置
		c.list.MoveToFront(entry.Element)
		c.stats.Hits++
		return entry.Response, true
	}

	c.stats.Misses++
	return nil, false
}

// Set 设置缓存项
func (c *lruCache) Set(key string, msg *dns.Msg) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// 计算消息大小
	msgData, err := msg.Pack()
	msgSize := int64(512) // 默认大小
	if err == nil {
		msgSize = int64(len(msgData))
	}

	// 计算TTL
	ttl := c.calculateTTL(msg)
	expiresAt := time.Now().Add(ttl)

	// 检查是否已存在
	if entry, ok := c.cache[key]; ok {
		// 更新现有条目
		// 减去旧消息大小
		oldData, _ := entry.Response.Pack()
		c.currentMemory -= int64(len(oldData))
		// 加上新消息大小
		c.currentMemory += msgSize
		// 更新条目
		entry.Response = msg
		entry.ExpiresAt = expiresAt
		entry.OriginalTTL = ttl // 更新原始TTL
		c.list.MoveToFront(entry.Element)
		c.stats.MemoryUsage = c.currentMemory
		return
	}

	// 确保有足够的内存空间
	for (len(c.cache) >= c.capacity || (c.maxMemory > 0 && c.currentMemory+msgSize > c.maxMemory)) && len(c.cache) > 0 {
		c.removeOldest()
		c.stats.Evictions++
	}

	// 创建新条目
	entry := &CacheEntry{
		Response:    msg,
		ExpiresAt:   expiresAt,
		OriginalTTL: ttl, // 记录原始TTL
		Key:         key,
	}

	// 添加到链表和映射
	element := c.list.PushFront(entry)
	entry.Element = element
	c.cache[key] = entry
	// 更新内存使用
	c.currentMemory += msgSize
	c.stats.MemoryUsage = c.currentMemory
	c.stats.EntryCount = int64(len(c.cache))
}

// Delete 删除缓存项
func (c *lruCache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if entry, ok := c.cache[key]; ok {
		c.removeEntry(entry)
	}
}

// Len 获取缓存大小
func (c *lruCache) Len() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return len(c.cache)
}

// GetExpiringKeys 获取即将过期的键
func (c *lruCache) GetExpiringKeys(threshold float64) []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var expiringKeys []string
	now := time.Now()

	for key, entry := range c.cache {
		// 计算剩余时间
		remaining := entry.ExpiresAt.Sub(now)
		if remaining <= 0 {
			continue
		}

		// 使用原始TTL计算剩余比例
		if entry.OriginalTTL <= 0 {
			continue
		}

		// 计算剩余时间比例
		remainingRatio := remaining.Seconds() / entry.OriginalTTL.Seconds()
		if remainingRatio <= threshold {
			expiringKeys = append(expiringKeys, key)
		}
	}

	return expiringKeys
}

// backgroundExpiryCheck 后台过期检查
func (c *lruCache) backgroundExpiryCheck() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.removeExpiredEntries()
		}
	}
}

// removeExpiredEntries 删除所有过期的条目
func (c *lruCache) removeExpiredEntries() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	var expiredCount int64

	// 遍历所有条目，删除过期的
	for key, entry := range c.cache {
		if now.After(entry.ExpiresAt) {
			// 减去条目大小
			oldData, _ := entry.Response.Pack()
			c.currentMemory -= int64(len(oldData))
			// 删除条目
			c.list.Remove(entry.Element)
			delete(c.cache, key)
			expiredCount++
		}
	}

	// 更新统计
	if expiredCount > 0 {
		c.stats.Expirations += expiredCount
		c.stats.MemoryUsage = c.currentMemory
		c.stats.EntryCount = int64(len(c.cache))
	}
}

// Clear 清空缓存
func (c *lruCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache = make(map[string]*CacheEntry)
	c.list.Init()
	c.currentMemory = 0
	// 重置统计
	c.stats = CacheStats{}
}

// Stats 获取缓存统计信息
func (c *lruCache) Stats() CacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.stats
}

// calculateTTL 计算TTL
func (c *lruCache) calculateTTL(msg *dns.Msg) time.Duration {
	var ttl time.Duration

	// 1. 如果配置了自定义TTL，直接使用
	if c.customTTL > 0 {
		ttl = c.customTTL
	} else {
		// 从DNS响应中获取最小TTL
		minTTL := uint32(0)

		for _, rr := range msg.Answer {
			if rr.Header().Ttl < minTTL || minTTL == 0 {
				minTTL = rr.Header().Ttl
			}
		}

		for _, rr := range msg.Ns {
			if rr.Header().Ttl < minTTL || minTTL == 0 {
				minTTL = rr.Header().Ttl
			}
		}

		for _, rr := range msg.Extra {
			// 跳过OPT记录（Type为0），其TTL字段通常为0，不应该影响缓存TTL
			if rr.Header().Rrtype == 0 {
				continue
			}
			if rr.Header().Ttl < minTTL || minTTL == 0 {
				minTTL = rr.Header().Ttl
			}
		}

		// 默认TTL为300秒
		if minTTL == 0 {
			minTTL = 300
		}

		// 转换为时间.Duration
		ttl = time.Duration(minTTL) * time.Second
	}

	// 2. 应用最小TTL限制
	if c.minTTL > 0 && ttl < c.minTTL {
		ttl = c.minTTL
	}

	// 3. 应用最大TTL限制，只有当maxTTL > 0时才生效
	if c.maxTTL > 0 && ttl > c.maxTTL {
		ttl = c.maxTTL
	}

	return ttl
}

// removeOldest 删除最旧的条目
func (c *lruCache) removeOldest() {
	element := c.list.Back()
	if element == nil {
		return
	}

	entry := element.Value.(*CacheEntry)
	c.removeEntry(entry)
}

// removeEntry 删除指定条目
func (c *lruCache) removeEntry(entry *CacheEntry) {
	// 减去条目大小
	oldData, _ := entry.Response.Pack()
	c.currentMemory -= int64(len(oldData))
	// 更新统计
	c.stats.MemoryUsage = c.currentMemory
	c.stats.EntryCount = int64(len(c.cache)) - 1
	// 删除条目
	c.list.Remove(entry.Element)
	delete(c.cache, entry.Key)
}

// GroupCache 分组缓存
type GroupCache struct {
	domestic Cache
	foreign  Cache
}

// GroupCacheConfig 分组缓存配置
type GroupCacheConfig struct {
	DomesticConfig Config
	ForeignConfig  Config
}

// NewGroupCache 创建分组缓存
func NewGroupCache(config GroupCacheConfig) *GroupCache {
	return &GroupCache{
		domestic: NewCache(config.DomesticConfig),
		foreign:  NewCache(config.ForeignConfig),
	}
}

// GetDomestic 获取国内缓存
func (gc *GroupCache) GetDomestic() Cache {
	return gc.domestic
}

// GetForeign 获取国外缓存
func (gc *GroupCache) GetForeign() Cache {
	return gc.foreign
}
