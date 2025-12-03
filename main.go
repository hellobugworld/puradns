package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hellobugworld/puradns/internal/cache"
	"github.com/hellobugworld/puradns/internal/config"
	"github.com/hellobugworld/puradns/internal/resources"
	"github.com/hellobugworld/puradns/internal/server"
	"github.com/hellobugworld/puradns/internal/upstream"
)

func main() {
	// 解析命令行参数
	configPath := flag.String("config", "puradns.yaml", "Path to configuration file")
	flag.Parse()

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Convert upstream config to server format
	domesticClients := make([]*upstream.Config, 0, len(cfg.UpstreamConfig.Domestic))
	for _, srv := range cfg.UpstreamConfig.Domestic {
		domesticClients = append(domesticClients, &upstream.Config{
			Addr:      srv.Addr,
			Protocol:  upstream.Protocol(srv.Protocol),
			Timeout:   cfg.UpstreamConfig.QueryTimeout,
			Retry:     3,
			Bootstrap: cfg.UpstreamConfig.BootstrapDNS,
			TLSConfig: upstream.TLSConfig{
				ServerName: srv.SNI,
			},
		})
	}

	foreignClients := make([]*upstream.Config, 0, len(cfg.UpstreamConfig.Foreign))
	for _, srv := range cfg.UpstreamConfig.Foreign {
		foreignClients = append(foreignClients, &upstream.Config{
			Addr:      srv.Addr,
			Protocol:  upstream.Protocol(srv.Protocol),
			Timeout:   cfg.UpstreamConfig.QueryTimeout,
			Retry:     3,
			Bootstrap: cfg.UpstreamConfig.BootstrapDNS,
			TLSConfig: upstream.TLSConfig{
				ServerName: srv.SNI,
			},
		})
	}

	// 解析缓存内存大小配置
	maxMemory, err := config.ParseMemorySize(cfg.CacheConfig.MaxMemory)
	if err != nil {
		log.Fatalf("Failed to parse cache max_memory: %v", err)
	}

	// 创建服务器实例
	srv, err := server.NewServer(&server.Config{
		ListenAddr:    cfg.ListenAddr,
		ListenAddrTCP: cfg.ListenAddr,
		UpstreamDomestic: &upstream.PoolConfig{
			Clients:     domesticClients,
			HealthCheck: 30 * time.Second,
		},
		UpstreamForeign: &upstream.PoolConfig{
			Clients:     foreignClients,
			HealthCheck: 30 * time.Second,
		},
		CacheConfig: &cache.GroupCacheConfig{
			DomesticConfig: cache.Config{
				Capacity:   cfg.CacheConfig.Capacity,
				MaxTTL:     cfg.CacheConfig.MaxTTL,
				MinTTL:     cfg.CacheConfig.MinTTL,
				CustomTTL:  cfg.CacheConfig.CustomTTL,
				MaxMemory:  maxMemory,
			},
			ForeignConfig: cache.Config{
				Capacity:   cfg.CacheConfig.Capacity,
				MaxTTL:     cfg.CacheConfig.MaxTTL,
				MinTTL:     cfg.CacheConfig.MinTTL,
				CustomTTL:  cfg.CacheConfig.CustomTTL,
				MaxMemory:  maxMemory,
			},
		},
		QueryTimeout:             cfg.UpstreamConfig.QueryTimeout,
		MaxRetries:               3,
		PreRefreshEnabled:        cfg.PreRefreshConfig.Enabled,
		PreRefreshThreshold:      cfg.PreRefreshConfig.Threshold,
		PreRefreshInterval:       cfg.PreRefreshConfig.Interval,
		PreRefreshMaxConcurrency: cfg.PreRefreshConfig.MaxConcurrency,
		PreRefreshRetryCount:     cfg.PreRefreshConfig.RetryCount,
		ResourceConfig: resources.ResourceConfig{
			ChinaIPPath:     cfg.ResourceConfig.ChinaIPPath,
			ChinaListPath:   cfg.ResourceConfig.ChinaListPath,
			GFWListPath:     cfg.ResourceConfig.GFWListPath,
			UpdateInterval:  cfg.ResourceConfig.UpdateInterval,
			URLs: struct {
				ChinaIP   string
				ChinaList string
				GFWList   string
			}{
				ChinaIP:   cfg.ResourceConfig.URLs.ChinaIP,
				ChinaList: cfg.ResourceConfig.URLs.ChinaList,
				GFWList:   cfg.ResourceConfig.URLs.GFWList,
			},
			DownloadTimeout: cfg.ResourceConfig.DownloadTimeout,
			MaxRetries:      cfg.ResourceConfig.MaxRetries,
			RetryDelay:      cfg.ResourceConfig.RetryDelay,
		},
	})
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// 启动服务器
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop()

	log.Printf("PuraDNS server started, listening on %s", cfg.ListenAddr)

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// 关闭服务器
	srv.Stop()

	log.Println("Server exiting")
}
