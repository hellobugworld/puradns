package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 表示PuraDNS的完整配置
type Config struct {
	// 服务器配置
	ListenAddr string `yaml:"listen_addr"`

	// 资源文件配置
	ResourceConfig ResourceConfig `yaml:"resource"`

	// 缓存配置
	CacheConfig CacheConfig `yaml:"cache"`

	// 预刷新配置
	PreRefreshConfig PreRefreshConfig `yaml:"pre_refresh"`

	// 上游DNS配置
	UpstreamConfig UpstreamConfig `yaml:"upstream"`

	// 安全配置
	SecurityConfig SecurityConfig `yaml:"security"`

	// 调试配置
	DebugConfig DebugConfig `yaml:"debug"`
}

// ResourceURLs 资源文件URL配置
type ResourceURLs struct {
	ChinaIP   string `yaml:"china_ip"`
	ChinaList string `yaml:"china_list"`
	GFWList   string `yaml:"gfw_list"`
}

// ResourceConfig 资源文件配置
type ResourceConfig struct {
	ChinaIPPath     string        `yaml:"china_ip_path"`
	ChinaListPath   string        `yaml:"china_list_path"`
	GFWListPath     string        `yaml:"gfw_list_path"`
	UpdateInterval  time.Duration `yaml:"update_interval"`
	URLs            ResourceURLs  `yaml:"urls"`
	DownloadTimeout time.Duration `yaml:"download_timeout"`
	MaxRetries      int           `yaml:"max_retries"`
	RetryDelay      time.Duration `yaml:"retry_delay"`
}

// CacheConfig 缓存配置
type CacheConfig struct {
	Enabled    bool          `yaml:"enabled"`
	Capacity   int           `yaml:"capacity"`
	MaxTTL     time.Duration `yaml:"max_ttl"`
	MinTTL     time.Duration `yaml:"min_ttl,omitempty"` // 最小TTL，可选
	CustomTTL  time.Duration `yaml:"custom_ttl,omitempty"` // 自定义TTL，可选，优先级高于DNS响应中的TTL
	MaxMemory  string        `yaml:"max_memory"`
}

// PreRefreshConfig 预刷新配置
type PreRefreshConfig struct {
	Enabled        bool          `yaml:"enabled"`
	Threshold      float64       `yaml:"threshold"`
	Interval       time.Duration `yaml:"interval"`
	MaxConcurrency int           `yaml:"max_concurrency"`
	RetryCount     int           `yaml:"retry_count"`
}

// UpstreamConfig 上游DNS配置
type UpstreamConfig struct {
	Domestic     []UpstreamServer `yaml:"domestic"`
	Foreign      []UpstreamServer `yaml:"foreign"`
	BootstrapDNS []string         `yaml:"bootstrap_dns"`
	QueryTimeout time.Duration    `yaml:"query_timeout"`
}

// UpstreamServer 上游DNS服务器配置
type UpstreamServer struct {
	Addr      string `yaml:"addr"`
	Protocol  string `yaml:"protocol"`
	SNI       string `yaml:"sni,omitempty"`
	ECHConfig string `yaml:"ech_config,omitempty"` // ECH配置，十六进制字符串
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	MaxQueriesPerSecond  int      `yaml:"max_queries_per_second"`
	MaxResponseSize      int      `yaml:"max_response_size"`
	EnableDNSSEC         bool     `yaml:"enable_dnssec"`
	EnableQueryLogging   bool     `yaml:"enable_query_logging"`
	TrustedUpstreams     []string `yaml:"trusted_upstreams"`
	RestrictedQueryTypes []uint16 `yaml:"restricted_query_types"`
}

// DebugConfig 调试配置
type DebugConfig struct {
	Enabled         bool   `yaml:"enabled"`
	LogLevel        string `yaml:"log_level"`
	VerboseQuery    bool   `yaml:"verbose_query"`
	VerboseCache    bool   `yaml:"verbose_cache"`
	VerboseDiverter bool   `yaml:"verbose_diverter"`
	VerboseUpstream bool   `yaml:"verbose_upstream"`
}

// Load 从文件加载配置
func Load(path string) (*Config, error) {
	// 读取配置文件
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// 解析YAML配置
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// 设置默认值
	cfg.setDefaults()

	return &cfg, nil
}

// setDefaults 设置配置默认值
func (c *Config) setDefaults() {
	// 所有配置都从yaml文件读取，不设置默认值
	// 确保配置文件中包含所有必要的配置项
}

// ParseMemorySize 解析内存大小字符串（如"128MB"）为字节数
func ParseMemorySize(sizeStr string) (int64, error) {
	if sizeStr == "" {
		return 0, nil
	}

	var size int64
	var unit string
	_, err := fmt.Sscanf(sizeStr, "%d%s", &size, &unit)
	if err != nil {
		// 尝试直接解析为数字
		if _, err := fmt.Sscanf(sizeStr, "%d", &size); err == nil {
			return size, nil
		}
		return 0, fmt.Errorf("invalid memory size format: %s", sizeStr)
	}

	switch strings.ToUpper(unit) {
	case "B":
		return size, nil
	case "KB":
		return size * 1024, nil
	case "MB":
		return size * 1024 * 1024, nil
	case "GB":
		return size * 1024 * 1024 * 1024, nil
	case "TB":
		return size * 1024 * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("unsupported memory unit: %s", unit)
	}
}
