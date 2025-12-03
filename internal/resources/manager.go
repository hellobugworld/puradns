package resources

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hellobugworld/puradns/internal/errors"
)

// Manager 资源管理器
type Manager struct {
	chinaIPs   *IPSet
	chinaList  *DomainSet
	gfwList    *DomainSet
	config     ResourceConfig
	mutex      sync.RWMutex
	updateChan chan struct{}
	stopChan   chan struct{}
}

// ResourceConfig 资源配置
type ResourceConfig struct {
	ChinaIPPath    string
	ChinaListPath  string
	GFWListPath    string
	UpdateInterval time.Duration
	URLs           struct {
		ChinaIP   string
		ChinaList string
		GFWList   string
	}
	DownloadTimeout time.Duration
	MaxRetries      int
	RetryDelay      time.Duration
}

// IPSet IP集合
type IPSet struct {
	ipv4Cidrs []*net.IPNet
	ipv6Cidrs []*net.IPNet
	mutex     sync.RWMutex
}

// TrieNode Trie树节点
type TrieNode struct {
	children map[string]*TrieNode
	isEnd    bool
}

// DomainSet 域名集合
type DomainSet struct {
	domains map[string]bool
	trie    *TrieNode
	mutex   sync.RWMutex
}

// NewManager 创建资源管理器
func NewManager(config ResourceConfig) (*Manager, error) {
	m := &Manager{
		chinaIPs:   &IPSet{ipv4Cidrs: make([]*net.IPNet, 0), ipv6Cidrs: make([]*net.IPNet, 0)},
		chinaList:  &DomainSet{domains: make(map[string]bool), trie: newTrieNode()},
		gfwList:    &DomainSet{domains: make(map[string]bool), trie: newTrieNode()},
		config:     config,
		updateChan: make(chan struct{}),
		stopChan:   make(chan struct{}),
	}

	// 初始加载资源文件
	if err := m.loadAll(); err != nil {
		return nil, err
	}

	// 启动定期更新协程
	go m.startUpdateLoop()

	return m, nil
}

// Close 关闭资源管理器
func (m *Manager) Close() {
	select {
	case <-m.stopChan:
		// 通道已经关闭，避免重复关闭
	default:
		close(m.stopChan)
	}
}

// IsChinaIP 检查IP是否在国内IP段
func (m *Manager) IsChinaIP(ip net.IP) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.chinaIPs.Contains(ip)
}

// IsChinaDomain 检查域名是否在国内域名列表
func (m *Manager) IsChinaDomain(domain string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 将域名转换为小写，确保匹配不区分大小写
	domain = strings.ToLower(domain)

	// 使用DomainSet的Match方法，利用Trie树进行高效匹配
	return m.chinaList.Match(domain)
}

// IsGFWDomain 检查域名是否在GFW列表
func (m *Manager) IsGFWDomain(domain string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 将域名转换为小写，确保匹配不区分大小写
	domain = strings.ToLower(domain)

	// 使用DomainSet的Match方法，利用Trie树进行高效匹配
	return m.gfwList.Match(domain)
}

// loadAll 加载所有资源文件
func (m *Manager) loadAll() error {
	if err := m.loadChinaIP(); err != nil {
		return err
	}
	if err := m.loadChinaList(); err != nil {
		return err
	}
	if err := m.loadGFWList(); err != nil {
		return err
	}
	return nil
}

// loadChinaIP 加载国内IP段
func (m *Manager) loadChinaIP() error {
	file, err := os.Open(m.config.ChinaIPPath)
	if err != nil {
		return errors.NewResourceError(fmt.Sprintf("failed to open china-ip.txt: %v", err), err)
	}
	defer file.Close()

	newIPSet := &IPSet{
		ipv4Cidrs: make([]*net.IPNet, 0),
		ipv6Cidrs: make([]*net.IPNet, 0),
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		_, cidr, err := net.ParseCIDR(line)
		if err != nil {
			continue // 跳过无效的CIDR
		}

		// 根据IP类型将CIDR添加到对应的切片
		if cidr.IP.To4() != nil {
			// IPv4地址
			newIPSet.ipv4Cidrs = append(newIPSet.ipv4Cidrs, cidr)
		} else {
			// IPv6地址
			newIPSet.ipv6Cidrs = append(newIPSet.ipv6Cidrs, cidr)
		}
	}

	if err := scanner.Err(); err != nil {
		return errors.NewResourceError(fmt.Sprintf("failed to read china-ip.txt: %v", err), err)
	}

	m.mutex.Lock()
	m.chinaIPs = newIPSet
	m.mutex.Unlock()

	return nil
}

// loadChinaList 加载国内域名列表
func (m *Manager) loadChinaList() error {
	return m.loadDomainSet(m.config.ChinaListPath, m.chinaList)
}

// loadGFWList 加载GFW域名列表
func (m *Manager) loadGFWList() error {
	return m.loadDomainSet(m.config.GFWListPath, m.gfwList)
}

// loadDomainSet 加载域名集合
func (m *Manager) loadDomainSet(path string, domainSet *DomainSet) error {
	// 打开文件
	file, err := os.Open(path)
	if err != nil {
		log.Printf("Failed to open %s: %v", path, err)
		return errors.NewResourceError(fmt.Sprintf("failed to open %s: %v", path, err), err)
	}
	defer file.Close()

	newDomainSet := &DomainSet{domains: make(map[string]bool), trie: newTrieNode()}

	scanner := bufio.NewScanner(file)
	lineCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lineCount++

		// 将域名转换为小写，确保匹配不区分大小写
		line = strings.ToLower(line)

		// 处理通配符域名
		if strings.HasPrefix(line, "*") {
			suffix := strings.TrimPrefix(line, "*")
			if suffix != "" {
				// 插入Trie树，支持后缀匹配
				newDomainSet.insertSuffix(suffix)
			}
		} else {
			// 精确匹配的域名
			newDomainSet.domains[line] = true
			// 同时也作为后缀插入Trie树，支持子域名匹配
			newDomainSet.insertSuffix(line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Failed to read %s: %v", path, err)
		return errors.NewResourceError(fmt.Sprintf("failed to read %s: %v", path, err), err)
	}

	// 打印加载结果
	log.Printf("Loaded %d domains from %s", len(newDomainSet.domains), path)

	m.mutex.Lock()
	if domainSet == m.chinaList {
		m.chinaList = newDomainSet
		log.Printf("Updated China list with %d domains", len(newDomainSet.domains))
	} else {
		m.gfwList = newDomainSet
		log.Printf("Updated GFW list with %d domains", len(newDomainSet.domains))
	}
	m.mutex.Unlock()

	return nil
}

// downloadFile 从URL下载文件到本地路径
func (m *Manager) downloadFile(url, filePath string) error {
	if url == "" {
		// URL未配置，跳过下载
		return nil
	}

	log.Printf("Downloading file from %s to %s", url, filePath)

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: m.config.DownloadTimeout,
	}

	var err error
	var resp *http.Response

	// 重试机制
	for i := 0; i < m.config.MaxRetries; i++ {
		resp, err = client.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}

		// 关闭响应体
		if resp != nil {
			resp.Body.Close()
		}

		log.Printf("Download failed (attempt %d/%d): %v", i+1, m.config.MaxRetries, err)
		if i < m.config.MaxRetries-1 {
			time.Sleep(m.config.RetryDelay)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to download %s: %v", url, err)
	}
	defer resp.Body.Close()

	// 创建目录（如果不存在）
	dir := filepath.Dir(filePath)
	if err = os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// 创建临时文件
	tempFile, err := os.CreateTemp("", "puradns-")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	tempPath := tempFile.Name()
	defer func() {
		if err != nil {
			os.Remove(tempPath)
		}
	}()

	// 写入文件
	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write to temp file: %v", err)
	}
	tempFile.Close()

	// 原子替换文件
	if err := os.Rename(tempPath, filePath); err != nil {
		return fmt.Errorf("failed to rename temp file: %v", err)
	}

	log.Printf("Successfully downloaded %s to %s", url, filePath)
	return nil
}

// startUpdateLoop 启动定期更新循环
func (m *Manager) startUpdateLoop() {
	ticker := time.NewTicker(m.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 先下载最新的资源文件
			if err := m.downloadAllFiles(); err != nil {
				log.Printf("Failed to download resources: %v", err)
			}
			// 然后加载资源
			if err := m.loadAll(); err != nil {
				log.Printf("Failed to update resources: %v", err)
			}
		case <-m.updateChan:
			// 先下载最新的资源文件
			if err := m.downloadAllFiles(); err != nil {
				log.Printf("Failed to download resources: %v", err)
			}
			// 然后加载资源
			if err := m.loadAll(); err != nil {
				log.Printf("Failed to update resources: %v", err)
			}
		case <-m.stopChan:
			return
		}
	}
}

// downloadAllFiles 下载所有资源文件
func (m *Manager) downloadAllFiles() error {
	// 下载国内IP段文件
	if err := m.downloadFile(m.config.URLs.ChinaIP, m.config.ChinaIPPath); err != nil {
		return err
	}

	// 下载国内域名列表
	if err := m.downloadFile(m.config.URLs.ChinaList, m.config.ChinaListPath); err != nil {
		return err
	}

	// 下载GFW域名列表
	if err := m.downloadFile(m.config.URLs.GFWList, m.config.GFWListPath); err != nil {
		return err
	}

	return nil
}

// Contains 检查IP是否在IPSet中
func (s *IPSet) Contains(ip net.IP) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// 根据IP类型选择对应的CIDR切片
	var cidrs []*net.IPNet
	if ip.To4() != nil {
		// IPv4地址，只检查IPv4 CIDR
		cidrs = s.ipv4Cidrs
	} else {
		// IPv6地址，只检查IPv6 CIDR
		cidrs = s.ipv6Cidrs
	}

	// 遍历对应的CIDR切片
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// newTrieNode 创建新的Trie节点
func newTrieNode() *TrieNode {
	return &TrieNode{
		children: make(map[string]*TrieNode),
		isEnd:    false,
	}
}

// insertSuffix 将域名后缀插入Trie树
func (s *DomainSet) insertSuffix(suffix string) {
	// 反转域名后缀，例如 "baidu.com" 变为 "moc.udiab"
	// 这样可以从域名末尾开始匹配
	parts := strings.Split(suffix, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	reversed := strings.Join(parts, ".")

	// 插入到Trie树
	current := s.trie
	for _, part := range strings.Split(reversed, ".") {
		if current.children[part] == nil {
			current.children[part] = newTrieNode()
		}
		current = current.children[part]
	}
	current.isEnd = true
}

// Match 检查域名是否匹配DomainSet
func (s *DomainSet) Match(domain string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// 精确匹配
	if s.domains[domain] {
		return true
	}

	// 使用Trie树进行后缀匹配
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	reversed := strings.Join(parts, ".")
	reversedParts := strings.Split(reversed, ".")

	current := s.trie
	for _, part := range reversedParts {
		current = current.children[part]
		if current == nil {
			return false
		}
		if current.isEnd {
			return true
		}
	}

	return false
}

// Update 手动触发资源更新
func (m *Manager) Update() {
	select {
	case m.updateChan <- struct{}{}:
	default:
		// 防止阻塞
	}
}
