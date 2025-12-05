package diverter

import (
	"net"
	"strings"

	"github.com/hellobugworld/puradns/internal/resources"
)

// Decision 分流决策
type Decision int

const (
	// DecisionDomestic 仅使用国内DNS
	DecisionDomestic Decision = iota
	// DecisionForeign 仅使用国外DNS
	DecisionForeign
	// DecisionBoth 同时使用国内和国外DNS
	DecisionBoth
)

// Diverter 分流器接口
type Diverter interface {
	// Decide 根据域名决定使用哪个DNS组
	Decide(domain string) Decision
	// ValidateResult 验证DNS结果是否有效
	ValidateResult(result *Result) bool
	// IsChinaIP 检查IP是否在国内IP段
	IsChinaIP(ip net.IP) bool
}

// Result DNS查询结果
type Result struct {
	Domain         string
	IPs            []net.IP
	IsFromDomestic bool
}

// Config 分流器配置
type Config struct {
	ResourceManager *resources.Manager
}

// diverter 分流器实现
type diverter struct {
	resourceManager *resources.Manager
}

// NewDiverter 创建分流器
func NewDiverter(config Config) Diverter {
	return &diverter{
		resourceManager: config.ResourceManager,
	}
}

// Decide 根据域名决定使用哪个DNS组
func (d *diverter) Decide(domain string) Decision {
	// 去除域名末尾的点
	domain = strings.TrimSuffix(domain, ".")

	// 检查域名是否在国内列表
	isChinaDomain := d.resourceManager.IsChinaDomain(domain)
	isGFWDomain := d.resourceManager.IsGFWDomain(domain)

	if isChinaDomain {
		return DecisionDomestic
	}

	if isGFWDomain {
		return DecisionForeign
	}

	// 否则同时查询国内和国外DNS
	return DecisionBoth
}

// ValidateResult 验证DNS结果是否有效
func (d *diverter) ValidateResult(result *Result) bool {
	// 如果是国内结果，检查IP是否在国内IP段
	if result.IsFromDomestic {
		for _, ip := range result.IPs {
			if !d.IsChinaIP(ip) {
				// 国内结果返回国外IP，可能被污染
				return false
			}
		}
	}
	return true
}

// IsChinaIP 检查IP是否在国内IP段
func (d *diverter) IsChinaIP(ip net.IP) bool {
	return d.resourceManager.IsChinaIP(ip)
}
