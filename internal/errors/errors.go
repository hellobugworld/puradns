package errors

import (
	"fmt"
)

// ErrorType 错误类型枚举
type ErrorType int

const (
	// ErrorTypeNetwork 网络错误
	ErrorTypeNetwork ErrorType = iota
	// ErrorTypeProtocol 协议错误
	ErrorTypeProtocol
	// ErrorTypeConfig 配置错误
	ErrorTypeConfig
	// ErrorTypeRuleEngine 规则引擎错误
	ErrorTypeRuleEngine
	// ErrorTypeCache 缓存错误
	ErrorTypeCache
	// ErrorTypeTimeout 超时错误
	ErrorTypeTimeout
	// ErrorTypeResource 资源错误
	ErrorTypeResource
	// ErrorTypeSecurity 安全错误
	ErrorTypeSecurity
)

// PuraDNSError 自定义错误类型
type PuraDNSError struct {
	Type    ErrorType
	Message string
	Cause   error
}

// Error 实现error接口
func (e *PuraDNSError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap 实现Unwrap接口，支持errors.Unwrap
func (e *PuraDNSError) Unwrap() error {
	return e.Cause
}

// NewError 创建新错误的辅助函数
func NewError(errType ErrorType, message string, cause error) *PuraDNSError {
	return &PuraDNSError{
		Type:    errType,
		Message: message,
		Cause:   cause,
	}
}

// NewNetworkError 创建网络错误
func NewNetworkError(message string, cause error) *PuraDNSError {
	return NewError(ErrorTypeNetwork, message, cause)
}

// NewProtocolError 创建协议错误
func NewProtocolError(message string, cause error) *PuraDNSError {
	return NewError(ErrorTypeProtocol, message, cause)
}

// NewConfigError 创建配置错误
func NewConfigError(message string, cause error) *PuraDNSError {
	return NewError(ErrorTypeConfig, message, cause)
}

// NewRuleEngineError 创建规则引擎错误
func NewRuleEngineError(message string, cause error) *PuraDNSError {
	return NewError(ErrorTypeRuleEngine, message, cause)
}

// NewCacheError 创建缓存错误
func NewCacheError(message string, cause error) *PuraDNSError {
	return NewError(ErrorTypeCache, message, cause)
}

// NewTimeoutError 创建超时错误
func NewTimeoutError(message string, cause error) *PuraDNSError {
	return NewError(ErrorTypeTimeout, message, cause)
}

// NewResourceError 创建资源错误
func NewResourceError(message string, cause error) *PuraDNSError {
	return NewError(ErrorTypeResource, message, cause)
}

// NewSecurityError 创建安全错误
func NewSecurityError(message string, cause error) *PuraDNSError {
	return NewError(ErrorTypeSecurity, message, cause)
}
