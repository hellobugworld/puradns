# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- 支持从配置文件读取Goroutine池配置（大小和队列大小）
- 为配置文件添加了用户友好的中文注释
- 实现了HTTP/3自动回退机制，提高DoH连接可靠性
- 添加了预刷新最大键数量配置，允许用户自定义每次预刷新处理的最大键数量
- 添加了HTTP/3相关配置，允许用户自定义HTTP/3尝试超时和重试间隔
- 添加了上游查询重试次数配置，允许用户自定义上游查询失败后的重试次数

### Changed
- 重构了服务器缓存查询逻辑，将if-else结构替换为更清晰的switch语句
- 优化了配置文件注释，使用更通俗易懂的语言
- 改进了TLS密码套件配置，使用安全默认值
- 将`bootstrap_dns`参数名简化为`bootstrap`
- 移除了`puradns.yaml`文件的git版本控制
- 将硬编码的上游查询重试次数改为使用配置值

### Fixed
- 修复了`parseCipherSuites`函数中未使用的`suites`参数
- 修复了服务器缓存查询的代码质量问题
- 删除了项目中所有调试日志，提高生产环境性能
- 删除了代码中重复的注释，提高代码可读性

## [1.0.0] - 2025-12-05

### Added
- 完整的TLS配置支持，包括最小/最大版本、密码套件、SNI等
- DoT服务器地址自动解析功能
- Bootstrap解析器支持，用于解析DoT/DoH服务器域名
- 详细的TLS握手和DNS查询日志
- TLS版本自适应协商机制

### Changed
- 重构了upstream客户端的TLS配置逻辑
- 改进了DoT查询的错误处理机制
- 优化了配置文件结构，支持更灵活的TLS配置
- 增强了EDNS支持性检测

### Fixed
- TLS协议版本自适应问题
- 无法动态识别上游EDNS支持性问题
- DoT服务器域名解析问题

### Removed
- 移除了Makefile，简化项目结构

[Unreleased]: https://github.com/hellobugworld/puradns/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/hellobugworld/puradns/releases/tag/v1.0.0
