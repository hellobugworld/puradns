# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
