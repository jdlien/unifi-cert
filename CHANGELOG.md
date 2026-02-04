# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-02-04

### Added

- Initial release of UniFi Certificate Manager
- Dual-path certificate installation (EUS nginx + WebUI PostgreSQL)
- Interactive and non-interactive CLI modes
- DNS validation support for multiple providers:
  - DigitalOcean, Cloudflare, Route53, Google Cloud DNS, Linode, Namecheap, OVH
- Remote installation via SSH/SCP
- Local installation on UniFi devices
- Automatic certbot renewal hook setup
- Certificate metadata extraction via OpenSSL
- Auto-detection of domain from existing certificates
- Persistent configuration for email and DNS provider preferences
- Curl-pipe installation support (`curl ... | python3 -`)

### Fixed

- DNS credential field name bug (GlennR's API returns wrong field names)
- WebUI certificate desync issue (PostgreSQL now updated alongside file installation)

### Technical

- Pure Python stdlib implementation (no external dependencies)
- Single-file design for easy deployment
- Python 3.9+ compatible with explicit UTF-8 encoding for future-proofing
- 95% test coverage

[1.0.0]: https://github.com/jdlien/unifi-cert/releases/tag/v1.0.0
