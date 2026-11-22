# FileWatch - File Integrity Monitor

A Python-based File Integrity Monitor (FIM) built during the SkillMe Cybersecurity Virtual Internship to monitor file additions, modifications, and deletions using baseline snapshots and cryptographic hashing.

## Legal and Ethical Notice
Scanning or testing systems or directories without authorization is unethical and prohibited. Use this tool strictly on directories you own or have explicit permission to monitor (such as `test_folder`).

## Overview
- Computes file digests by reading files in binary mode (`rb`) in `4096`-byte chunks via Python's `hashlib` module (supporting **SHA-256** by default as well as **SHA-1** and **MD5**).
- Recursively scans target directories and subdirectories using relative paths so baselines remain portable even if the monitored folder is moved.
- Saves baseline snapshots to `baseline.json` (including file hash, file size in bytes, and modification timestamp `mtime`) and compares current directory state against the baseline.
- Reports **Added**, **Modified**, and **Deleted** files in separate sections, along with size and timestamp changes.

## Why SHA-256 Is Preferred Over SHA-1
- **Collision Resistance:** SHA-1 produces a 160-bit hash and suffers from practical collision attacks, whereas SHA-256 produces a 256-bit hash with substantially stronger collision resistance.
- **Security Standards:** Modern integrity monitoring and software verification standards favor SHA-256, treating SHA-1 as legacy/deprecated for security verification.

## Usage

### 1. Create a Baseline Snapshot
```powershell
python filewatch.py baseline test_folder
## Week 3: Continuous Monitoring, Logging & HMAC Signing

- Continuous `watch` mode with configurable interval and colored alerts.
- Structured logging with timestamps to `filewatch.log`.
- Ignore patterns in `config.json` (e.g., `*.tmp`, `.git`) matched via `fnmatch`.
- Graceful handling of `PermissionError`, missing files, and `Ctrl+C` (`KeyboardInterrupt`).
- HMAC-SHA256 baseline signing and tampering detection (`verify_baseline_hmac`).
