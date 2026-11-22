import argparse
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_CONFIG = {
    "interval_seconds": 3,
    "log_file": "filewatch.log",
    "hmac_enabled": True,
    "ignore_patterns": [
        "*.tmp",
        "*.swp",
        ".git",
        ".git/**",
        "__pycache__",
        "__pycache__/**",
        ".pytest_cache",
        ".pytest_cache/**",
        "baseline.json",
        "filewatch.log",
    ],
}

DEFAULT_HMAC_SECRET = "filewatch-default-secret-key"

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_RED = "\033[91m"
ANSI_CYAN = "\033[96m"


def resolve_hmac_key(cli_key: str | None = None) -> bytes:
    secret = cli_key or os.environ.get("FILEWATCH_HMAC_KEY") or DEFAULT_HMAC_SECRET
    return secret.encode("utf-8")


def compute_payload_hmac(payload_without_hmac: dict, key: bytes) -> str:
    canonical = json.dumps(payload_without_hmac, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def sign_baseline_payload(payload: dict, key: bytes) -> dict:
    unsigned = {k: v for k, v in payload.items() if k != "hmac"}
    signed = dict(unsigned)
    signed["hmac"] = compute_payload_hmac(unsigned, key)
    return signed


def verify_baseline_hmac(data: dict, key: bytes) -> tuple[bool, str]:
    stored_sig = data.get("hmac")
    if not stored_sig or not isinstance(stored_sig, str):
        return False, "Missing HMAC signature in baseline file."

    unsigned = {k: v for k, v in data.items() if k != "hmac"}
    expected_sig = compute_payload_hmac(unsigned, key)
    if hmac.compare_digest(stored_sig, expected_sig):
        return True, "HMAC signature valid."
    return False, "HMAC signature mismatch! Baseline file may have been tampered with."


def load_config(config_path: Path | None = None) -> dict:
    cfg = {
        "interval_seconds": DEFAULT_CONFIG["interval_seconds"],
        "log_file": DEFAULT_CONFIG["log_file"],
        "hmac_enabled": DEFAULT_CONFIG["hmac_enabled"],
        "ignore_patterns": list(DEFAULT_CONFIG["ignore_patterns"]),
    }
    target_cfg = config_path or Path("config.json")
    if target_cfg.exists():
        loaded = json.loads(target_cfg.read_text(encoding="utf-8"))
        if "interval_seconds" in loaded:
            cfg["interval_seconds"] = max(0.2, float(loaded["interval_seconds"]))
        if "log_file" in loaded and loaded["log_file"]:
            cfg["log_file"] = str(loaded["log_file"])
        if "hmac_enabled" in loaded:
            cfg["hmac_enabled"] = bool(loaded["hmac_enabled"])
        if isinstance(loaded.get("ignore_patterns"), list):
            cfg["ignore_patterns"] = [str(p) for p in loaded["ignore_patterns"]]
    return cfg


def setup_logger(log_file: Path, logger_name: str = "filewatch") -> logging.Logger:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)

    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


def is_ignored(rel_path: str, ignore_patterns: list[str] | None) -> bool:
    if not ignore_patterns:
        return False

    normalized = rel_path.strip("/")
    parts = normalized.split("/")

    for pattern in ignore_patterns:
        pat = pattern.strip().replace("\\", "/")
        if not pat:
            continue
        if pat.endswith("/**"):
            prefix = pat[:-3]
            if normalized == prefix or normalized.startswith(prefix + "/"):
                return True
        elif fnmatch.fnmatchcase(normalized, pat):
            return True
        elif any(fnmatch.fnmatchcase(part, pat) for part in parts):
            return True

    return False


def compute_file_hash(file_path: Path, algo: str = "sha256", chunk_size: int = 4096) -> str:
    hasher = hashlib.new(algo)
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def scan_directory(
    target_dir: Path,
    algo: str = "sha256",
    baseline_file: Path | None = None,
    ignore_patterns: list[str] | None = None,
    logger: logging.Logger | None = None,
) -> dict:
    snapshot = {}
    try:
        entries = sorted(target_dir.rglob("*"))
    except PermissionError as exc:
        if logger:
            logger.warning("Permission denied while scanning directory '%s': %s", target_dir, exc)
        return snapshot
    except FileNotFoundError as exc:
        if logger:
            logger.warning("Target directory disappeared during scan '%s': %s", target_dir, exc)
        return snapshot
    except OSError as exc:
        if logger:
            logger.warning("OS error while scanning '%s': %s", target_dir, exc)
        return snapshot

    for path in entries:
        try:
            if not path.is_file():
                continue
            if baseline_file is not None and path.resolve() == baseline_file.resolve():
                continue

            rel_path = path.relative_to(target_dir).as_posix()
            if is_ignored(rel_path, ignore_patterns):
                continue

            stat = path.stat()
            snapshot[rel_path] = {
                "hash": compute_file_hash(path, algo=algo),
                "size": stat.st_size,
                "mtime": stat.st_mtime,
            }
        except PermissionError as exc:
            if logger:
                logger.warning("Permission denied accessing '%s': %s", path, exc)
        except FileNotFoundError as exc:
            if logger:
                logger.warning("File vanished during scan '%s': %s", path, exc)
        except OSError as exc:
            if logger:
                logger.warning("Error reading '%s': %s", path, exc)

    return snapshot


def format_mtime(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def create_baseline(
    target_dir: Path,
    output_file: Path,
    algo: str = "sha256",
    ignore_patterns: list[str] | None = None,
    logger: logging.Logger | None = None,
    hmac_key: bytes | None = None,
    use_hmac: bool = True,
) -> dict:
    if not target_dir.exists() or not target_dir.is_dir():
        raise FileNotFoundError(f"Target directory not found: {target_dir}")

    snapshot = scan_directory(
        target_dir,
        algo=algo,
        baseline_file=output_file,
        ignore_patterns=ignore_patterns,
        logger=logger,
    )
    payload: dict = {
        "algorithm": algo,
        "files": snapshot,
    }
    if use_hmac:
        key = hmac_key or resolve_hmac_key()
        payload = sign_baseline_payload(payload, key)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def compare_snapshots(baseline_files: dict, current_files: dict) -> dict:
    old_keys = set(baseline_files.keys())
    new_keys = set(current_files.keys())

    added = sorted(new_keys - old_keys)
    deleted = sorted(old_keys - new_keys)
    common = sorted(old_keys & new_keys)

    modified = []
    for rel in common:
        old_item = baseline_files[rel]
        new_item = current_files[rel]
        if (
            old_item["hash"] != new_item["hash"]
            or old_item.get("size") != new_item.get("size")
            or old_item.get("mtime") != new_item.get("mtime")
        ):
            modified.append(rel)

    return {
        "added": added,
        "modified": modified,
        "deleted": deleted,
    }


def handle_hmac_check(
    data: dict,
    baseline_file: Path,
    hmac_key: bytes,
    logger: logging.Logger | None = None,
    strict_hmac: bool = False,
) -> bool:
    is_valid, reason = verify_baseline_hmac(data, hmac_key)
    if is_valid:
        return True

    alert_msg = f"HMAC TAMPER ALERT on '{baseline_file}': {reason}"
    print(f"\n{ANSI_BOLD}{ANSI_RED}[SECURITY ALERT] {alert_msg}{ANSI_RESET}")
    if logger:
        logger.error(alert_msg)

    if strict_hmac:
        raise ValueError(alert_msg)
    return False


def log_and_alert_changes(
    changes: dict,
    baseline_files: dict,
    current_files: dict,
    logger: logging.Logger,
) -> bool:
    has_changes = bool(changes["added"] or changes["modified"] or changes["deleted"])
    if not has_changes:
        return False

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{ANSI_BOLD}{ANSI_RED}[ALERT @ {now_str}] File integrity changes detected!{ANSI_RESET}")

    for rel in changes["added"]:
        info = current_files[rel]
        msg = f"ADDED | {rel} | size={info['size']}B | mtime={format_mtime(info['mtime'])}"
        logger.info(msg)
        print(f"  {ANSI_GREEN}+ {msg}{ANSI_RESET}")

    for rel in changes["modified"]:
        old_info = baseline_files[rel]
        new_info = current_files[rel]
        msg = (
            f"MODIFIED | {rel} | size={old_info.get('size')}B->{new_info['size']}B | "
            f"mtime={format_mtime(old_info.get('mtime', 0))}->{format_mtime(new_info['mtime'])}"
        )
        logger.info(msg)
        print(f"  {ANSI_YELLOW}~ {msg}{ANSI_RESET}")

    for rel in changes["deleted"]:
        old_info = baseline_files[rel]
        msg = (
            f"DELETED | {rel} | last size={old_info.get('size')}B | "
            f"last mtime={format_mtime(old_info.get('mtime', 0))}"
        )
        logger.info(msg)
        print(f"  {ANSI_RED}- {msg}{ANSI_RESET}")

    return True


def run_check(
    target_dir: Path,
    baseline_file: Path,
    algo_override: str | None = None,
    ignore_patterns: list[str] | None = None,
    logger: logging.Logger | None = None,
    hmac_key: bytes | None = None,
    use_hmac: bool = True,
    strict_hmac: bool = False,
) -> dict:
    if not baseline_file.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_file}")

    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    if use_hmac:
        handle_hmac_check(
            data=data,
            baseline_file=baseline_file,
            hmac_key=hmac_key or resolve_hmac_key(),
            logger=logger,
            strict_hmac=strict_hmac,
        )

    algo = algo_override or data.get("algorithm", "sha256")
    baseline_files = data.get("files", {})

    current_files = scan_directory(
        target_dir,
        algo=algo,
        baseline_file=baseline_file,
        ignore_patterns=ignore_patterns,
        logger=logger,
    )
    changes = compare_snapshots(baseline_files, current_files)

    print("=== Added Files ===")
    if changes["added"]:
        for rel in changes["added"]:
            info = current_files[rel]
            print(f"  + {rel} | size: {info['size']}B | mtime: {format_mtime(info['mtime'])}")
    else:
        print("  None")

    print("\n=== Modified Files ===")
    if changes["modified"]:
        for rel in changes["modified"]:
            old_info = baseline_files[rel]
            new_info = current_files[rel]
            print(
                f"  ~ {rel} | size: {old_info.get('size')}B -> {new_info['size']}B | "
                f"mtime: {format_mtime(old_info.get('mtime', 0))} -> {format_mtime(new_info['mtime'])}"
            )
    else:
        print("  None")

    print("\n=== Deleted Files ===")
    if changes["deleted"]:
        for rel in changes["deleted"]:
            old_info = baseline_files[rel]
            print(
                f"  - {rel} | last size: {old_info.get('size')}B | "
                f"last mtime: {format_mtime(old_info.get('mtime', 0))}"
            )
    else:
        print("  None")

    if not (changes["added"] or changes["modified"] or changes["deleted"]):
        print("\nNo changes detected. Directory matches baseline.")

    return changes


def watch_directory(
    target_dir: Path,
    baseline_file: Path,
    interval: float,
    algo_override: str | None = None,
    ignore_patterns: list[str] | None = None,
    logger: logging.Logger | None = None,
    update_baseline_on_change: bool = False,
    hmac_key: bytes | None = None,
    use_hmac: bool = True,
    strict_hmac: bool = False,
) -> None:
    if not target_dir.exists() or not target_dir.is_dir():
        raise FileNotFoundError(f"Target directory not found: {target_dir}")

    active_logger = logger or setup_logger(Path("filewatch.log"))
    active_ignores = ignore_patterns if ignore_patterns is not None else list(DEFAULT_CONFIG["ignore_patterns"])
    key = hmac_key or resolve_hmac_key()

    if baseline_file.exists():
        data = json.loads(baseline_file.read_text(encoding="utf-8"))
        if use_hmac:
            handle_hmac_check(
                data=data,
                baseline_file=baseline_file,
                hmac_key=key,
                logger=active_logger,
                strict_hmac=strict_hmac,
            )
        algo = algo_override or data.get("algorithm", "sha256")
        baseline_files = dict(data.get("files", {}))
    else:
        algo = algo_override or "sha256"
        created = create_baseline(
            target_dir,
            baseline_file,
            algo=algo,
            ignore_patterns=active_ignores,
            logger=active_logger,
            hmac_key=key,
            use_hmac=use_hmac,
        )
        baseline_files = dict(created.get("files", {}))
        active_logger.info("Initial baseline created at '%s' for '%s'", baseline_file, target_dir)

    print(
        f"{ANSI_CYAN}{ANSI_BOLD}[FileWatch] Watching '{target_dir}' every {interval}s... "
        f"(Press Ctrl+C to stop){ANSI_RESET}"
    )
    active_logger.info("Started watching '%s' every %ss", target_dir, interval)

    try:
        while True:
            time.sleep(interval)
            current_files = scan_directory(
                target_dir,
                algo=algo,
                baseline_file=baseline_file,
                ignore_patterns=active_ignores,
                logger=active_logger,
            )
            changes = compare_snapshots(baseline_files, current_files)
            if log_and_alert_changes(changes, baseline_files, current_files, active_logger):
                if update_baseline_on_change:
                    baseline_files = dict(current_files)
                    payload: dict = {"algorithm": algo, "files": baseline_files}
                    if use_hmac:
                        payload = sign_baseline_payload(payload, key)
                    baseline_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except KeyboardInterrupt:
        print(f"\n{ANSI_CYAN}[FileWatch] Monitoring stopped cleanly by user.{ANSI_RESET}")
        active_logger.info("Monitoring stopped cleanly via Ctrl+C")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FileWatch - File Integrity Monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    common_args = argparse.ArgumentParser(add_help=False)
    common_args.add_argument(
        "--config",
        default="config.json",
        help="Path to JSON configuration file (default: config.json)",
    )
    common_args.add_argument(
        "--log-file",
        default=None,
        help="Path to log file (overrides config.json)",
    )
    common_args.add_argument(
        "--hmac-key",
        default=None,
        help="Secret key for signing/verifying baseline HMAC (or env FILEWATCH_HMAC_KEY)",
    )
    common_args.add_argument(
        "--no-hmac",
        action="store_true",
        help="Disable HMAC baseline signing and verification",
    )
    common_args.add_argument(
        "--strict-hmac",
        action="store_true",
        help="Raise an error if baseline HMAC verification fails",
    )

    base_parser = subparsers.add_parser(
        "baseline",
        parents=[common_args],
        help="Create a baseline JSON snapshot",
    )
    base_parser.add_argument("target", help="Target directory to monitor")
    base_parser.add_argument(
        "--baseline",
        default="baseline.json",
        help="Path to baseline JSON file (default: baseline.json)",
    )
    base_parser.add_argument(
        "--algo",
        default="sha256",
        choices=["sha256", "sha1", "md5"],
        help="Hash algorithm (default: sha256)",
    )

    check_parser = subparsers.add_parser(
        "check",
        parents=[common_args],
        help="Compare current directory against baseline",
    )
    check_parser.add_argument("target", help="Target directory to monitor")
    check_parser.add_argument(
        "--baseline",
        default="baseline.json",
        help="Path to baseline JSON file (default: baseline.json)",
    )
    check_parser.add_argument(
        "--algo",
        default=None,
        choices=["sha256", "sha1", "md5"],
        help="Override hash algorithm",
    )

    watch_parser = subparsers.add_parser(
        "watch",
        parents=[common_args],
        help="Continuously monitor target directory for changes",
    )
    watch_parser.add_argument("target", help="Target directory to monitor")
    watch_parser.add_argument(
        "--baseline",
        default="baseline.json",
        help="Path to baseline JSON file (default: baseline.json)",
    )
    watch_parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Poll interval in seconds (overrides config.json)",
    )
    watch_parser.add_argument(
        "--algo",
        default=None,
        choices=["sha256", "sha1", "md5"],
        help="Override hash algorithm",
    )
    watch_parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Update in-memory and saved baseline after reporting changes",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    cfg = load_config(Path(args.config) if args.config else None)
    log_path = Path(args.log_file or cfg["log_file"])
    logger = setup_logger(log_path)
    ignore_patterns = cfg["ignore_patterns"]
    use_hmac = cfg["hmac_enabled"] and not args.no_hmac
    hmac_key = resolve_hmac_key(args.hmac_key)

    target_dir = Path(args.target)
    baseline_file = Path(args.baseline)

    if args.command == "baseline":
        create_baseline(
            target_dir,
            baseline_file,
            algo=args.algo,
            ignore_patterns=ignore_patterns,
            logger=logger,
            hmac_key=hmac_key,
            use_hmac=use_hmac,
        )
        print(f"Baseline saved to {baseline_file}")
    elif args.command == "check":
        run_check(
            target_dir,
            baseline_file,
            algo_override=args.algo,
            ignore_patterns=ignore_patterns,
            logger=logger,
            hmac_key=hmac_key,
            use_hmac=use_hmac,
            strict_hmac=args.strict_hmac,
        )
    elif args.command == "watch":
        interval = args.interval if args.interval is not None else cfg["interval_seconds"]
        watch_directory(
            target_dir,
            baseline_file,
            interval=interval,
            algo_override=args.algo,
            ignore_patterns=ignore_patterns,
            logger=logger,
            update_baseline_on_change=args.update_baseline,
            hmac_key=hmac_key,
            use_hmac=use_hmac,
            strict_hmac=args.strict_hmac,
        )


if __name__ == "__main__":
    main()