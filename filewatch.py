import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def compute_file_hash(file_path: Path, algo: str = "sha256", chunk_size: int = 4096) -> str:
    hasher = hashlib.new(algo)
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def scan_directory(target_dir: Path, algo: str = "sha256", baseline_file: Path | None = None) -> dict:
    snapshot = {}
    for path in sorted(target_dir.rglob("*")):
        if not path.is_file():
            continue
        if baseline_file is not None and path.resolve() == baseline_file.resolve():
            continue

        rel_path = path.relative_to(target_dir).as_posix()
        stat = path.stat()
        snapshot[rel_path] = {
            "hash": compute_file_hash(path, algo=algo),
            "size": stat.st_size,
            "mtime": stat.st_mtime,
        }
    return snapshot


def format_mtime(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def create_baseline(target_dir: Path, output_file: Path, algo: str = "sha256") -> dict:
    if not target_dir.exists() or not target_dir.is_dir():
        raise FileNotFoundError(f"Target directory not found: {target_dir}")

    snapshot = scan_directory(target_dir, algo=algo, baseline_file=output_file)
    payload = {
        "algorithm": algo,
        "files": snapshot,
    }
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


def run_check(target_dir: Path, baseline_file: Path, algo_override: str | None = None) -> dict:
    if not baseline_file.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_file}")

    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    algo = algo_override or data.get("algorithm", "sha256")
    baseline_files = data.get("files", {})

    current_files = scan_directory(target_dir, algo=algo, baseline_file=baseline_file)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FileWatch - File Integrity Monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    base_parser = subparsers.add_parser("baseline", help="Create a baseline JSON snapshot")
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

    check_parser = subparsers.add_parser("check", help="Compare current directory against baseline")
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

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    target_dir = Path(args.target)
    baseline_file = Path(args.baseline)

    if args.command == "baseline":
        create_baseline(target_dir, baseline_file, algo=args.algo)
        print(f"Baseline saved to {baseline_file}")
    elif args.command == "check":
        run_check(target_dir, baseline_file, algo_override=args.algo)


if __name__ == "__main__":
    main()