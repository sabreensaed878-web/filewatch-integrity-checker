import json
from pathlib import Path

from filewatch import (
    compare_snapshots,
    create_baseline,
    run_check,
    scan_directory,
    setup_logger,
    verify_baseline_hmac,
)


def test_ignore_patterns_skip_tmp_and_git(tmp_path: Path):
    target = tmp_path / "watched"
    target.mkdir()
    (target / "app.py").write_text("print('ok')", encoding="utf-8")
    (target / "notes.tmp").write_text("temp", encoding="utf-8")
    git_dir = target / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")

    snap = scan_directory(target, ignore_patterns=["*.tmp", ".git", ".git/**"])
    assert list(snap.keys()) == ["app.py"]


def test_scan_handles_permission_and_missing_file_errors(tmp_path: Path, monkeypatch):
    target = tmp_path / "watched"
    target.mkdir()
    locked_file = target / "secret.txt"
    locked_file.write_text("top-secret", encoding="utf-8")
    ok_file = target / "public.txt"
    ok_file.write_text("hello", encoding="utf-8")

    log_file = tmp_path / "filewatch.log"
    logger = setup_logger(log_file, logger_name="test_errors_logger")

    orig_hash = __import__("filewatch").compute_file_hash

    def fake_hash(path: Path, algo: str = "sha256", chunk_size: int = 4096) -> str:
        if path.name == "secret.txt":
            raise PermissionError("Access denied")
        return orig_hash(path, algo=algo, chunk_size=chunk_size)

    monkeypatch.setattr("filewatch.compute_file_hash", fake_hash)

    snap = scan_directory(target, logger=logger)
    assert "public.txt" in snap
    assert "secret.txt" not in snap
    assert "Permission denied accessing" in log_file.read_text(encoding="utf-8")


def test_hmac_signing_detects_baseline_tampering(tmp_path: Path, capsys):
    target = tmp_path / "watched"
    target.mkdir()
    (target / "config.yaml").write_text("env: prod", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"
    key = b"test-secret-key"
    create_baseline(target, baseline_path, hmac_key=key, use_hmac=True)

    raw_data = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert verify_baseline_hmac(raw_data, key)[0] is True

    # Tamper with recorded hash inside baseline.json without re-signing
    first_file = next(iter(raw_data["files"]))
    raw_data["files"][first_file]["hash"] = "0" * 64
    baseline_path.write_text(json.dumps(raw_data, indent=2), encoding="utf-8")

    is_valid, _ = verify_baseline_hmac(json.loads(baseline_path.read_text(encoding="utf-8")), key)
    assert is_valid is False

    run_check(target, baseline_path, hmac_key=key, use_hmac=True)
    out = capsys.readouterr().out
    assert "HMAC TAMPER ALERT" in out


def test_compare_snapshots_detects_added_modified_deleted():
    base = {
        "a.txt": {"hash": "1", "size": 5, "mtime": 100.0},
        "b.txt": {"hash": "2", "size": 5, "mtime": 100.0},
    }
    curr = {
        "a.txt": {"hash": "1", "size": 5, "mtime": 100.0},
        "b.txt": {"hash": "9", "size": 6, "mtime": 200.0},
        "c.txt": {"hash": "3", "size": 5, "mtime": 300.0},
    }
    diff = compare_snapshots(base, curr)
    assert diff == {"added": ["c.txt"], "modified": ["b.txt"], "deleted": []}