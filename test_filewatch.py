import os
import time
from pathlib import Path
from filewatch import create_baseline, run_check


def test_no_changes_detected(tmp_path: Path):
    target = tmp_path / "monitored"
    target.mkdir()
    (target / "a.txt").write_text("hello", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"

    create_baseline(target, baseline_path)
    changes = run_check(target, baseline_path)

    assert changes["added"] == []
    assert changes["modified"] == []
    assert changes["deleted"] == []


def test_detects_added_file(tmp_path: Path):
    target = tmp_path / "monitored"
    target.mkdir()
    (target / "a.txt").write_text("initial", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    create_baseline(target, baseline_path)

    (target / "new.txt").write_text("added content", encoding="utf-8")
    changes = run_check(target, baseline_path)

    assert "new.txt" in changes["added"]
    assert changes["modified"] == []
    assert changes["deleted"] == []


def test_detects_modified_file(tmp_path: Path):
    target = tmp_path / "monitored"
    target.mkdir()
    file_a = target / "a.txt"
    file_a.write_text("abc", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    create_baseline(target, baseline_path)

    time.sleep(0.05)
    file_a.write_text("abd", encoding="utf-8")
    changes = run_check(target, baseline_path)

    assert "a.txt" in changes["modified"]
    assert changes["added"] == []
    assert changes["deleted"] == []


def test_detects_deleted_file(tmp_path: Path):
    target = tmp_path / "monitored"
    target.mkdir()
    victim = target / "temp.txt"
    victim.write_text("delete me", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    create_baseline(target, baseline_path)

    victim.unlink()
    changes = run_check(target, baseline_path)

    assert "temp.txt" in changes["deleted"]
    assert changes["added"] == []
    assert changes["modified"] == []


def test_subdirectories_included_with_relative_paths(tmp_path: Path):
    target = tmp_path / "monitored"
    nested = target / "sub1" / "sub2"
    nested.mkdir(parents=True)
    nested_file = nested / "config.txt"
    nested_file.write_text("v1", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"
    create_baseline(target, baseline_path)

    nested_file.write_text("v2", encoding="utf-8")
    changes = run_check(target, baseline_path)

    assert "sub1/sub2/config.txt" in changes["modified"]


def test_baseline_survives_directory_move(tmp_path: Path):
    first_dir = tmp_path / "dir_one"
    first_dir.mkdir()
    (first_dir / "data.txt").write_text("same", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"
    create_baseline(first_dir, baseline_path)

    moved_dir = tmp_path / "dir_two"
    os.rename(first_dir, moved_dir)

    changes = run_check(moved_dir, baseline_path)
    assert changes["added"] == []
    assert changes["modified"] == []
    assert changes["deleted"] == []
