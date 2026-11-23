import html
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, redirect, render_template_string, request, url_for

app = Flask(__name__)

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*\|\s*(?P<level>[A-Z]+)\s*\|\s*(?P<message>.*)$"
)


def parse_log_file(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []

    events: list[dict] = []
    for raw_line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        match = LOG_PATTERN.match(line)
        if match:
            ts = match.group("timestamp")
            level = match.group("level")
            msg = match.group("message")
        else:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            level = "INFO"
            msg = line

        event_type = "OTHER"
        upper_msg = msg.upper()
        if "ADDED |" in upper_msg or upper_msg.startswith("ADDED"):
            event_type = "ADDED"
        elif "MODIFIED |" in upper_msg or upper_msg.startswith("MODIFIED"):
            event_type = "MODIFIED"
        elif "DELETED |" in upper_msg or upper_msg.startswith("DELETED"):
            event_type = "DELETED"
        elif "HMAC" in upper_msg or "TAMPER" in upper_msg:
            event_type = "HMAC_ALERT"
        elif level in {"WARNING", "ERROR"}:
            event_type = "SYSTEM_WARNING"

        parts = [p.strip() for p in msg.split("|")]
        file_target = parts[1] if len(parts) >= 2 else "-"
        details = " | ".join(parts[2:]) if len(parts) >= 3 else msg
        minute_bucket = ts[:16]

        events.append(
            {
                "timestamp": ts,
                "minute": minute_bucket,
                "level": level,
                "type": event_type,
                "file": file_target,
                "details": details,
                "raw": msg,
            }
        )

    return events


def build_report_markdown(events: list[dict], log_path: Path) -> str:
    type_counts = Counter(e["type"] for e in events)
    recent = list(reversed(events[-25:]))

    lines = [
        "# FileWatch Integrity Report",
        "",
        f"- **Generated At:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Source Log:** `{log_path}`",
        f"- **Total Parsed Events:** {len(events)}",
        "",
        "## Summary by Event Type",
        "",
        "| Event Type | Count |",
        "| --- | --- |",
    ]
    for ev_type, count in sorted(type_counts.items()):
        lines.append(f"| {ev_type} | {count} |")

    lines.extend(
        [
            "",
            "## Recent Integrity Events",
            "",
            "| Timestamp | Type | Target | Details |",
            "| --- | --- | --- | --- |",
        ]
    )
    for ev in recent:
        safe_details = ev["details"].replace("|", "\\|")
        safe_file = ev["file"].replace("|", "\\|")
        lines.append(f"| {ev['timestamp']} | {ev['type']} | `{safe_file}` | {safe_details} |")

    return "\n".join(lines) + "\n"


def build_report_html(events: list[dict], log_path: Path) -> str:
    md_text = build_report_markdown(events, log_path)
    type_counts = Counter(e["type"] for e in events)
    cards = "".join(
        f"<div class='card'><h3>{html.escape(k)}</h3><p>{v}</p></div>"
        for k, v in sorted(type_counts.items())
    )
    rows = "".join(
        f"<tr><td>{html.escape(e['timestamp'])}</td><td>{html.escape(e['type'])}</td>"
        f"<td><code>{html.escape(e['file'])}</code></td><td>{html.escape(e['details'])}</td></tr>"
        for e in reversed(events[-50:])
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>FileWatch Integrity Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #0f172a; color: #e2e8f0; }}
    .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }}
    .card {{ background: #1e293b; padding: 14px 18px; border-radius: 8px; min-width: 140px; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; }}
    th, td {{ border: 1px solid #334155; padding: 8px 10px; text-align: left; }}
    th {{ background: #334155; }}
    pre {{ background: #1e293b; padding: 12px; border-radius: 8px; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <h1>FileWatch — File Integrity Report</h1>
  <p>Log Source: <code>{html.escape(str(log_path))}</code> | Total Events: <strong>{len(events)}</strong></p>
  <div class="cards">{cards}</div>
  <h2>Recent Events</h2>
  <table>
    <thead><tr><th>Timestamp</th><th>Type</th><th>File / Target</th><th>Details</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <h2>Markdown Export Preview</h2>
  <pre>{html.escape(md_text)}</pre>
</body>
</html>
"""


DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>FileWatch Dashboard</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; margin: 0; background: #0b1120; color: #e2e8f0; }
    header { background: #111827; padding: 18px 28px; border-bottom: 1px solid #1f2937; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
    h1 { margin: 0; font-size: 20px; color: #38bdf8; }
    .actions a, .actions button { background: #2563eb; color: #fff; border: none; padding: 8px 14px; border-radius: 6px; text-decoration: none; cursor: pointer; font-size: 14px; }
    .actions a.secondary { background: #334155; }
    .container { padding: 24px 28px; max-width: 1200px; margin: auto; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-bottom: 24px; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 16px; }
    .card .label { font-size: 12px; color: #94a3b8; text-transform: uppercase; }
    .card .val { font-size: 26px; font-weight: 700; margin-top: 6px; color: #f8fafc; }
    .panel { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 18px; margin-bottom: 22px; }
    h2 { margin-top: 0; font-size: 16px; color: #93c5fd; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { padding: 10px; border-bottom: 1px solid #1f2937; text-align: left; }
    th { color: #94a3b8; font-weight: 600; }
    .badge { padding: 3px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
    .ADDED { background: #064e3b; color: #6ee7b7; }
    .MODIFIED { background: #78350f; color: #fcd34d; }
    .DELETED { background: #7f1d1d; color: #fca5a5; }
    .HMAC_ALERT { background: #881337; color: #fda4af; }
    .SYSTEM_WARNING, .OTHER { background: #1e293b; color: #cbd5e1; }
    .bar-row { display: flex; align-items: center; gap: 10px; margin: 8px 0; font-size: 13px; }
    .bar-fill { height: 14px; background: #38bdf8; border-radius: 4px; }
    .flash { background: #065f46; color: #ecfdf5; padding: 10px 14px; border-radius: 8px; margin-bottom: 18px; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>FileWatch — Integrity Monitoring Dashboard</h1>
      <small style="color:#94a3b8;">Log source: {{ log_path }}</small>
    </div>
    <div class="actions">
      <a class="secondary" href="{{ url_for('index') }}">Refresh</a>
      <a href="{{ url_for('generate_report', fmt='md') }}">Generate Markdown Report</a>
      <a href="{{ url_for('generate_report', fmt='html') }}">Generate HTML Report</a>
    </div>
  </header>

  <div class="container">
    {% if status_msg %}
      <div class="flash">{{ status_msg }}</div>
    {% endif %}

    <div class="grid">
      <div class="card"><div class="label">Total Events</div><div class="val">{{ events|length }}</div></div>
      {% for ev_type, count in counts.items() %}
      <div class="card"><div class="label">{{ ev_type }}</div><div class="val">{{ count }}</div></div>
      {% endfor %}
    </div>

    <div class="panel">
      <h2>Timeline (Events by Minute)</h2>
      {% if timeline %}
        {% for bucket, count in timeline %}
        <div class="bar-row">
          <span style="min-width:130px; color:#94a3b8;">{{ bucket }}</span>
          <div class="bar-fill" style="width: {{ count * 28 }}px;"></div>
          <span>{{ count }}</span>
        </div>
        {% endfor %}
      {% else %}
        <p style="color:#94a3b8;">No timeline data yet.</p>
      {% endif %}
    </div>

    <div class="panel">
      <h2>Recent File Integrity Events</h2>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Type</th>
            <th>File</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {% for ev in recent_events %}
          <tr>
            <td>{{ ev.timestamp }}</td>
            <td><span class="badge {{ ev.type }}">{{ ev.type }}</span></td>
            <td><code>{{ ev.file }}</code></td>
            <td>{{ ev.details }}</td>
          </tr>
          {% else %}
          <tr><td colspan="4" style="color:#94a3b8;">No events recorded in log file yet.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""


@app.route("/")
def index() -> str:
    log_path = Path(request.args.get("log", "filewatch.log"))
    status_msg = request.args.get("msg")
    events = parse_log_file(log_path)
    counts = dict(sorted(Counter(e["type"] for e in events).items()))
    timeline = sorted(Counter(e["minute"] for e in events).items())
    recent_events = list(reversed(events[-30:]))
    return render_template_string(
        DASHBOARD_TEMPLATE,
        log_path=str(log_path),
        events=events,
        counts=counts,
        timeline=timeline,
        recent_events=recent_events,
        status_msg=status_msg,
    )


@app.route("/report/<fmt>")
def generate_report(fmt: str):
    log_path = Path(request.args.get("log", "filewatch.log"))
    events = parse_log_file(log_path)
    fmt_lower = fmt.lower()
    if fmt_lower == "html":
        out_path = Path("integrity_report.html")
        out_path.write_text(build_report_html(events, log_path), encoding="utf-8")
        return redirect(url_for("index", log=str(log_path), msg=f"Saved HTML report to {out_path}"))

    out_path = Path("integrity_report.md")
    out_path.write_text(build_report_markdown(events, log_path), encoding="utf-8")
    return redirect(url_for("index", log=str(log_path), msg=f"Saved Markdown report to {out_path}"))


@app.route("/report.md")
def download_md() -> Response:
    log_path = Path(request.args.get("log", "filewatch.log"))
    events = parse_log_file(log_path)
    return Response(build_report_markdown(events, log_path), mimetype="text/markdown")


@app.route("/report.html")
def download_html() -> Response:
    log_path = Path(request.args.get("log", "filewatch.log"))
    events = parse_log_file(log_path)
    return Response(build_report_html(events, log_path), mimetype="text/html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
