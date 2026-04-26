from datetime import datetime
import os

def generate_report(findings, target_url, output_path="report.html"):
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(findings)

    # Build findings rows
    if findings:
        rows = ""
        for i, f in enumerate(findings, 1):
            severity = f.get("severity", "Low")
            rows += f"""
            <tr>
                <td class="num">{i}</td>
                <td><span class="badge badge-{severity}">{severity}</span></td>
                <td class="type-cell">{f.get("type", "")}</td>
                <td class="url-cell">{f.get("url", "")}</td>
                <td class="detail-cell">{f.get("detail", "")}</td>
            </tr>"""
        table_html = f"""
        <table class="findings-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Detail</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""
    else:
        table_html = '<div class="no-findings">✓ No vulnerabilities detected.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>VulnScanX Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@300;400;600;700&display=swap');
  :root {{
    --bg:#0b0e14; --surface:#111520; --border:#1e2535;
    --accent:#00e5ff; --accent2:#ff3e6c;
    --critical:#ff3e6c; --high:#ff8c42; --medium:#f7c948; --low:#4fc3f7;
    --text:#c9d1e0; --muted:#5a6480;
    --mono:'Share Tech Mono',monospace; --sans:'Barlow',sans-serif;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--text); font-family:var(--sans); font-size:15px; line-height:1.6; }}
  body::before {{
    content:''; position:fixed; inset:0;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,229,255,0.015) 2px,rgba(0,229,255,0.015) 4px);
    pointer-events:none; z-index:1000;
  }}
  header {{
    background:var(--surface); border-bottom:1px solid var(--border);
    padding:2rem 3rem; display:flex; justify-content:space-between; align-items:flex-start;
  }}
  .logo {{ font-family:var(--mono); font-size:2rem; color:var(--accent); letter-spacing:0.08em; text-shadow:0 0 20px rgba(0,229,255,0.4); }}
  .logo span {{ color:var(--accent2); }}
  .scan-meta {{ text-align:right; font-family:var(--mono); font-size:0.8rem; color:var(--muted); line-height:1.8; }}
  .scan-meta strong {{ color:var(--text); }}
  .container {{ max-width:1200px; margin:0 auto; padding:2.5rem 3rem; }}
  .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:1rem; margin-bottom:2.5rem; }}
  .summary-card {{ background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:1.25rem 1.5rem; position:relative; overflow:hidden; }}
  .summary-card::before {{ content:''; position:absolute; top:0; left:0; right:0; height:3px; }}
  .summary-card.total::before {{ background:var(--accent); }}
  .summary-card.critical::before {{ background:var(--critical); }}
  .summary-card.high::before {{ background:var(--high); }}
  .summary-card.medium::before {{ background:var(--medium); }}
  .summary-card.low::before {{ background:var(--low); }}
  .label {{ font-size:0.7rem; text-transform:uppercase; letter-spacing:0.12em; color:var(--muted); margin-bottom:0.5rem; font-family:var(--mono); }}
  .count {{ font-family:var(--mono); font-size:2.4rem; font-weight:700; line-height:1; }}
  .summary-card.total .count {{ color:var(--accent); }}
  .summary-card.critical .count {{ color:var(--critical); }}
  .summary-card.high .count {{ color:var(--high); }}
  .summary-card.medium .count {{ color:var(--medium); }}
  .summary-card.low .count {{ color:var(--low); }}
  .section-title {{ font-family:var(--mono); font-size:0.75rem; text-transform:uppercase; letter-spacing:0.15em; color:var(--muted); margin-bottom:1rem; padding-bottom:0.5rem; border-bottom:1px solid var(--border); }}
  .findings-table {{ width:100%; border-collapse:collapse; font-size:0.9rem; }}
  .findings-table thead tr {{ background:rgba(0,229,255,0.04); border-bottom:1px solid var(--border); }}
  .findings-table th {{ font-family:var(--mono); font-size:0.7rem; text-transform:uppercase; letter-spacing:0.1em; color:var(--muted); padding:0.75rem 1rem; text-align:left; font-weight:400; }}
  .findings-table td {{ padding:0.9rem 1rem; border-bottom:1px solid rgba(30,37,53,0.8); vertical-align:top; }}
  .findings-table tbody tr:hover {{ background:rgba(0,229,255,0.03); }}
  .num {{ font-family:var(--mono); font-size:0.75rem; color:var(--muted); }}
  .badge {{ display:inline-block; font-family:var(--mono); font-size:0.68rem; font-weight:700; letter-spacing:0.06em; padding:0.2em 0.6em; border-radius:3px; text-transform:uppercase; }}
  .badge-Critical {{ background:rgba(255,62,108,0.15); color:var(--critical); border:1px solid rgba(255,62,108,0.3); }}
  .badge-High {{ background:rgba(255,140,66,0.15); color:var(--high); border:1px solid rgba(255,140,66,0.3); }}
  .badge-Medium {{ background:rgba(247,201,72,0.12); color:var(--medium); border:1px solid rgba(247,201,72,0.3); }}
  .badge-Low {{ background:rgba(79,195,247,0.1); color:var(--low); border:1px solid rgba(79,195,247,0.25); }}
  .url-cell {{ font-family:var(--mono); font-size:0.78rem; color:var(--accent); word-break:break-all; max-width:300px; }}
  .detail-cell {{ color:var(--text); font-size:0.85rem; opacity:0.85; max-width:380px; }}
  .type-cell {{ font-weight:600; color:var(--text); white-space:nowrap; }}
  .no-findings {{ text-align:center; padding:3rem; color:var(--muted); font-family:var(--mono); font-size:0.85rem; border:1px dashed var(--border); border-radius:4px; }}
  footer {{ text-align:center; padding:2rem; font-family:var(--mono); font-size:0.72rem; color:var(--muted); border-top:1px solid var(--border); margin-top:3rem; }}
  footer span {{ color:var(--accent); }}
</style>
</head>
<body>

<header>
  <div>
    <div class="logo">VULN<span>SCAN</span>X</div>
    <div style="margin-top:0.5rem;font-size:0.85rem;color:var(--muted);">Web Application Vulnerability Scanner</div>
  </div>
  <div class="scan-meta">
    <div><strong>Target:</strong> {target_url}</div>
    <div><strong>Scan Time:</strong> {scan_time}</div>
    <div><strong>Total Findings:</strong> {total}</div>
  </div>
</header>

<div class="container">
  <div class="summary-grid">
    <div class="summary-card total">
      <div class="label">Total Findings</div>
      <div class="count">{total}</div>
    </div>
    <div class="summary-card critical">
      <div class="label">Critical</div>
      <div class="count">{severity_counts["Critical"]}</div>
    </div>
    <div class="summary-card high">
      <div class="label">High</div>
      <div class="count">{severity_counts["High"]}</div>
    </div>
    <div class="summary-card medium">
      <div class="label">Medium</div>
      <div class="count">{severity_counts["Medium"]}</div>
    </div>
    <div class="summary-card low">
      <div class="label">Low</div>
      <div class="count">{severity_counts["Low"]}</div>
    </div>
  </div>

  <div class="section-title">// Vulnerability Findings</div>
  {table_html}
</div>

<footer>Generated by <span>VulnScanX</span> — For authorized security testing only</footer>

</body>
</html>"""

    abs_output = os.path.abspath(output_path)
    with open(abs_output, "w", encoding="utf-8") as file:
        file.write(html)

    print(f"\n[+] Report saved to: {abs_output}")
