#!/usr/bin/env python3
"""
NextDNS Log Parser - generates comprehensive reports from CSV exports.

Handles stupidly large log files by streaming them through Polars,
then spits out either a pretty HTML dashboard or plain text.
"""

import argparse
import glob
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import polars as pl

# --- config bits ---
TOP_N = 20  # how many items to show in each list

# keywords that suggest something nasty is going on
SECURITY_KEYWORDS = [
    "threat", "malware", "phishing", "crypto", "typosquatting",
    "dga", "c2", "botnet", "safe browsing", "security"
]


def find_log_file() -> Path | None:
    """
    Sniffs out the first CSV in the current directory.
    NextDNS exports tend to be short hex names like 'a1b2c3.csv'.
    """
    csv_files = glob.glob("*.csv")
    return Path(csv_files[0]) if csv_files else None


def parse_args():
    """Sets up the command line arguments, nothing fancy."""
    parser = argparse.ArgumentParser(
        description="Parse NextDNS log exports into useful reports"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["html", "txt"],
        default="html",
        help="Output format (default: html)"
    )
    parser.add_argument(
        "--input", "-i",
        type=Path,
        help="Input CSV file (auto-detects if not specified)"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output file path (auto-generated if not specified)"
    )
    return parser.parse_args()


def load_logs(file_path: Path) -> pl.LazyFrame:
    """
    Lazily loads the CSV so we don't choke on massive files.
    Polars handles the heavy lifting here, we just point it at the file.
    """
    return pl.scan_csv(
        file_path,
        try_parse_dates=True,
        ignore_errors=True  # some rows might be wonky
    )


def analyse_logs(lf: pl.LazyFrame) -> dict:
    """
    Crunches all the numbers in one go.
    Returns a dict stuffed with all the stats we need for the report.
    """
    # collect the dataframe - polars optimises the query plan automatically
    df = lf.collect()

    total_queries = len(df)

    # timestamp range for the report header
    timestamps = df.get_column("timestamp")
    date_start = timestamps.min()
    date_end = timestamps.max()

    # --- blocked traffic analysis ---
    blocked_df = df.filter(pl.col("status") == "blocked")
    total_blocked = len(blocked_df)
    block_rate = (
        (total_blocked / total_queries * 100) if total_queries > 0 else 0
    )

    # top blocked domains
    top_blocked_domains = (
        blocked_df.group_by("domain")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
        .head(TOP_N)
        .to_dicts()
    )

    reasons_df = _analyze_block_reasons(blocked_df)
    top_block_reasons = _get_top_block_reasons(reasons_df)
    domain_reason_map = _get_domain_reason_map(reasons_df)
    threat_reasons = _analyze_threats(top_block_reasons)

    # --- general traffic stats ---

    # top resolved domains (all traffic)
    top_domains = (
        df.group_by("domain")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
        .head(TOP_N)
        .to_dicts()
    )

    # top root domains - more useful for seeing which services are chattiest
    top_root_domains = (
        df.filter(pl.col("root_domain").is_not_null())
        .group_by("root_domain")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
        .head(TOP_N)
        .to_dicts()
    )

    # device breakdown
    device_stats = (
        df.filter(pl.col("device_name").is_not_null())
        .group_by("device_name")
        .agg(
            pl.len().alias("total"),
            (pl.col("status") == "blocked").sum().alias("blocked")
        )
        .with_columns(
            (pl.col("blocked") / pl.col("total") * 100).alias("block_rate")
        )
        .sort("total", descending=True)
        .head(TOP_N)
        .to_dicts()
    )

    stats = {
        "total_queries": total_queries,
        "total_blocked": total_blocked,
        "block_rate": block_rate,
        "date_start": date_start,
        "date_end": date_end,
        "top_domains": top_domains,
        "top_blocked_domains": top_blocked_domains,
        "top_root_domains": top_root_domains,
        "top_block_reasons": top_block_reasons,
        "domain_reason_map": domain_reason_map,
        "threat_reasons": threat_reasons,
        "device_stats": device_stats,
    }

    secondary_stats = _add_secondary_stats(df, total_queries)
    stats.update(secondary_stats)

    return stats


def _analyze_block_reasons(blocked_df: pl.LazyFrame) -> pl.LazyFrame:
    """
    block reasons breakdown - need to explode the comma-separated list
    """
    return (
        blocked_df.select("domain", "reasons")
        .filter(pl.col("reasons").is_not_null())
        .with_columns(
            pl.col("reasons").str.split(",").alias("reason_list")
        )
        .explode("reason_list")
        .with_columns(
            pl.col("reason_list").str.strip_chars().alias("reason")
        )
    )


def _get_top_block_reasons(reasons_df: pl.LazyFrame) -> list[dict]:
    """
    top block reasons
    """
    return (
        reasons_df.group_by("reason")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
        .head(TOP_N)
        .to_dicts()
    )


def _get_domain_reason_map(reasons_df: pl.LazyFrame) -> list[dict]:
    """
    domain to reason mapping - which domains got blocked by what
    """
    return (
        reasons_df.group_by("domain", "reason")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
        .head(50)  # top 50 domain-reason combos
        .to_dicts()
    )


def _analyze_threats(top_block_reasons: list[dict]) -> list[dict]:
    """
    security threats - anything matching our scary keywords
    """
    threat_reasons = []
    for item in top_block_reasons:
        reason_lower = item.get("reason", "").lower()
        if any(keyword in reason_lower for keyword in SECURITY_KEYWORDS):
            threat_reasons.append(item)
    return threat_reasons


def _add_secondary_stats(df: pl.DataFrame, total_queries: int) -> dict:
    """
    Add secondary stats like country, protocol, etc.
    """
    secondary_stats = {}

    # country breakdown for the map
    secondary_stats["country_stats"] = (
        df.filter(pl.col("destination_country").is_not_null())
        .group_by("destination_country")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
        .to_dicts()
    )

    # protocol distribution (DoH vs DoT etc)
    secondary_stats["protocol_stats"] = (
        df.filter(pl.col("protocol").is_not_null())
        .group_by("protocol")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
        .to_dicts()
    )

    # query type breakdown
    secondary_stats["query_type_stats"] = (
        df.filter(pl.col("query_type").is_not_null())
        .group_by("query_type")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
        .to_dicts()
    )

    # DNSSEC adoption
    dnssec_count = df.filter(pl.col("dnssec").eq(True)).height
    secondary_stats["dnssec_rate"] = (
        (dnssec_count / total_queries * 100) if total_queries > 0 else 0
    )

    # hourly activity pattern
    secondary_stats["hourly_stats"] = (
        df.with_columns(pl.col("timestamp").dt.hour().alias("hour"))
        .group_by("hour")
        .agg(pl.len().alias("count"))
        .sort("hour")
        .to_dicts()
    )

    # daily volume over time
    secondary_stats["daily_stats"] = (
        df.with_columns(pl.col("timestamp").dt.date().alias("date"))
        .group_by("date")
        .agg(
            pl.len().alias("total"),
            (pl.col("status") == "blocked").sum().alias("blocked")
        )
        .sort("date")
        .to_dicts()
    )

    return secondary_stats


def generate_text_report(stats: dict, output_path: Path):
    """
    Spits out a plain text report, for those who prefer the classics.
    """
    lines = []

    def w(text=""):
        lines.append(text)

    w("=" * 80)
    w("NEXTDNS LOG ANALYSIS REPORT")
    w(f"Date Range: {stats['date_start']} to {stats['date_end']}")
    w(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    w(f"Total Queries: {stats['total_queries']:,}")
    w(f"Total Blocked: {stats['total_blocked']:,} "
      f"({stats['block_rate']:.1f}%)")
    w("=" * 80)
    w()

    # threats section - the important bit
    w("SECURITY THREATS DETECTED")
    w("-" * 40)
    if not stats["threat_reasons"]:
        w("  All clear! No security threats detected.")
    else:
        for item in stats["threat_reasons"]:
            w(f"  {item['count']:>8,} blocks -- {item['reason']}")
    w()

    # block reasons
    w(f"TOP {TOP_N} BLOCK REASONS")
    w("-" * 40)
    for item in stats["top_block_reasons"]:
        w(f"  {item['count']:>8,} hits -- {item['reason']}")
    w()

    # blocked domains with their reasons
    w("TOP BLOCKED DOMAINS (with reasons)")
    w("-" * 40)
    domain_reasons = {}
    for item in stats["domain_reason_map"]:
        domain = item["domain"]
        if domain not in domain_reasons:
            domain_reasons[domain] = []
        domain_reasons[domain].append(item["reason"])

    for item in stats["top_blocked_domains"][:TOP_N]:
        domain = item["domain"]
        reasons = domain_reasons.get(domain, ["unknown"])[:3]
        w(f"  {item['count']:>8,} -- {domain}")
        w(f"           reasons: {', '.join(reasons)}")
    w()

    # device stats
    w(f"TOP {TOP_N} DEVICES")
    w("-" * 40)
    for item in stats["device_stats"]:
        w(f"  {item['total']:>8,} queries "
          f"({item['block_rate']:>5.1f}% blocked) -- {item['device_name']}")
    w()

    # country breakdown
    w("TOP DESTINATION COUNTRIES")
    w("-" * 40)
    for item in stats["country_stats"][:TOP_N]:
        w(f"  {item['count']:>8,} queries -- {item['destination_country']}")
    w()

    # protocol and query types
    w("PROTOCOL DISTRIBUTION")
    w("-" * 40)
    for item in stats["protocol_stats"]:
        pct = item["count"] / stats["total_queries"] * 100
        w(f"  {item['count']:>8,} ({pct:>5.1f}%) -- {item['protocol']}")
    w()

    w(f"DNSSEC: {stats['dnssec_rate']:.1f}% of queries")
    w("=" * 80)

    output_path.write_text("\n".join(lines), encoding="utf-8")


def generate_html_report(stats: dict, output_path: Path):
    """
    Creates a fancy HTML report with charts and a world map.
    Uses Chart.js and a simple SVG map, all from CDN so it works offline-ish.
    """
    # prep the data for charts
    daily_labels = [str(d["date"]) for d in stats["daily_stats"]]
    daily_totals = [d["total"] for d in stats["daily_stats"]]
    daily_blocked = [d["blocked"] for d in stats["daily_stats"]]

    hourly_labels = [f"{d['hour']:02d}:00" for d in stats["hourly_stats"]]
    hourly_counts = [d["count"] for d in stats["hourly_stats"]]

    country_data = {
        d["destination_country"]: d["count"] for d in stats["country_stats"]
    }

    block_reason_labels = [
        d["reason"][:30] for d in stats["top_block_reasons"][:10]
    ]
    block_reason_counts = [
        d["count"] for d in stats["top_block_reasons"][:10]
    ]

    # escape helper for safety
    def esc(s):
        return html.escape(str(s)) if s else ""

    # the threat status determines the alert colour
    has_threats = len(stats["threat_reasons"]) > 0

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextDNS Report - {stats["date_start"]} to {stats["date_end"]}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/jsvectormap"></script>
    <script src="https://cdn.jsdelivr.net/npm/jsvectormap/dist/maps/world.js">
    </script>
    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/jsvectormap/dist/css/jsvectormap.min.css">
    <style>
        :root {{
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: rgba(255, 255, 255, 0.03);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #e8e8ed;
            --text-secondary: #8b8b9e;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-pink: #ec4899;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-orange: #f59e0b;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            text-align: center;
            margin-bottom: 3rem;
        }}

        header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-blue),
                                      var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }}

        header .subtitle {{
            color: var(--text-secondary);
            font-size: 1rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
        }}

        .stat-card .value {{
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-blue),
                                      var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-top: 0.25rem;
        }}

        .card {{
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}

        .card h2 {{
            font-size: 1.25rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .card h2 .icon {{
            width: 24px;
            height: 24px;
        }}

        .threat-card {{
            border-color: {("var(--accent-red)" if has_threats
                            else "var(--accent-green)")};
            background: {("rgba(239, 68, 68, 0.1)" if has_threats
                          else "rgba(16, 185, 129, 0.1)")};
        }}

        .threat-card h2 {{
            color: {("var(--accent-red)" if has_threats
                     else "var(--accent-green)")};
        }}

        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 1.5rem;
        }}

        .grid-3 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        td {{
            font-size: 0.875rem;
        }}

        .count {{
            font-variant-numeric: tabular-nums;
            color: var(--accent-blue);
            font-weight: 600;
        }}

        .domain {{
            font-family: "SF Mono", Monaco, monospace;
            font-size: 0.8rem;
            color: var(--text-primary);
            word-break: break-all;
        }}

        .reason-tag {{
            display: inline-block;
            background: rgba(139, 92, 246, 0.2);
            color: var(--accent-purple);
            padding: 0.125rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            margin: 0.125rem;
        }}

        .chart-container {{
            position: relative;
            height: 300px;
        }}

        #worldMap {{
            height: 400px;
            border-radius: 12px;
            overflow: hidden;
        }}

        .progress-bar {{
            width: 100%;
            height: 8px;
            background: var(--bg-secondary);
            border-radius: 4px;
            overflow: hidden;
        }}

        .progress-bar .fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--accent-blue),
                                      var(--accent-purple));
            border-radius: 4px;
        }}

        .device-row {{
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--border-color);
        }}

        .device-row:last-child {{
            border-bottom: none;
        }}

        .device-name {{
            flex: 1;
            font-weight: 500;
        }}

        .device-stats {{
            text-align: right;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}

        .device-stats .blocked {{
            color: var(--accent-red);
        }}

        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}

        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}
            .grid-2, .grid-3 {{
                grid-template-columns: 1fr;
            }}
            header h1 {{
                font-size: 1.75rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>NextDNS Analytics Report</h1>
            <p class="subtitle">{esc(stats["date_start"])} to {esc(stats["date_end"])}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{stats["total_queries"]:,}</div>
                <div class="label">Total Queries</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats["total_blocked"]:,}</div>
                <div class="label">Blocked Queries</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats["block_rate"]:.1f}%</div>
                <div class="label">Block Rate</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats["dnssec_rate"]:.1f}%</div>
                <div class="label">DNSSEC Validated</div>
            </div>
        </div>

        <div class="card threat-card">
            <h2>{"Security Threats Detected" if has_threats else "No Security Threats"}</h2>
            {
                "<table><thead><tr><th>Threat Type</th><th>Blocks</th></tr></thead><tbody>" +
                "".join(f'<tr><td>{esc(t["reason"])}</td><td class="count">{t["count"]:,}</td></tr>'
                        for t in stats["threat_reasons"]) + "</tbody></table>"
                if has_threats else
                "<p>All clear - no security-related blocks detected in this period.</p>"
            }
        </div>

        <div class="grid-2">
            <div class="card">
                <h2>Queries Over Time</h2>
                <div class="chart-container">
                    <canvas id="dailyChart"></canvas>
                </div>
            </div>
            <div class="card">
                <h2>Hourly Activity Pattern</h2>
                <div class="chart-container">
                    <canvas id="hourlyChart"></canvas>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Traffic Destinations</h2>
            <div id="worldMap"></div>
        </div>

        <div class="grid-2">
            <div class="card">
                <h2>Top Block Reasons</h2>
                <div class="chart-container">
                    <canvas id="reasonsChart"></canvas>
                </div>
            </div>
            <div class="card">
                <h2>Top Blocked Domains</h2>
                <table>
                    <thead>
                        <tr><th>Domain</th><th>Reasons</th><th>Count</th></tr>
                    </thead>
                    <tbody>
                    {"".join(
                        _generate_blocked_domain_row(d, stats["domain_reason_map"])
                        for d in stats["top_blocked_domains"][:15]
                    )}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="grid-3">
            <div class="card">
                <h2>Top Resolved Domains</h2>
                <table>
                    <thead><tr><th>Domain</th><th>Count</th></tr></thead>
                    <tbody>
                        {"".join(
                            f'<tr><td class="domain">{esc(d["domain"])}</td>'
                            f'<td class="count">{d["count"]:,}</td></tr>'
                            for d in stats["top_domains"][:12]
                        )}
                    </tbody>
                </table>
            </div>
            <div class="card">
                <h2>Top Root Domains</h2>
                <table>
                    <thead><tr><th>Service</th><th>Count</th></tr></thead>
                    <tbody>
                        {"".join(
                            f'<tr><td class="domain">{esc(d["root_domain"])}</td>'
                            f'<td class="count">{d["count"]:,}</td></tr>'
                            for d in stats["top_root_domains"][:12]
                        )}
                    </tbody>
                </table>
            </div>
            <div class="card">
                <h2>Protocol Distribution</h2>
                <table>
                    <thead><tr><th>Protocol</th><th>Count</th></tr></thead>
                    <tbody>
                        {"".join(
                            f'<tr><td>{esc(d["protocol"])}</td>'
                            f'<td class="count">{d["count"]:,}</td></tr>'
                            for d in stats["protocol_stats"]
                        )}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <h2>Devices</h2>
            {"".join(_generate_device_row(d, stats["total_queries"])
                     for d in stats["device_stats"])}
        </div>

        <footer>
            <p>Generated on {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
        </footer>
    </div>

    <script>
        // chart styling
        Chart.defaults.color = '#8b8b9e';
        Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.08)';

        // daily queries chart
        new Chart(document.getElementById('dailyChart'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(daily_labels)},
                datasets: [{{
                    label: 'Total Queries',
                    data: {json.dumps(daily_totals)},
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4
                }}, {{
                    label: 'Blocked',
                    data: {json.dumps(daily_blocked)},
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                    tension: 0.4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'top' }}
                }},
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});

        // hourly pattern chart
        new Chart(document.getElementById('hourlyChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(hourly_labels)},
                datasets: [{{
                    label: 'Queries',
                    data: {json.dumps(hourly_counts)},
                    backgroundColor: 'rgba(139, 92, 246, 0.6)',
                    borderColor: '#8b5cf6',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});

        // block reasons chart
        new Chart(document.getElementById('reasonsChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(block_reason_labels)},
                datasets: [{{
                    data: {json.dumps(block_reason_counts)},
                    backgroundColor: [
                        '#3b82f6', '#8b5cf6', '#ec4899', '#10b981', '#f59e0b',
                        '#06b6d4', '#6366f1', '#f43f5e', '#84cc16', '#f97316'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'right' }}
                }}
            }}
        }});

        // world map
        const countryData = {json.dumps(country_data)};
        const maxCount = Math.max(...Object.values(countryData));
        
        new jsVectorMap({{
            selector: '#worldMap',
            map: 'world',
            backgroundColor: 'transparent',
            zoomButtons: false,
            regionStyle: {{
                initial: {{
                    fill: '#1e1e2e',
                    stroke: '#2e2e3e',
                    strokeWidth: 0.5
                }},
                hover: {{
                    fill: '#3b82f6'
                }}
            }},
            visualizeData: {{
                scale: ['#1e293b', '#3b82f6'],
                values: countryData
            }},
            onRegionTooltipShow: function(event, tooltip, code) {{
                const count = countryData[code] || 0;
                tooltip.text(
                    `<div style="padding: 8px">
                        <strong>${{tooltip.text()}}</strong><br>
                        ${{count.toLocaleString()}} queries
                    </div>`,
                    true
                );
            }}
        }});
    </script>
</body>
</html>"""

    output_path.write_text(html_content, encoding="utf-8")


def _generate_blocked_domain_row(domain_item: dict, domain_reason_map: list) -> str:
    """Helper to build a table row for blocked domains with their reasons."""
    domain = domain_item["domain"]
    count = domain_item["count"]

    # grab the reasons for this domain
    reasons = [
        item["reason"] for item in domain_reason_map
        if item["domain"] == domain
    ][:3]  # limit to 3 reasons

    reason_tags = "".join(
        f'<span class="reason-tag">{html.escape(r[:25])}</span>'
        for r in reasons
    ) if reasons else '<span class="reason-tag">unknown</span>'

    return f'''<tr>
        <td class="domain">{html.escape(domain)}</td>
        <td>{reason_tags}</td>
        <td class="count">{count:,}</td>
    </tr>'''


def _generate_device_row(device: dict, total_queries: int) -> str:
    """Helper to build a device row with progress bar."""
    pct = (device["total"] / total_queries * 100) if total_queries > 0 else 0
    return f'''<div class="device-row">
        <div class="device-name">{html.escape(str(device["device_name"]))}</div>
        <div style="flex: 2">
            <div class="progress-bar">
                <div class="fill" style="width: {min(pct * 2, 100)}%"></div>
            </div>
        </div>
        <div class="device-stats">
            {device["total"]:,} queries
            <span class="blocked">({device["block_rate"]:.1f}% blocked)</span>
        </div>
    </div>'''


def main():
    """Entry point - parses args, loads data, generates report."""
    args = parse_args()

    # figure out which file to read
    input_file = args.input or find_log_file()
    if not input_file or not input_file.exists():
        print("Error: No CSV file found. Use --input to specify one.")
        return 1

    # output filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    extension = "html" if args.format == "html" else "txt"
    output_file = args.output or Path(f"NextDNS_Report_{timestamp}.{extension}")

    print(f"Loading {input_file}...")
    lf = load_logs(input_file)

    print("Analysing logs...")
    stats = analyse_logs(lf)

    print(f"Generating {args.format.upper()} report...")
    if args.format == "html":
        generate_html_report(stats, output_file)
    else:
        generate_text_report(stats, output_file)

    print(f"Done! Report saved to: {output_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
