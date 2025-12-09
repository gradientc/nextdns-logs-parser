import pandas as pd
import os
import glob
from datetime import datetime

# --- CONFIGURATION ---
CHUNK_SIZE = 100000             # Process 100k rows at a time
TOP_N = 20                      # Number of items to show in lists

# Security keywords to hunt for in the "reasons" column
SECURITY_KEYWORDS = [
    'threat', 'malware', 'phishing', 'crypto', 'typosquatting', 
    'dga', 'c2', 'botnet', 'safe browsing', 'security'
]

def get_log_file():
    """Automatically finds the first CSV file in the directory."""
    csv_files = glob.glob("*.csv")
    if not csv_files:
        return None
    # NextDNS logs usually look like 'a1b2c3.csv', so we prefer short filenames
    # But we'll just take the first one found to be simple.
    return csv_files[0]

def write_and_print(f, text):
    """Helper to write to file and print to console simultaneously."""
    print(text)
    f.write(text + "\n")

def analyze_logs():
    file_path = get_log_file()
    
    if not file_path:
        print("❌ Error: No CSV file found in this folder.")
        print("   Please place your NextDNS log file (e.g., 'abc1234.csv') in the same folder as this script.")
        return

    report_filename = f"NextDNS_Report_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.txt"
    
    # Initialize counters
    total_queries = 0
    device_stats = {}
    domain_stats = {}
    blocked_domain_stats = {}
    block_reason_stats = {}
    threat_intel_stats = {}
    
    print(f"🚀 Found log file: {file_path}")
    print(f"📄 Preparing report: {report_filename}...")
    
    try:
        # Process file in chunks
        for chunk in pd.read_csv(file_path, chunksize=CHUNK_SIZE):
            
            # 1. Total Volume
            total_queries += len(chunk)
            
            # 2. Device Traffic (Tailscale Handling)
            if 'device_name' in chunk.columns:
                chunk['device_name'] = chunk['device_name'].fillna('Unknown Device')
                dev_counts = chunk['device_name'].value_counts()
                for device, count in dev_counts.items():
                    device_stats[device] = device_stats.get(device, 0) + count

            # 3. Analyze Blocked Traffic Only
            if 'status' in chunk.columns:
                blocked_chunk = chunk[chunk['status'] == 'blocked'].copy()
                
                # Count Blocked Domains
                blocked_counts = blocked_chunk['domain'].value_counts()
                for domain, count in blocked_counts.items():
                    blocked_domain_stats[domain] = blocked_domain_stats.get(domain, 0) + count
                
                # 4. Analyze Block Reasons
                if 'reasons' in blocked_chunk.columns:
                    reasons_series = blocked_chunk['reasons'].dropna().astype(str)
                    for reasons_str in reasons_series:
                        reasons_list = [r.strip() for r in reasons_str.split(',')]
                        for reason in reasons_list:
                            clean_reason = reason.replace('blocklist:', '').replace('security:', '')
                            block_reason_stats[clean_reason] = block_reason_stats.get(clean_reason, 0) + 1
                            
                            # Check for Threats
                            if any(k in clean_reason.lower() for k in SECURITY_KEYWORDS):
                                threat_intel_stats[clean_reason] = threat_intel_stats.get(clean_reason, 0) + 1

            # 5. Top Destinations (All Traffic)
            if 'domain' in chunk.columns:
                dom_counts = chunk['domain'].value_counts()
                for domain, count in dom_counts.items():
                    domain_stats[domain] = domain_stats.get(domain, 0) + count

            print(f"   ...processed {total_queries:,} rows...", end='\r')
            
    except Exception as e:
        print(f"\n❌ Error reading CSV: {e}")
        return

    print(f"\n✅ Analysis Complete. Writing report...")

    # --- WRITING THE REPORT ---
    with open(report_filename, "w", encoding="utf-8") as f:
        write_and_print(f, "="*80)
        write_and_print(f, f"NEXTDNS LOG ANALYSIS REPORT")
        write_and_print(f, f"Source File: {file_path}")
        write_and_print(f, f"Date Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        write_and_print(f, f"Total Queries Scanned: {total_queries:,}")
        write_and_print(f, "="*80)
        write_and_print(f, "")

        # 1. THREAT INTELLIGENCE
        write_and_print(f, f"🚨 SECURITY THREATS DETECTED (High Priority)")
        if not threat_intel_stats:
            write_and_print(f, "   ✅ Clean! No security threats detected.")
        else:
            sorted_threats = sorted(threat_intel_stats.items(), key=lambda x: x[1], reverse=True)
            for reason, count in sorted_threats:
                write_and_print(f, f"   {count:>8,} blocks -- {reason}")
        write_and_print(f, "-" * 80)
        write_and_print(f, "")

        # 2. TOP BLOCK REASONS
        write_and_print(f, f"🛡️ TOP {TOP_N} BLOCK SOURCES (Filter Lists)")
        sorted_reasons = sorted(block_reason_stats.items(), key=lambda x: x[1], reverse=True)[:TOP_N]
        for reason, count in sorted_reasons:
            write_and_print(f, f"   {count:>8,} hits   -- {reason}")
        write_and_print(f, "-" * 80)
        write_and_print(f, "")

        # 3. TOP BLOCKED DOMAINS
        write_and_print(f, f"🚫 TOP {TOP_N} BLOCKED DOMAINS")
        sorted_blocked = sorted(blocked_domain_stats.items(), key=lambda x: x[1], reverse=True)[:TOP_N]
        for domain, count in sorted_blocked:
            write_and_print(f, f"   {count:>8,} blocked -- {domain}")
        write_and_print(f, "-" * 80)
        write_and_print(f, "")
        
        # 4. TOP TALKERS
        write_and_print(f, f"📡 TOP {TOP_N} NOISIEST DEVICES (Tailscale Nodes)")
        sorted_devices = sorted(device_stats.items(), key=lambda x: x[1], reverse=True)[:TOP_N]
        for device, count in sorted_devices:
            percentage = (count / total_queries) * 100
            write_and_print(f, f"   {count:>8,} queries ({percentage:04.1f}%) -- {device}")
        write_and_print(f, "=" * 80)
        
    print(f"\n📄 Report saved to: {report_filename}")

if __name__ == "__main__":
    analyze_logs()