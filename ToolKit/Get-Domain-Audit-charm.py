import subprocess
import shutil
import re
import sys


# --- Helper Functions ---
def run_command(cmd_list):
    """Runs a shell command and returns the output string."""
    try:
        if not shutil.which(cmd_list[0]):
            return None
        # stderr=subprocess.DEVNULL hides the "curl" progress meter/errors cleanly
        result = subprocess.run(cmd_list, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception:
        return None


def get_dig(record_type, target):
    """Helper to run dig and format the output."""
    output = run_command(["dig", "+short", record_type, target])
    return output.replace('\n', ', ') if output else None


def get_whois_info(target):
    """Attempts to parse Registrar and Expiry from raw WHOIS data."""
    raw = run_command(["whois", target])

    # Defaults
    registrar = "Unknown (Manual Check)"
    expiry = "Unknown (Manual Check)"
    registrant_loc = "Unknown"
    registrant_name = "Redacted"

    # SPECIAL HANDLING FOR .EDU DOMAINS
    if target.endswith(".edu"):
        registrar = "Educause"

    if raw:
        # Registrar (Overwrites default if found, unless it's .edu which is fixed)
        if not target.endswith(".edu"):
            reg_match = re.search(r'Registrar:\s*(.+)', raw, re.IGNORECASE)
            if reg_match:
                registrar = reg_match.group(1).strip()

        # Expiry - Handles Standard + Educause formats
        exp_match = re.search(r'(Registry Expiry Date|Expiration Date|Domain expires):\s*(.+)', raw, re.IGNORECASE)
        if exp_match:
            expiry = exp_match.group(2).strip()

        # Registrant Name
        # Educause often lists "Organization: Hope College", standard uses "Registrant Name"
        name_match = re.search(r'(Registrant Name|Organization):\s*(.+)', raw, re.IGNORECASE)
        if name_match:
            name_val = name_match.group(2).strip()
            if "REDACTED" not in name_val.upper():
                registrant_name = name_val

        # Location
        loc_match = re.search(r'Registrant (State/Province|Country):\s*(.+)', raw, re.IGNORECASE)
        if loc_match:
            registrant_loc = loc_match.group(2).strip()

    return registrar, expiry, registrant_name, registrant_loc


def get_hosting_provider(ip_address):
    """Runs WHOIS on the IP to identify the hosting company."""
    if not ip_address:
        return "Unknown"

    first_ip = ip_address.split(',')[0].strip()

    # Fastly / Generic CDN Check
    if first_ip.startswith("151.101") or first_ip.startswith("199.232"):
        return "Fastly (CDN)"

    raw = run_command(["whois", first_ip])
    provider = "Unknown Provider"

    if raw:
        org_match = re.search(r'OrgName:\s*(.+)', raw, re.IGNORECASE)
        net_match = re.search(r'NetName:\s*(.+)', raw, re.IGNORECASE)

        if org_match:
            provider = org_match.group(1).strip()
        elif net_match:
            provider = net_match.group(1).strip()

        # Clean up common messy names
        p_up = provider.upper()
        if "GOOGLE" in p_up:
            provider = "Google Cloud"
        elif "AMAZON" in p_up or "AWS" in p_up:
            provider = "AWS"
        elif "CLOUDFLARE" in p_up:
            provider = "Cloudflare"
        elif "MICROSOFT" in p_up:
            provider = "Microsoft Azure / 365"
        elif "FASTLY" in p_up:
            provider = "Fastly (CDN)"
        elif "AKAMAI" in p_up:
            provider = "Akamai (CDN)"
        elif "RIPE" in p_up:
            provider = "Europe/Global Registry (See IP)"

    return provider.title()


def check_hsts(target):
    """Checks for Strict-Transport-Security header via curl (Case Insensitive)."""
    headers = run_command(["curl", "-s", "-I", "-L", "--max-time", "5", f"http://{target}"])
    if headers and "strict-transport-security" in headers.lower():
        return "Active / Enabled"
    return "Not Configured"


def find_dkim(target):
    """Smart Scans for common DKIM selectors."""
    candidates = ["selector1", "google", "default", "k1", "mandrill", "20230601"]
    for sel in candidates:
        result = get_dig("CNAME", f"{sel}._domainkey.{target}")
        if not result:
            result = get_dig("TXT", f"{sel}._domainkey.{target}")
        if result:
            return "Enabled", f"Selector '{sel}': {result}"
    return "Disabled / Unknown", "No common selectors found"


def check_transfer_lock(target):
    # .EDU domains don't use standard EPP locks
    if target.endswith(".edu"):
        return "Restricted (Educause Policy)"

    whois_data = run_command(["whois", target])
    if whois_data:
        if "clientTransferProhibited" in whois_data or "serverTransferProhibited" in whois_data:
            return "Enabled"
        return "Disabled / Unlocked"
    return "Unknown"


# --- Main Interaction ---
print("-" * 60)
domain = input("Enter the domain (e.g., aerosgroup.com): ").strip()
if not domain:
    exit()

print(f"\nQuerying detailed infrastructure for {domain}...\n")

# --- Fetch Data ---
ns_raw = get_dig("NS", domain)
a_raw = get_dig("A", domain)
aaaa_raw = get_dig("AAAA", domain)
mx_raw = get_dig("MX", domain)
caa_raw = get_dig("CAA", domain)
ds_raw = get_dig("DS", domain)
soa_raw = get_dig("SOA", domain)

web_host_provider = get_hosting_provider(a_raw)

# SPF Parsing
spf_raw = "Missing"
txt_out = run_command(["dig", "+short", "TXT", domain])
if txt_out:
    for line in txt_out.splitlines():
        if "v=spf1" in line:
            spf_raw = line.strip('"')
            break

# DMARC & DKIM
dmarc_raw = get_dig("TXT", f"_dmarc.{domain}")
dmarc_raw = dmarc_raw.strip('"') if dmarc_raw else "Not Configured"
dkim_status, dkim_details = find_dkim(domain)

# SOA details
soa_ttl, soa_serial = "Unknown", "Unknown"
soa_full = run_command(["dig", "SOA", domain, "+noall", "+answer"])
if soa_full:
    parts = soa_full.split()
    if len(parts) >= 7:
        soa_ttl = parts[1]
        soa_serial = parts[6]

# Non-DNS Checks
hsts_status = check_hsts(domain)
lock_status = check_transfer_lock(domain)
registrar, expiry, reg_name, reg_loc = get_whois_info(domain)

# --- Output ---
ns_prov = "Custom / Other"
if ns_raw:
    nsl = ns_raw.lower()
    if "microsoft" in nsl:
        ns_prov = "M365 (BDM)"
    elif "bluehost" in nsl:
        ns_prov = "Bluehost"
    elif "cloudflare" in nsl:
        ns_prov = "Cloudflare"
    elif "google" in nsl:
        ns_prov = "Google"
    elif "awsdns" in nsl:
        ns_prov = "AWS Route 53"
    elif "cscdns" in nsl:
        ns_prov = "CSC Corporate"

mx_prov = "Custom / Other"
if mx_raw:
    mxl = mx_raw.lower()
    if "arsmtp" in mxl:
        mx_prov = "AppRiver"
    elif "outlook" in mxl:
        mx_prov = "Direct-to-MS"
    elif "google" in mxl:
        mx_prov = "Google Workspace"
    elif "mimecast" in mxl:
        mx_prov = "Mimecast"

row_fmt = "{:<20} | {:<25} | {:<}"
print("-" * 100)
print(row_fmt.format("Component", "Provider/Status", "Details"))
print("-" * 100)
print(row_fmt.format("Registrar", registrar, f"Expiry: {expiry}"))
print(row_fmt.format("Registrant", reg_name, f"Location: {reg_loc}"))
print(row_fmt.format("Name Servers", ns_prov, ns_raw if ns_raw else "Not Found"))
print(row_fmt.format("A Record (Web)", web_host_provider, a_raw if a_raw else "Not Found"))
print(row_fmt.format("MX Record (Mail)", mx_prov, mx_raw if mx_raw else "Not Found"))
print(row_fmt.format("SPF Record", "TXT Record", spf_raw))
print(row_fmt.format("DNSSEC", "Active" if ds_raw else "Unsigned", ds_raw if ds_raw else "No DS record"))
print(row_fmt.format("CAA Record", "Cert Authority", caa_raw if caa_raw else "Not Configured"))
print(row_fmt.format("HSTS", "Web Server Header", hsts_status))
print(row_fmt.format("Transfer Lock", "Registrar Lock", lock_status))
print(row_fmt.format("SOA Record", "Primary NS", soa_raw if soa_raw else "Not Found"))
print(row_fmt.format("TTL / Serial", f"{soa_ttl} seconds", f"Serial: {soa_serial}"))
print(row_fmt.format("DMARC", "Active" if dmarc_raw != "Not Configured" else "Missing", dmarc_raw))
print(row_fmt.format("DKIM", dkim_status, dkim_details))
print("-" * 100)