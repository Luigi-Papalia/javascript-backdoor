import os
import sys
import argparse
from collections import defaultdict
from ioc_finder import find_iocs
from pymisp import PyMISP
from concurrent.futures import ThreadPoolExecutor
import urllib3
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── CLI Argument Parsing ───────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(description="Scan files for IOCs and check MISP")
    parser.add_argument("--input-folder", default=".",
                        help="Directory to scan for IOCs")
    parser.add_argument("--max-workers", type=int, default=8,
                        help="Number of worker threads for MISP queries")
    parser.add_argument("--misp-url", required=True,
                        help="Base URL of MISP instance")
    parser.add_argument("--misp-key", required=True,
                        help="API key for MISP authentication")
    parser.add_argument("--verify-cert", default=False,
                        help="Verify SSL certificates for MISP API calls")
    return parser.parse_args()

# ── 1) Setup and Initialization ──────────────────────────────────────────────────
def initialize(args):
    # Initialize MISP client with connection pooling
    misp = PyMISP(args.misp_url, args.misp_key, ssl=args.verify_cert)
    session = misp._PyMISP__session
    session.verify = args.verify_cert
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=50)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return misp

# ── 2) Collect & dedupe all IOCs, mapping to source files ───────────────────────
def collect_iocs(input_folder, extensions):
    ioc_sources = defaultdict(set)
    for root, _, files in os.walk(input_folder):
        for fn in files:
            ext = fn.rsplit('.', 1)[-1]
            if ext in extensions:
                path = os.path.join(root, fn)
                try:
                    with open(path, encoding='utf-8') as f:
                        content = f.read()
                except Exception as e:
                    print(f"[WARN] Cannot read {path}: {e}")
                    continue

                extracted = find_iocs(content)
                for lst in extracted.values():
                    for ioc in lst:
                        ioc_sources[ioc].add(path)
    return ioc_sources

# ── 3) Cache-backed MISP search ─────────────────────────────────────────────────
cache = {}
def cached_search(misp, ioc):
    if ioc in cache:
        return cache[ioc]
    res = misp.search(
        controller='attributes',
        value=ioc,
        return_format='json',
        pythonify=False
    )
    attrs = res.get('Attribute', [])
    cache[ioc] = attrs
    return attrs

# ── 4) Display details with file context ───────────────────────────────────────
def display_match_details(misp, attr, filepath):
    try:
        event = misp.get_event(attr['event_id'], pythonify=True)
        print(f"\n[ALERT] Match found (file: {filepath}):")
        print(f"  - IOC Value           : {attr.get('value')}")
        print(f"  - IOC Type            : {attr.get('type')}")
        print(f"  - Category            : {attr.get('category')}")
        print(f"  - To IDS              : {attr.get('to_ids')}")
        print(f"  - Comment             : {attr.get('comment')}")
        tags = [t['name'] for t in attr.get('Tag', [])]
        print(f"  - Attribute Tags      : {tags}")

        print(f"  - Event ID            : {event.id}")
        print(f"  - Event Info          : {event.info}")
        print(f"  - Event Date          : {event.date}")
        etags = [t.name for t in event.tags]
        print(f"  - Event Tags          : {etags}")
        print(f"  - Event Threat Level  : {event.threat_level_id}")
        print(f"  - Event Analysis      : {event.analysis}")
        print(f"  - Event Distribution  : {event.distribution}")
        print(f"  - Event Org           : {event.orgc.name}")
    except Exception as e:
        print(f"[ERROR] Failed to retrieve details for event {attr.get('event_id')}: {e}")

# ── 5) Main workflow ────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    # Validate input folder
    if not os.path.isdir(args.input_folder):
        print(f"[ERROR] The directory {args.input_folder} does not exist.")
        sys.exit(1)

    print(f"[INFO] Scanning '{args.input_folder}' with {args.max_workers} threads...")

    # Initialize MISP client
    misp = initialize(args)

    # Collect IOCs
    extensions = {'txt', 'js', 'yaml', 'json', 'html', 'Dockerfile'}
    ioc_sources = collect_iocs(args.input_folder, extensions)
    print(f"[INFO] Collected {len(ioc_sources)} unique IOCs.")

    # Process IOCs in parallel
    seen = set()
    def worker(ioc):
        matches = cached_search(misp, ioc)
        for attr in matches:
            key = (attr['event_id'], attr['value'], tuple(sorted(ioc_sources[ioc])))
            if key in seen:
                continue
            seen.add(key)
            for filepath in ioc_sources[ioc]:
                display_match_details(misp, attr, filepath)

    with ThreadPoolExecutor(max_workers=args.max_workers) as exe:
        exe.map(worker, list(ioc_sources.keys()))

if __name__ == '__main__':
    main()
