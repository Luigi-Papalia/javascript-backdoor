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

# ── Initialize MISP with connection pooling ────────────────────────────────────
def initialize_misp(url, key, verify):
    misp = PyMISP(url, key, ssl=verify)
    session = misp._PyMISP__session
    session.verify = verify
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=50)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return misp

# ── Collect & dedupe all IOCs, mapping to source files ────────────────────────
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
                    print(f"**Warning:** Cannot read `{path}`: {e}")
                    continue

                for lst in find_iocs(content).values():
                    for ioc in lst:
                        ioc_sources[ioc].add(path)
    return ioc_sources

# ── Cache-backed MISP search ─────────────────────────────────────────────────
cache = {}
def cached_search(misp, ioc):
    if ioc in cache:
        return cache[ioc]
    res = misp.search(controller='attributes', value=ioc, return_format='json', pythonify=False)
    attrs = res.get('Attribute', [])
    cache[ioc] = attrs
    return attrs

# ── Display details in Markdown format ────────────────────────────────────────
def display_match_details_md(misp, attr, filepath):
    try:
        event = misp.get_event(attr['event_id'], pythonify=True)
        # Markdown header for each alert
        print(f"## :warning: Alert: Match found (file: `{filepath}`)")
        print()
        # IOC details
        print(f"- **IOC Value:** `{attr.get('value')}`")
        print(f"- **IOC Type:** {attr.get('type')}  ")
        print(f"- **Category:** {attr.get('category')}  ")
        print(f"- **To IDS:** {attr.get('to_ids')}  ")
        comment = attr.get('comment') or ''
        print(f"- **Comment:** {comment}  ")
        tags = ', '.join(f'`{t["name"]}`' for t in attr.get('Tag', []))
        print(f"- **Attribute Tags:** {tags if tags else 'None'}")
        print()
        # Event details
        print(f"### Event Details")
        print(f"- **Event ID:** {event.id}")
        print(f"- **Info:** {event.info}")
        print(f"- **Date:** {event.date}")
        etags = ', '.join(f'`{t.name}`' for t in event.tags)
        print(f"- **Event Tags:** {etags if etags else 'None'}")
        print(f"- **Threat Level:** {event.threat_level_id}")
        print(f"- **Analysis:** {event.analysis}")
        print(f"- **Distribution:** {event.distribution}")
        print(f"- **Organization:** {event.orgc.name}")
        print()
    except Exception as e:
        print(f"**Error:** Failed to retrieve details for event `{attr.get('event_id')}`: {e}")

# ── Main workflow ─────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    if not os.path.isdir(args.input_folder):
        print(f"**Error:** The directory `{args.input_folder}` does not exist.")
        sys.exit(1)

    print(f"# IOC Matcher Report")
    print(f"Scanned directory: `{args.input_folder}` with `{args.max_workers}` threads  ")
    print()

    # Initialize MISP
    misp = initialize_misp(args.misp_url, args.misp_key, args.verify_cert)

    # Collect IOCs
    extensions = {'txt', 'js', 'yaml', 'json', 'html', 'Dockerfile'}
    ioc_sources = collect_iocs(args.input_folder, extensions)
    print(f"- **Total unique IOCs:** {len(ioc_sources)}  ")
    print()

    # Process IOCs
    seen = set()
    def worker(ioc):
        matches = cached_search(misp, ioc)
        for attr in matches:
            key = (attr['event_id'], attr['value'], tuple(sorted(ioc_sources[ioc])))
            if key in seen:
                continue
            seen.add(key)
            for filepath in ioc_sources[ioc]:
                display_match_details_md(misp, attr, filepath)

    with ThreadPoolExecutor(max_workers=args.max_workers) as exe:
        exe.map(worker, list(ioc_sources.keys()))

if __name__ == '__main__':
    main()
