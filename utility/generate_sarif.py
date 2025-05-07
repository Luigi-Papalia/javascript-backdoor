import json
import sys
from datetime import datetime

def convert_falco_to_sarif(falco_alerts):
    """Convert multiple Falco alerts to SARIF format"""
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Falco",
                        "informationUri": "https://falco.org",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    # Track rules we've already added to avoid duplicates
    seen_rules = set()

    for alert in falco_alerts:
        try:
            data = json.loads(alert)
            
            # Add rule if not already present
            rule_id = data.get("rule", "unknown_rule")
            if rule_id not in seen_rules:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {
                        "text": data.get("output", "").split(":")[0] or rule_id
                    },
                    "defaultConfiguration": {
                        "level": data.get("priority", "warning").lower()
                    },
                    "properties": {
                        "tags": data.get("tags", [])
                    }
                })
                seen_rules.add(rule_id)

            # Add result
            output_fields = data.get("output_fields", {})
            sarif["runs"][0]["results"].append({
                "ruleId": rule_id,
                "ruleIndex": len(seen_rules) - 1,
                "level": data.get("priority", "warning").lower(),
                "message": {
                    "text": data.get("output", "")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": output_fields.get("fd.name", "unknown_file")
                            }
                        }
                    }
                ],
                "properties": {
                    "eventTime": data.get("time", ""),
                    "user": output_fields.get("user.name", ""),
                    "uid": output_fields.get("user.uid", ""),
                    "process": {
                        "executable": output_fields.get("proc.exepath", ""),
                        "commandLine": output_fields.get("proc.cmdline", "")
                    }
                }
            })

        except json.JSONDecodeError as e:
            print(f"Error parsing line: {alert}\nError: {e}", file=sys.stderr)

    return sarif

def main():
    if len(sys.argv) != 3:
        print("Usage: python falco_to_sarif.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        with open(input_file, 'r') as f:
            falco_alerts = [line.strip() for line in f if line.strip()]

        sarif = convert_falco_to_sarif(falco_alerts)

        with open(output_file, 'w') as f:
            json.dump(sarif, f, indent=2)

        print(f"Successfully converted {len(falco_alerts)} alerts to SARIF format in {output_file}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
