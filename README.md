# Vulnerable Node.js Microservice

This repository contains a deliberately insecure Node.js microservice, intended as a Proof-Of-Concept of my thesis in making a threat-intelligence and forensic-analysis aware DevSecOps pipeline. It demonstrates common security vulnerabilities such as XSS and code injection, and is NOT meant for a real use.

---

## Features

- Simple Express.js web server
- In-memory SQLite database with test users
- Login form (no session management)
- Vulnerable endpoints for XSS and code injection demonstration
- Dockerfile and Kubernetes deployment YAML included

---

## Security Vulnerabilities

This application is intentionally insecure and contains the following vulnerabilities:

- **Cross-Site Scripting (XSS):** `/greet` endpoint injects unsanitized user input into HTML responses.
- **Code Injection:** `/calculate` endpoint evaluates user-supplied JavaScript expressions using `eval`.
- **Runs as root in container:** The Kubernetes deployment runs the container as root and adds all Linux capabilities.
- **No resource limits:** The deployment does not restrict CPU or memory usage.
- **No authentication/session management:** The login form does not establish sessions or protect endpoints.

---

## Requirements

- Node.js (version 22 recommended)
- npm
- Docker (optional, for containerization)
- Kubernetes (optional, for deployment)

---

## Installation

1. **Clone the repository:**

```bash
git clone <repository-url>
cd <repository-directory>
```

2. **Install dependencies (this will inject the backdoor):**

```bash
npm install
```


---

## Usage

### Run Locally

```bash
node server.js
```

The service will be available at [http://localhost:3000](http://localhost:3000).

### Docker

Build and run the Docker container:

```bash
docker build -t microservizio-js:v1 .
docker run -p 3000:3000 microservizio-js:v1
```


### Kubernetes

Apply the deployment and service:

```bash
kubectl apply -f microservizio-js-deployment.yaml
```

Access the service at `NodeIP:30000`.

---

## API Endpoints

| Endpoint | Method | Description |
| :-- | :-- | :-- |
| `/` | GET | Serves `index.html` with instructions. |
| `/login` | GET | Renders a login form. Accepts `username` and `password` via POST. |
| `/greet` | GET | Greets user by `name` parameter. **Vulnerable to reflected XSS.** |
| `/calculate` | GET | Evaluates the `expr` query parameter as JS. **Vulnerable to code injection.** |
| `/robots.txt` | GET | Returns the robots.txt file, for DAST purposes. |

### `/` (GET)

- **Description:** Returns the main HTML page (`index.html`) with instructions.
- **Usage:**

```
curl http://localhost:3000/
```

- **Response:**
HTML content with usage instructions.

---

### `/login` (GET, POST)

- **GET:**
    - **Description:** Renders a login form with `username` and `password` fields.
    - **Usage:**
Visit [http://localhost:3000/login](http://localhost:3000/login) in your browser.
- **POST:**
    - **Description:** Processes login form submission. Checks credentials against the in-memory SQLite database.
    - **Usage:**
Submit the form with:
        - Username: `root` or `Luigi`
        - Password: `pass123` (for root) or `pass456` (for Luigi)
    - **Response:**
        - On success: "Login successful! Welcome, [username] ([role])"
        - On failure: "Login failed. Invalid credentials."
    - **Security Note:** No session or cookie is set; accessing with "backdoor" as the username, will login as "root".

---

### `/greet` (GET)

- **Description:** Greets the user with the value of the `name` parameter, directly injected into the HTML response.
- **Usage:**

```
curl "http://localhost:3000/greet?name=Alice"
```

Or, to demonstrate XSS:

```
curl "http://localhost:3000/greet?name=<script>alert(1)</script>"
```

- **Response:**

```
<h2>Hello, [name]!</h2>
```

**Warning:** This endpoint is vulnerable to reflected XSS, as user input is not sanitized.

---

### `/calculate` (GET)

- **Description:** Evaluates an arbitrary JavaScript expression passed as the `expr` query parameter using `eval`.
- **Usage:**

```
curl "http://localhost:3000/calculate?expr=2*2"
```

Or, to demonstrate code injection:

```
curl "http://localhost:3000/calculate?expr=process.env"
```

- **Response:**

```
<h2>Result: [result]</h2>
```

**Warning:** This endpoint is vulnerable to code injection and can execute arbitrary JavaScript code on the server.

---

### `/robots.txt` (GET)

- **Description:** Returns the robots.txt file.
- **Usage:**

```
curl http://localhost:3000/robots.txt
```

- **Response:**

```
User-agent: *
Disallow:
```

---

## Docker \& Kubernetes Deployment

- **Dockerfile:**
Uses Node.js 22, installs dependencies, exposes port 3000, and runs `server.js`.
- **Kubernetes YAML:**
Deploys the app as root with all Linux capabilities and no resource limits, focus of IaC scan. Exposes via NodePort 30000.

Description of utility scripts

---

# `generate_sarif.py` - Convert Falco Alerts to SARIF Format

This script converts a list of Falco JSON alerts into a [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) (Static Analysis Results Interchange Format) file, suitable for integration with security and code analysis tools like GitHub Advanced Security.

---

## Requirements

* Python 3.6+
* Input file containing **one JSON-formatted Falco alert per line**

---

## Usage

```bash
python generate_sarif.py <input_file> <output_file>
```

### Example

```bash
python generate_sarif.py falco_alerts.json alerts_output.sarif
```

---

## Input

* `input_file`: A text file where each line is a Falco alert in JSON format.
* Each alert should resemble:

  ```json
  {
    "time": "2025-07-20T10:32:00Z",
    "rule": "Write below etc",
    "priority": "Warning",
    "output": "Write below etc: User root attempted to write to /etc/passwd",
    "output_fields": {
      "fd.name": "/etc/passwd",
      "user.name": "root",
      "user.uid": "0",
      "proc.exepath": "/usr/bin/vim",
      "proc.cmdline": "vim /etc/passwd"
    },
    "tags": ["filesystem", "write"]
  }
  ```

---

## Output

* `output_file`: A [SARIF 2.1.0](https://json.schemastore.org/sarif-2.1.0.json) compliant JSON file.
* Contains:

  * Tool metadata (name: `Falco`)
  * Unique rules derived from Falco `rule`
  * Results with:

    * Message from `output`
    * Rule ID and severity (`priority`)
    * Location (`fd.name`)
    * Metadata like user, uid, process executable, and command line

---

## Output Example

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Falco",
          "rules": [
            {
              "id": "Write below etc",
              "name": "Write below etc",
              "shortDescription": {
                "text": "Write below etc"
              },
              "defaultConfiguration": {
                "level": "warning"
              },
              "properties": {
                "tags": ["filesystem", "write"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "Write below etc",
          "level": "warning",
          "message": {
            "text": "Write below etc: User root attempted to write to /etc/passwd"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "/etc/passwd"
                }
              }
            }
          ],
          "properties": {
            "eventTime": "2025-07-20T10:32:00Z",
            "user": "root",
            "uid": "0",
            "process": {
              "executable": "/usr/bin/vim",
              "commandLine": "vim /etc/passwd"
            }
          }
        }
      ]
    }
  ]
}
```

---

## Error Handling

* Malformed JSON lines will be reported to `stderr`, but the script continues.
* File I/O errors or argument issues will halt the script with a message.

---

# `ioc_matcher.py` - IOC Scanner and MISP Correlator

This script recursively scans files for Indicators of Compromise (IOCs) using [ioc-finder](https://github.com/InQuest/python-iocextract), and checks them against a MISP (Malware Information Sharing Platform) instance via the PyMISP API. Results are printed in human-readable **Markdown format**.

---

## Requirements

### Python Dependencies

You must install the following Python packages:

```bash
pip install pymisp ioc-finder requests
```

* [`pymisp`](https://github.com/MISP/PyMISP)
* [`ioc-finder`](https://github.com/InQuest/python-iocextract)
* `requests`
* `urllib3`

---

## Usage

```bash
python ioc_matcher.py --input-folder <path_to_scan> \
                      --misp-url <https://misp-instance> \
                      --misp-key <your_api_key> \
                      [--max-workers 8] \
                      [--verify-cert true|false]
```

### Example

```bash
python ioc_matcher.py \
  --input-folder ./my_project \
  --misp-url https://misp.local \
  --misp-key ABCDEFGH1234567890 \
  --max-workers 4 \
  --verify-cert false
```

---

## Input

* `--input-folder`: Directory to scan for IOCs (default: current folder).
* Files with the following extensions are considered: `.txt`, `.js`, `.yaml`, `.json`, `.html`, `Dockerfile`.

The script extracts IOCs like:

* IP addresses
* Domains
* URLs
* File hashes

---

## 📤 Output

* Markdown report printed to standard output (`stdout`)
* Includes:

  * File and IOC matched
  * MISP attribute details (value, type, tags, IDS flag)
  * Related MISP event (ID, info, tags, threat level, distribution)

---

### Output Example

```markdown
# IOC Matcher Report
Scanned directory: `./my_project` with `4` threads  

- **Total unique possible IOCs extracted from repository:** 12  

## :warning: Alert: Match found (file: `src/config.json`)

- **IOC Value:** `1.2.3.4`
- **IOC Type:** ip-dst  
- **Category:** Network activity  
- **To IDS:** True  
- **Comment:** Malicious C2 server  
- **Attribute Tags:** `APT`, `malware`

### Event Details
- **Event ID:** 1023
- **Info:** C2 infrastructure for malware XYZ
- **Date:** 2024-09-10
- **Event Tags:** `APT`, `xyz-family`
- **Threat Level:** 2
- **Analysis:** 2
- **Distribution:** 1
- **Organization:** CERT-X
```

---

## Internal Logic

1. **IOC Extraction**

   * Uses `ioc_finder.find_iocs(content)` to extract indicators from readable files.
   * Filters out placeholder IPs like `0.0.0.0`.

2. **MISP Querying**

   * Efficient parallel search using `ThreadPoolExecutor`.
   * All results cached per IOC to minimize redundant lookups.

3. **Markdown Display**

   * Results displayed using `print()` in Markdown format.

---

## Error Handling

* If a file cannot be read (e.g., permission issues), it logs a warning and continues.
* If a MISP query fails, it logs the error and skips the event.
* If the `input-folder` does not exist, the script exits with an error.

---

**Author:** Luigi Papalia
**Thesis Supervisor:** Andrea Atzeni

---
