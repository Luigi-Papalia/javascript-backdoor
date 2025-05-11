# Vulnerable Node.js Microservice

This repository contains a deliberately insecure Node.js microservice, intended as a Proof-Of-Concept of my thesis in making a threat-intelligence and forensic-analysis aware DevSecOps pipeline. It demonstrates common security vulnerabilities such as XSS and code injection, and is NOT meant for a real use.

---

## Table of Contents

- Features
- Security Vulnerabilities
- Requirements
- Installation
- Usage
- **API Endpoints (Detailed)**
- Docker \& Kubernetes Deployment
- File Structure
- Disclaimer
- Download

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

---

**Author:** Luigi Papalia
**Thesis Supervisor:** Andrea Atzeni

---
