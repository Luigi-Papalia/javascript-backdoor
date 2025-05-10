const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const app = express();
const port = 3000;
const path = require('path');

const c2ioc = "www.minergate.com"; // Just for PoC, real IoC used in SolarWinds SUNBURST backdoor

// support for encoded URLs and static files
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Set up middleware
app.use(bodyParser.urlencoded({ extended: false }));

// Create or connect to SQLite DB
const db = new sqlite3.Database(':memory:'); // In-memory DB for testing

// Create users table and insert a test user
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER, username TEXT, password TEXT, role TEXT)");
  db.run("INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)", [1, "root", "pass123", "admin"]);
  db.run("INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)", [2, "Luigi", "pass456", "user"]);
});

app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send('User-agent: *\nDisallow:');
});

// Serve the HTML page for the instructions
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Login form
app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form method="POST" action="/login">
      <label>Username: <input type="text" name="username"></label><br>
      <label>Password: <input type="password" name="password"></label><br>
      <button type="submit">Login</button>
    </form>
  `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const query = "SELECT * FROM users WHERE username = ? AND password = ?";
  
  db.get(query, [username, password], (err, row) => {
    if (err) {
      res.status(500).send("Internal server error");
    } else if (row) {
      res.redirect(`/greet?name=${encodeURIComponent(username)}&role=${encodeURIComponent(row.role)}`);
    } else {
      res.send("<p>Login failed. Invalid credentials.</p>");
    }
  });
});

// Vulnerable endpoint: it accepts a parameter and injects it in an HTML response, without prior sanitization
app.get('/greet', (req, res) => {
    // gets a parameter called "name" from the URL. If not provided, it falls back to Guest
    const name = req.query.name || 'Guest';
    const role = req.query.role;
    const responseHtml = 
    `<html>
      <body>
        <h1>Welcome, ${name}! You are ${role}</h1>
        <p>This page is vulnerable to Cross-Site Scripting (XSS).</p>
      </body>
    </html>`;
    res.send(responseHtml);
});

// Vulnerable endpoint: code injection is provided by the bad function eval
app.get('/calculate', (req, res) => {
    const expression = req.query.expr;
    if (!expression) {
        return res.send("Please provide an expression, e.g.: /calculate?expr=2%2B2");
    }
    try {
        let result = eval(expression);
        const responseHtml = 
        `<html>
          <body>
            <h1>Welcome! The result of your expression is: ${result}!</h1>
            <p>This page is vulnerable, but not limited to, Code Injection.</p>
          </body>
        </html>`;
        res.send(responseHtml);
    } catch (error) {
        res.send(`Error in evaluating expression: ${error.message}`);
    }
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Bad microservice running on port ${port}`);
});
