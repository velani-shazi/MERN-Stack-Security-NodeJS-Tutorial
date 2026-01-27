# 🔐 MERN Stack Security Tutorial: From Vulnerable to Secure

## Table of Contents
1. [Introduction](#introduction)
2. [Setting Up](#setting-up)
3. [Vulnerability Analysis](#vulnerability-analysis)
4. [Step-by-Step Fixes](#step-by-step-fixes)
5. [Testing Security](#testing-security)
6. [Production Checklist](#production-checklist)

---

## Introduction

This tutorial demonstrates common security vulnerabilities in MERN stack applications and how to fix them. We'll transform a vulnerable application into a production-ready secure one.

### Prerequisites
- Node.js (v16+)
- MongoDB
- Basic understanding of Express and Mongoose

---

## Setting Up

### Install Dependencies for Secure Application

```bash
cd secure-app
npm install
```

### Required Packages
```json
{
  "express": "^4.18.2",           // Web framework
  "mongoose": "^7.6.3",           // MongoDB ODM
  "helmet": "^7.0.0",             // Security headers
  "express-mongo-sanitize": "^2.2.0", // NoSQL injection prevention
  "express-rate-limit": "^7.1.1", // Rate limiting
  "bcrypt": "^5.1.1",             // Password hashing
  "jsonwebtoken": "^9.0.2",       // JWT tokens
  "express-validator": "^7.0.1",  // Input validation
  "dotenv": "^16.3.1",            // Environment variables
  "cors": "^2.8.5"                // CORS handling
}
```

---

## Vulnerability Analysis

### Critical Vulnerabilities in the Insecure App

| Vulnerability | Risk Level | Impact |
|--------------|------------|---------|
| Plaintext passwords | 🔴 Critical | Account takeover |
| No authentication | 🔴 Critical | Unauthorized access |
| NoSQL injection | 🔴 Critical | Database compromise |
| eval() usage | 🔴 Critical | Remote code execution |
| Wide-open CORS | 🟡 High | CSRF attacks |
| No rate limiting | 🟡 High | Brute force attacks |
| No input validation | 🟡 High | Data corruption |
| Exposed credentials | 🔴 Critical | Full system compromise |

---

## Step-by-Step Fixes

### 1. 🔒 Password Security: Hash Passwords with bcrypt

#### ❌ Vulnerable Code
```javascript
// Storing plaintext password
const user = new User({
  username: req.body.username,
  password: req.body.password  // DANGER: Plaintext!
});
await user.save();
```

#### ✅ Secure Code
```javascript
const bcrypt = require('bcrypt');

// Hash password before saving
const saltRounds = 12;
const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

const user = new User({
  username: req.body.username,
  password: hashedPassword  // ✅ Hashed!
});
await user.save();
```

#### 📝 Implementation Steps

**Step 1:** Install bcrypt
```bash
npm install bcrypt
```

**Step 2:** Update User Schema to hide password by default
```javascript
const userSchema = new mongoose.Schema({
  password: {
    type: String,
    required: true,
    select: false  // ✅ Don't return password in queries
  }
});
```

**Step 3:** Hash password on registration
```javascript
const hashedPassword = await bcrypt.hash(password, 12);
```

**Step 4:** Compare passwords on login
```javascript
// Explicitly select password for comparison
const user = await User.findOne({ username }).select('+password');
const isValid = await bcrypt.compare(password, user.password);
```

#### 🎯 Why This Works
- bcrypt uses adaptive hashing (slower = more secure against brute force)
- Salt rounds of 12 provide strong protection
- Even if database is compromised, passwords remain secure

---

### 2. 🎫 Authentication: Implement JWT Tokens

#### ❌ Vulnerable Code
```javascript
// No real authentication
app.get('/api/users', async (req, res) => {
  const users = await User.find({}); // Anyone can access!
  res.json(users);
});
```

#### ✅ Secure Code
```javascript
const jwt = require('jsonwebtoken');

// Generate JWT on login
const token = jwt.sign(
  { userId: user._id, role: user.role },
  process.env.JWT_SECRET,
  { expiresIn: '7d' }
);

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.userId);
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Protected route
app.get('/api/users', authenticate, async (req, res) => {
  // Only authenticated users can access
});
```

#### 📝 Implementation Steps

**Step 1:** Install JWT
```bash
npm install jsonwebtoken
```

**Step 2:** Create JWT secret in .env
```bash
JWT_SECRET=your-super-secret-key-min-32-chars
JWT_EXPIRE=7d
```

**Step 3:** Create authentication middleware
```javascript
// middleware/authenticate.js
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Auth required' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.userId);
    if (!req.user) {
      return res.status(401).json({ message: 'User not found' });
    }
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};
```

**Step 4:** Apply to routes
```javascript
app.get('/api/protected', authenticate, (req, res) => {
  res.json({ user: req.user });
});
```

#### 🎯 Best Practices
- Use HTTP-only cookies for web apps
- Set token expiration (not too long, not too short)
- Implement token refresh mechanism for better UX
- Store tokens securely on client side

---

### 3. 🛡️ Authorization: Role-Based Access Control

#### ❌ Vulnerable Code
```javascript
// Anyone can access admin routes
app.get('/api/admin/stats', async (req, res) => {
  const stats = await getAdminStats();
  res.json(stats);
});

// Anyone can modify any user
app.put('/api/users/:id', async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, req.body);
});
```

#### ✅ Secure Code
```javascript
// Admin authorization middleware
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      message: 'Access denied. Admin privileges required.' 
    });
  }
  next();
};

// Protected admin route
app.get('/api/admin/stats', 
  authenticate, 
  authorizeAdmin, 
  async (req, res) => {
    const stats = await getAdminStats();
    res.json(stats);
  }
);

// Ownership check
app.put('/api/users/:id', authenticate, async (req, res) => {
  // Users can only update their own profile
  if (req.params.id !== req.user._id.toString()) {
    return res.status(403).json({ message: 'Access denied' });
  }
  
  // Update user...
});
```

#### 📝 Implementation Steps

**Step 1:** Add role to user schema
```javascript
const userSchema = new mongoose.Schema({
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  }
});
```

**Step 2:** Create authorization middleware
```javascript
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};
```

**Step 3:** Implement ownership checks
```javascript
const checkOwnership = (req, res, next) => {
  const resourceOwnerId = req.resource.userId.toString();
  const currentUserId = req.user._id.toString();
  const isAdmin = req.user.role === 'admin';
  
  if (resourceOwnerId !== currentUserId && !isAdmin) {
    return res.status(403).json({ message: 'Access denied' });
  }
  next();
};
```

#### 🎯 Authorization Patterns
- **Resource ownership:** User can only modify their own resources
- **Role-based:** Different permissions for user/admin/moderator
- **Permission-based:** Granular permissions (read, write, delete)
- **Hierarchical:** Manager can access subordinate data

---

### 4. ✅ Input Validation & Sanitization

#### ❌ Vulnerable Code
```javascript
// No validation - accepts anything!
app.post('/api/register', async (req, res) => {
  const user = new User(req.body); // DANGER: All fields accepted
  await user.save();
});
```

#### ✅ Secure Code
```javascript
const { body, validationResult } = require('express-validator');

app.post('/api/register',
  [
    body('username')
      .trim()
      .isLength({ min: 3, max: 30 })
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Invalid username'),
    body('email')
      .isEmail()
      .normalizeEmail(),
    body('password')
      .isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage('Password must contain uppercase, lowercase, and number')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    // Only accept specific fields
    const { username, email, password } = req.body;
    const user = new User({ username, email, password });
    await user.save();
  }
);
```

#### 📝 Implementation Steps

**Step 1:** Install express-validator
```bash
npm install express-validator
```

**Step 2:** Create validation middleware
```javascript
const { body, param, query, validationResult } = require('express-validator');

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false, 
      errors: errors.array() 
    });
  }
  next();
};
```

**Step 3:** Define validation rules
```javascript
const userValidation = {
  register: [
    body('username')
      .trim()
      .isLength({ min: 3, max: 30 })
      .matches(/^[a-zA-Z0-9_]+$/),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 })
  ],
  update: [
    body('username').optional().trim().isLength({ min: 3, max: 30 }),
    body('email').optional().isEmail(),
    body('role').not().exists() // Prevent role modification
  ]
};
```

**Step 4:** Apply validations to routes
```javascript
app.post('/api/register', 
  userValidation.register, 
  handleValidationErrors, 
  registerHandler
);
```

#### 🎯 Validation Best Practices
- ✅ Whitelist allowed fields (don't blacklist)
- ✅ Validate data types, formats, and ranges
- ✅ Sanitize inputs (trim, normalize)
- ✅ Reject unexpected fields
- ✅ Use schema validation in Mongoose too

---

### 5. 🚫 NoSQL Injection Prevention

#### ❌ Vulnerable Code
```javascript
// Direct query injection possible
app.get('/api/users/search', async (req, res) => {
  const users = await User.find(req.query); // DANGER!
});

// Login vulnerable to NoSQL injection
const user = await User.findOne({
  username: req.body.username,
  password: req.body.password
});
```

**Attack example:**
```javascript
// Attacker sends:
POST /api/login
{
  "username": {"$ne": null},
  "password": {"$ne": null}
}
// This matches ANY user!
```

#### ✅ Secure Code
```javascript
const mongoSanitize = require('express-mongo-sanitize');

// Sanitize all inputs
app.use(mongoSanitize());

// Build safe queries
app.get('/api/users/search', async (req, res) => {
  const searchQuery = {};
  
  // Only accept specific fields with proper types
  if (req.query.username) {
    searchQuery.username = req.query.username.toString();
  }
  
  const users = await User.find(searchQuery);
});
```

#### 📝 Implementation Steps

**Step 1:** Install mongo-sanitize
```bash
npm install express-mongo-sanitize
```

**Step 2:** Apply globally
```javascript
const mongoSanitize = require('express-mongo-sanitize');

app.use(mongoSanitize({
  replaceWith: '_',  // Replace $ and . with _
  onSanitize: ({ req, key }) => {
    console.warn(`Sanitized key: ${key}`);
  }
}));
```

**Step 3:** Build safe queries explicitly
```javascript
// SAFE: Explicitly construct query
const searchQuery = {};
if (req.query.username && typeof req.query.username === 'string') {
  searchQuery.username = req.query.username;
}

// UNSAFE: Direct assignment
const unsafeQuery = req.query; // Could contain operators
```

**Step 4:** Use Mongoose schema validation
```javascript
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    match: /^[a-zA-Z0-9_]+$/  // Only alphanumeric
  }
});
```

#### 🎯 Prevention Techniques
- ✅ Sanitize all user inputs
- ✅ Never pass raw query objects to MongoDB
- ✅ Use parameterized queries
- ✅ Validate data types explicitly
- ✅ Use Mongoose schema validation

---

### 6. 🚦 Rate Limiting

#### ❌ Vulnerable Code
```javascript
// No rate limiting - open to brute force
app.post('/api/login', async (req, res) => {
  // Attacker can try millions of passwords
});
```

#### ✅ Secure Code
```javascript
const rateLimit = require('express-rate-limit');

// Strict rate limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

// General API rate limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests'
});

app.use('/api/', apiLimiter);
app.post('/api/login', authLimiter, loginHandler);
app.post('/api/register', authLimiter, registerHandler);
```

#### 📝 Implementation Steps

**Step 1:** Install rate-limit
```bash
npm install express-rate-limit
```

**Step 2:** Configure different limiters
```javascript
const rateLimit = require('express-rate-limit');

// Authentication limiter (strict)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true, // Don't count successful logins
  message: 'Too many attempts'
});

// API limiter (moderate)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

// Upload limiter (very strict)
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10
});
```

**Step 3:** Apply to routes
```javascript
app.post('/api/login', authLimiter, loginHandler);
app.post('/api/register', authLimiter, registerHandler);
app.use('/api/', apiLimiter);
app.post('/api/upload', uploadLimiter, uploadHandler);
```

#### 🎯 Rate Limiting Strategy
- **Authentication:** 5 attempts per 15 minutes
- **API calls:** 100 requests per 15 minutes
- **File uploads:** 10 per hour
- **Password reset:** 3 per hour
- Use Redis for distributed rate limiting in production

---

### 7. 🛡️ Security Headers with Helmet

#### ❌ Vulnerable Code
```javascript
// No security headers
const app = express();
// Missing protection against common attacks
```

#### ✅ Secure Code
```javascript
const helmet = require('helmet');

app.use(helmet());

// Disable x-powered-by header
app.disable('x-powered-by');
```

#### 📝 Implementation Steps

**Step 1:** Install helmet
```bash
npm install helmet
```

**Step 2:** Apply helmet middleware
```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
```

**Step 3:** Disable revealing headers
```javascript
app.disable('x-powered-by');
```

#### 🎯 Headers Added by Helmet
- **X-Content-Type-Options:** Prevents MIME sniffing
- **X-Frame-Options:** Prevents clickjacking
- **X-XSS-Protection:** Enables XSS filter
- **Strict-Transport-Security:** Forces HTTPS
- **Content-Security-Policy:** Prevents XSS and injection

---

### 8. 🌐 CORS Configuration

#### ❌ Vulnerable Code
```javascript
// Open to all origins
app.use(cors());
```

#### ✅ Secure Code
```javascript
const cors = require('cors');

const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || [
    'http://localhost:3000',
    'https://yourdomain.com'
  ],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
```

#### 📝 Implementation Steps

**Step 1:** Configure CORS properly
```javascript
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
};
```

**Step 2:** Set in .env
```bash
ALLOWED_ORIGINS=http://localhost:3000,https://app.yourdomain.com
```

#### 🎯 CORS Best Practices
- ✅ Whitelist specific origins
- ✅ Enable credentials for cookie-based auth
- ✅ Restrict methods and headers
- ❌ Never use `origin: '*'` in production

---

### 9. 📊 Mongoose Schema Validation

#### ❌ Vulnerable Code
```javascript
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  balance: Number
});
```

#### ✅ Secure Code
```javascript
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username too short'],
    maxlength: [30, 'Username too long'],
    match: [/^[a-zA-Z0-9_]+$/, 'Invalid username format']
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Invalid email']
  },
  balance: {
    type: Number,
    default: 0,
    min: [0, 'Balance cannot be negative'],
    validate: {
      validator: Number.isInteger,
      message: 'Balance must be an integer'
    }
  }
});

// Create indexes
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
```

#### 📝 Implementation Steps

**Step 1:** Add comprehensive validation
```javascript
const userSchema = new mongoose.Schema({
  field: {
    type: String,
    required: [true, 'Error message'],
    unique: true,
    trim: true,
    lowercase: true,
    minlength: [3, 'Too short'],
    maxlength: [50, 'Too long'],
    match: [/regex/, 'Invalid format'],
    enum: {
      values: ['option1', 'option2'],
      message: 'Invalid value'
    },
    default: 'defaultValue'
  }
});
```

**Step 2:** Add custom validators
```javascript
balance: {
  type: Number,
  validate: {
    validator: function(v) {
      return v >= 0 && Number.isInteger(v);
    },
    message: 'Invalid balance'
  }
}
```

**Step 3:** Create indexes
```javascript
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ createdAt: -1 });
```

#### 🎯 Schema Validation Benefits
- ✅ Data integrity at database level
- ✅ Consistent validation across app
- ✅ Better error messages
- ✅ Prevents invalid data insertion

---

### 10. 🚫 Prevent eval() and Code Injection

#### ❌ Vulnerable Code
```javascript
// CRITICAL VULNERABILITY - Remote Code Execution
app.post('/api/calculate', (req, res) => {
  const result = eval(req.body.expression); // NEVER DO THIS!
  res.json({ result });
});

// Attack example:
// { "expression": "require('child_process').exec('rm -rf /')" }
```

#### ✅ Secure Code
```javascript
// Option 1: Use safe-eval or math.js
const math = require('mathjs');

app.post('/api/calculate', (req, res) => {
  try {
    const { expression } = req.body;
    
    // Validate expression format
    if (!/^[\d\s\+\-\*\/\(\)\.]+$/.test(expression)) {
      return res.status(400).json({ error: 'Invalid expression' });
    }
    
    // Use safe math parser
    const result = math.evaluate(expression);
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: 'Calculation error' });
  }
});

// Option 2: Use Function constructor with strict validation
app.post('/api/calculate-v2', (req, res) => {
  const { expression } = req.body;
  
  // Very strict validation
  if (!/^[\d\s\+\-\*\/\(\)\.]+$/.test(expression)) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
  
  try {
    const result = Function('"use strict"; return (' + expression + ')')();
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: 'Invalid calculation' });
  }
});
```

#### 📝 Implementation Steps

**Step 1:** Remove all eval() usage
```bash
# Search your codebase
grep -r "eval(" .
```

**Step 2:** Install safe alternatives
```bash
npm install mathjs
# or
npm install safe-eval
```

**Step 3:** Replace eval() with safe alternatives
```javascript
// NEVER: eval(userInput)
// USE: mathjs or validated Function constructor
const result = math.evaluate(expression);
```

#### 🎯 Code Injection Prevention
- ❌ **NEVER** use eval()
- ❌ Avoid Function constructor with user input
- ❌ Don't use child_process.exec with user input
- ✅ Use safe-eval or mathjs
- ✅ Validate and sanitize all inputs
- ✅ Run with least privilege

---

### 11. 🔐 Environment Variables & Secrets Management

#### ❌ Vulnerable Code
```javascript
// Hardcoded secrets in code
const JWT_SECRET = 'mysecret123';
const MONGO_URI = 'mongodb://admin:password@localhost:27017';
```

#### ✅ Secure Code
```javascript
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;

// Validate required env vars
if (!JWT_SECRET || !MONGO_URI) {
  console.error('Missing required environment variables');
  process.exit(1);
}
```

#### 📝 Implementation Steps

**Step 1:** Install dotenv
```bash
npm install dotenv
```

**Step 2:** Create .env file
```bash
# .env (NEVER COMMIT THIS)
JWT_SECRET=your-super-secret-key-min-32-characters-long
MONGO_URI=mongodb://localhost:27017/securedb
ALLOWED_ORIGINS=http://localhost:3000
NODE_ENV=development
```

**Step 3:** Create .env.example
```bash
# .env.example (COMMIT THIS)
JWT_SECRET=
MONGO_URI=
ALLOWED_ORIGINS=
NODE_ENV=
```

**Step 4:** Add .env to .gitignore
```bash
# .gitignore
.env
.env.local
.env.production
node_modules/
```

**Step 5:** Load and validate
```javascript
require('dotenv').config();

// Validate required variables
const requiredEnvVars = ['JWT_SECRET', 'MONGO_URI'];
const missing = requiredEnvVars.filter(v => !process.env[v]);

if (missing.length > 0) {
  console.error(`Missing env vars: ${missing.join(', ')}`);
  process.exit(1);
}
```

#### 🎯 Secrets Management
- ✅ Use .env for development
- ✅ Use secret managers in production (AWS Secrets Manager, HashiCorp Vault)
- ✅ Rotate secrets regularly
- ✅ Never commit secrets to git
- ✅ Use different secrets per environment

---

### 12. 🍪 HTTP-Only Cookies for Tokens

#### ❌ Vulnerable Code
```javascript
// Sending token in response body only
res.json({ 
  token: jwt.sign({ userId }, JWT_SECRET) 
});
```

#### ✅ Secure Code
```javascript
// Send token in HTTP-only cookie
const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });

res.cookie('token', token, {
  httpOnly: true,              // Prevents XSS access
  secure: process.env.NODE_ENV === 'production', // HTTPS only
  sameSite: 'strict',          // CSRF protection
  maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
});

res.json({ success: true, user });
```

#### 📝 Implementation Steps

**Step 1:** Install cookie-parser
```bash
npm install cookie-parser
```

**Step 2:** Configure cookie-parser
```javascript
const cookieParser = require('cookie-parser');
app.use(cookieParser());
```

**Step 3:** Set secure cookies
```javascript
app.post('/api/login', async (req, res) => {
  // ... authenticate user ...
  
  const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
  
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  
  res.json({ success: true });
});
```

**Step 4:** Read from cookies
```javascript
const authenticate = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  // ... verify token ...
};
```

#### 🎯 Cookie Security
- ✅ **httpOnly:** Prevents JavaScript access (XSS protection)
- ✅ **secure:** HTTPS only
- ✅ **sameSite:** CSRF protection
- ✅ Set appropriate **maxAge**
- ✅ Clear on logout

---

### 13. 🚪 Token Invalidation on Logout

#### ❌ Vulnerable Code
```javascript
// Client-side logout only
app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logged out' });
  // Token still valid on server!
});
```

#### ✅ Secure Code
```javascript
// Token blacklist (use Redis in production)
const tokenBlacklist = new Set();

app.post('/api/logout', authenticate, (req, res) => {
  // Add token to blacklist
  tokenBlacklist.add(req.token);
  
  // Clear cookie
  res.clearCookie('token');
  
  res.json({ success: true, message: 'Logged out' });
});

// Check blacklist in auth middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ message: 'Token invalidated' });
  }
  
  // ... verify token ...
};
```

#### 📝 Implementation Steps

**Step 1:** Create token blacklist (Redis in production)
```javascript
// Development: In-memory
const tokenBlacklist = new Set();

// Production: Redis
const redis = require('redis');
const client = redis.createClient();
```

**Step 2:** Add logout endpoint
```javascript
app.post('/api/logout', authenticate, async (req, res) => {
  try {
    // Add to blacklist
    await redis.setex(
      `blacklist:${req.token}`,
      7 * 24 * 60 * 60, // Expire after 7 days
      'true'
    );
    
    res.clearCookie('token');
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Logout failed' });
  }
});
```

**Step 3:** Check blacklist in auth middleware
```javascript
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  // Check if blacklisted
  const isBlacklisted = await redis.get(`blacklist:${token}`);
  if (isBlacklisted) {
    return res.status(401).json({ message: 'Token revoked' });
  }
  
  // ... continue ...
};
```

#### 🎯 Token Management
- ✅ Implement token blacklist
- ✅ Use Redis for distributed systems
- ✅ Set TTL equal to token expiry
- ✅ Clear client-side storage
- ✅ Consider refresh tokens for better UX

---

### 14. 📏 Request Size Limiting

#### ❌ Vulnerable Code
```javascript
// No size limit - vulnerable to DOS
app.use(express.json());
```

#### ✅ Secure Code
```javascript
// Limit request body size
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// For file uploads, use multer with limits
const multer = require('multer');
const upload = multer({
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 5
  }
});
```

#### 📝 Implementation Steps

**Step 1:** Set body parser limits
```javascript
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '10kb' 
}));
```

**Step 2:** Configure multer for uploads
```javascript
const multer = require('multer');

const upload = multer({
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB per file
    files: 5,                   // Max 5 files
    fields: 10                  // Max 10 fields
  },
  fileFilter: (req, file, cb) => {
    // Only allow specific file types
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only images allowed'), false);
    }
  }
});

app.post('/api/upload', 
  upload.single('image'), 
  uploadHandler
);
```

#### 🎯 Size Limits
- **JSON body:** 10kb (adjust based on needs)
- **File uploads:** 5-10MB per file
- **Total request:** 50MB
- Always set appropriate limits

---

### 15. ✅ Proper HTTP Status Codes

#### ❌ Vulnerable Code
```javascript
// Always returns 200, even for errors
app.post('/api/login', async (req, res) => {
  if (!user) {
    res.json({ error: 'User not found' }); // Wrong status!
  }
  res.json({ user });
});
```

#### ✅ Secure Code
```javascript
app.post('/api/login', async (req, res) => {
  try {
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials' 
      });
    }
    
    res.status(200).json({ success: true, user });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      message: 'Internal server error' 
    });
  }
});
```

#### 📝 Common Status Codes

| Code | Meaning | When to Use |
|------|---------|-------------|
| 200 | OK | Successful GET, PUT, PATCH |
| 201 | Created | Successful POST (resource created) |
| 204 | No Content | Successful DELETE |
| 400 | Bad Request | Invalid input/validation error |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Valid auth but insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Resource already exists |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Unexpected server error |

#### 🎯 Status Code Best Practices
- ✅ Always set appropriate status codes
- ✅ Use consistent response format
- ✅ Include success flag in JSON
- ✅ Provide helpful error messages
- ❌ Don't expose internal error details

---

## Testing Security

### Security Testing Checklist

#### 1. Authentication Testing

```bash
# Test without token
curl -X GET http://localhost:5000/api/users \
  -H "Content-Type: application/json"
# Expected: 401 Unauthorized

# Test with invalid token
curl -X GET http://localhost:5000/api/users \
  -H "Authorization: Bearer invalid-token"
# Expected: 401 Unauthorized

# Test with expired token
# Expected: 401 Unauthorized
```

#### 2. Authorization Testing

```bash
# Try to access admin endpoint as regular user
curl -X GET http://localhost:5000/api/admin/stats \
  -H "Authorization: Bearer $USER_TOKEN"
# Expected: 403 Forbidden

# Try to modify another user's data
curl -X PUT http://localhost:5000/api/users/OTHER_USER_ID \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"username": "hacked"}'
# Expected: 403 Forbidden
```

#### 3. Input Validation Testing

```bash
# Test with invalid email
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "email": "invalid", "password": "pass"}'
# Expected: 400 Bad Request with validation errors

# Test with extra fields
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "email": "test@test.com", "password": "Password123", "role": "admin"}'
# Expected: 400 Bad Request or role should be ignored
```

#### 4. NoSQL Injection Testing

```bash
# Try NoSQL injection in login
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'
# Expected: 400 Bad Request or login failure

# Try NoSQL injection in query
curl -X GET 'http://localhost:5000/api/users/search?username[$ne]=test'
# Expected: Sanitized or rejected
```

#### 5. Rate Limiting Testing

```bash
# Send multiple rapid requests
for i in {1..10}; do
  curl -X POST http://localhost:5000/api/login \
    -H "Content-Type: application/json" \
    -d '{"username": "test", "password": "wrong"}'
done
# Expected: After 5 attempts, should return 429 Too Many Requests
```

#### 6. CORS Testing

```bash
# Test CORS from unauthorized origin
curl -X POST http://localhost:5000/api/login \
  -H "Origin: http://malicious-site.com" \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "password": "test"}'
# Expected: CORS error or no CORS headers in response
```

### Automated Security Testing Tools

```bash
# Install security testing tools
npm install --save-dev jest supertest

# Run security tests
npm test
```

**Example security test:**

```javascript
// tests/security.test.js
const request = require('supertest');
const app = require('../server');

describe('Security Tests', () => {
  
  test('Should reject requests without authentication', async () => {
    const res = await request(app)
      .get('/api/users')
      .expect(401);
  });
  
  test('Should prevent NoSQL injection', async () => {
    const res = await request(app)
      .post('/api/login')
      .send({ username: { $ne: null }, password: { $ne: null } })
      .expect(400);
  });
  
  test('Should rate limit login attempts', async () => {
    const attempts = Array(6).fill().map(() =>
      request(app)
        .post('/api/login')
        .send({ username: 'test', password: 'wrong' })
    );
    
    const results = await Promise.all(attempts);
    expect(results[5].status).toBe(429);
  });
  
  test('Should prevent privilege escalation', async () => {
    const res = await request(app)
      .post('/api/register')
      .send({ 
        username: 'hacker', 
        email: 'hack@test.com',
        password: 'Password123',
        role: 'admin' 
      });
    
    expect(res.body.user.role).toBe('user');
  });
});
```

---

## Production Checklist

### Before Deploying to Production

#### Environment & Configuration
- [ ] All secrets in environment variables (not in code)
- [ ] .env file not committed to git
- [ ] Strong JWT_SECRET (min 32 random characters)
- [ ] NODE_ENV set to 'production'
- [ ] Database credentials secured
- [ ] CORS configured for production domains only
- [ ] HTTPS/SSL enabled

#### Authentication & Authorization
- [ ] Passwords hashed with bcrypt (saltRounds >= 12)
- [ ] JWT tokens with expiration
- [ ] HTTP-only cookies for web apps
- [ ] Token blacklist on logout
- [ ] Role-based access control implemented
- [ ] Ownership checks for all user resources
- [ ] Admin routes protected

#### Input Validation & Sanitization
- [ ] All inputs validated with express-validator
- [ ] MongoDB inputs sanitized (express-mongo-sanitize)
- [ ] Request body size limited
- [ ] File upload size limited
- [ ] Extra fields rejected
- [ ] No eval() or Function() with user input

#### Security Middleware
- [ ] Helmet configured
- [ ] Rate limiting on all routes
- [ ] Strict rate limiting on auth routes
- [ ] x-powered-by header disabled
- [ ] Proper CORS configuration

#### Database Security
- [ ] Mongoose schema validation enabled
- [ ] Indexes on frequently queried fields
- [ ] NoSQL injection prevention
- [ ] Separate DB user (not admin) for app
- [ ] Database backups configured
- [ ] Connection string not exposed

#### Monitoring & Logging
- [ ] Error logging configured
- [ ] Failed login attempts logged
- [ ] Security events logged
- [ ] Monitoring for unusual activity
- [ ] Log rotation configured

#### Testing
- [ ] Security tests passing
- [ ] Penetration testing completed
- [ ] Dependency audit clean (`npm audit`)
- [ ] No high/critical vulnerabilities

#### Documentation
- [ ] API documentation updated
- [ ] Security guidelines documented
- [ ] Incident response plan prepared

---

## Quick Reference

### Essential Security Packages

```json
{
  "helmet": "Security headers",
  "express-mongo-sanitize": "NoSQL injection prevention",
  "express-rate-limit": "Rate limiting",
  "bcrypt": "Password hashing",
  "jsonwebtoken": "JWT tokens",
  "express-validator": "Input validation",
  "dotenv": "Environment variables",
  "cors": "CORS management"
}
```

### Security Middleware Order

```javascript
// Correct order of middleware
app.use(helmet());                    // 1. Security headers
app.disable('x-powered-by');          // 2. Hide server info
app.use(cors(corsOptions));           // 3. CORS
app.use(express.json({ limit: '10kb' })); // 4. Body parsing with limit
app.use(mongoSanitize());             // 5. Input sanitization
app.use('/api/', apiLimiter);         // 6. Rate limiting
// ... routes ...
app.use(errorHandler);                // Last: Error handling
```

### Common Security Mistakes to Avoid

❌ **DON'T:**
- Store passwords in plaintext
- Use eval() with user input
- Trust client-side validation only
- Expose error stack traces to users
- Use weak JWT secrets
- Allow unlimited request sizes
- Skip authentication checks
- Commit secrets to git
- Use wide-open CORS
- Ignore dependency vulnerabilities

✅ **DO:**
- Hash passwords with bcrypt
- Validate and sanitize all inputs
- Implement proper authorization
- Use security headers (Helmet)
- Set appropriate rate limits
- Keep dependencies updated
- Use HTTPS in production
- Log security events
- Perform regular security audits
- Follow principle of least privilege

---

## Conclusion

Security is not optional—it's essential. This tutorial covered:

1. ✅ Password hashing with bcrypt
2. ✅ JWT authentication
3. ✅ Role-based authorization
4. ✅ Input validation & sanitization
5. ✅ NoSQL injection prevention
6. ✅ Rate limiting
7. ✅ Security headers
8. ✅ CORS configuration
9. ✅ Schema validation
10. ✅ Code injection prevention
11. ✅ Secrets management
12. ✅ HTTP-only cookies
13. ✅ Token invalidation
14. ✅ Request size limiting
15. ✅ Proper status codes

### Next Steps

1. Review your current application
2. Implement these security measures
3. Run security tests
4. Perform dependency audit
5. Get security review
6. Deploy with confidence

### Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

---

**Remember:** Security is an ongoing process, not a one-time task. Keep your dependencies updated, stay informed about new vulnerabilities, and regularly audit your application.

🔐 **Stay Secure!**