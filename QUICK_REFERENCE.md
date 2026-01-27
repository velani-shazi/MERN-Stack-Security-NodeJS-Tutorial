# 🔐 MERN Security Quick Reference Guide

## 🚀 Quick Start Checklist

### 1. Installation
```bash
npm install express mongoose cors helmet express-mongo-sanitize express-rate-limit bcrypt jsonwebtoken express-validator dotenv cookie-parser
```

### 2. Environment Setup
```bash
# Create .env file
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
echo "JWT_SECRET=$JWT_SECRET" > .env
echo "MONGO_URI=mongodb://localhost:27017/yourdb" >> .env
echo "NODE_ENV=development" >> .env
```

### 3. Basic Secure Server Template
```javascript
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');

const app = express();

// Security middleware
app.use(helmet());
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use(mongoSanitize());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// Your routes here...

app.listen(5000, () => console.log('Server running'));
```

---

## 📋 Security Patterns

### ✅ Secure User Schema
```javascript
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: /^[a-zA-Z0-9_]+$/
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    match: /^\S+@\S+\.\S+$/
  },
  password: {
    type: String,
    required: true,
    select: false // Never return by default
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  }
});

userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
```

### ✅ Secure Registration
```javascript
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');

app.post('/api/register',
  [
    body('username').trim().isLength({ min: 3, max: 30 }),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = new User({
      username,
      email,
      password: hashedPassword,
      role: 'user' // Force user role
    });
    
    await user.save();
    
    res.status(201).json({ 
      success: true,
      user: { id: user._id, username: user.username }
    });
  }
);
```

### ✅ Secure Login
```javascript
const jwt = require('jsonwebtoken');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  
  const user = await User.findOne({ username }).select('+password');
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const isValid = await bcrypt.compare(password, user.password);
  
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const token = jwt.sign(
    { userId: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
  
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  
  res.json({ 
    success: true,
    user: { id: user._id, username: user.username, role: user.role },
    token
  });
});
```

### ✅ Authentication Middleware
```javascript
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};
```

### ✅ Authorization Middleware
```javascript
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

const checkOwnership = (resourceOwnerField) => {
  return async (req, res, next) => {
    const resource = await Model.findById(req.params.id);
    
    if (!resource) {
      return res.status(404).json({ error: 'Not found' });
    }
    
    if (resource[resourceOwnerField].toString() !== req.user._id.toString() &&
        req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    req.resource = resource;
    next();
  };
};

// Usage
app.delete('/api/posts/:id', 
  authenticate, 
  checkOwnership('authorId'),
  async (req, res) => {
    await Post.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  }
);
```

### ✅ Input Validation
```javascript
// Validation rules
const userValidation = {
  create: [
    body('username').trim().isLength({ min: 3, max: 30 })
      .matches(/^[a-zA-Z0-9_]+$/),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 })
  ],
  update: [
    body('username').optional().trim().isLength({ min: 3 }),
    body('email').optional().isEmail(),
    body('role').not().exists() // Prevent role modification
  ]
};

// Error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Usage
app.post('/api/users',
  userValidation.create,
  handleValidationErrors,
  createUserHandler
);
```

### ✅ Safe Query Building
```javascript
// BAD - NoSQL injection possible
const users = await User.find(req.query);

// GOOD - Explicit query building
const searchQuery = {};

if (req.query.username && typeof req.query.username === 'string') {
  searchQuery.username = req.query.username;
}

if (req.query.email && typeof req.query.email === 'string') {
  searchQuery.email = req.query.email;
}

const users = await User.find(searchQuery).limit(50);
```

### ✅ Secure Update
```javascript
app.put('/api/users/:id', 
  authenticate,
  [
    param('id').isMongoId(),
    body('role').not().exists(),
    body('balance').not().exists()
  ],
  handleValidationErrors,
  async (req, res) => {
    // Ownership check
    if (req.params.id !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Whitelist allowed fields
    const allowedFields = ['username', 'email'];
    const updates = {};
    
    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true, runValidators: true }
    ).select('-password');
    
    res.json({ success: true, user });
  }
);
```

---

## 🎯 Common Vulnerabilities & Fixes

| Vulnerability | Bad Code | Good Code |
|--------------|----------|-----------|
| **Plaintext Passwords** | `password: req.body.password` | `password: await bcrypt.hash(password, 12)` |
| **No Auth** | `app.get('/api/users', handler)` | `app.get('/api/users', authenticate, handler)` |
| **NoSQL Injection** | `User.find(req.query)` | `User.find(sanitizedQuery)` + `mongoSanitize()` |
| **No Rate Limit** | No limiter | `app.use(rateLimit({...}))` |
| **eval() Usage** | `eval(req.body.code)` | Use `mathjs` or validated input |
| **Wide CORS** | `cors()` | `cors({ origin: ['https://app.com'] })` |
| **Exposed Secrets** | `JWT_SECRET = 'secret'` | `process.env.JWT_SECRET` |
| **No Size Limit** | `express.json()` | `express.json({ limit: '10kb' })` |
| **Mass Assignment** | `User.update(req.body)` | Whitelist fields explicitly |
| **No Ownership** | Update any user | Check `req.user._id === resource.ownerId` |

---

## 🔒 Security Middleware Setup

```javascript
const express = require('express');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();

// 1. Security headers
app.use(helmet());
app.disable('x-powered-by');

// 2. CORS
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(','),
  credentials: true
}));

// 3. Body parsing with size limit
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 4. Sanitize NoSQL injection
app.use(mongoSanitize());

// 5. Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true
});

app.use('/api/', apiLimiter);
app.post('/api/login', authLimiter);
app.post('/api/register', authLimiter);

// Routes...

// Error handler (last)
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});
```

---

## 📊 Status Code Reference

```javascript
// Success
200 - OK (GET, PUT, PATCH)
201 - Created (POST)
204 - No Content (DELETE)

// Client Errors
400 - Bad Request (validation error)
401 - Unauthorized (no/invalid auth)
403 - Forbidden (valid auth, insufficient permissions)
404 - Not Found (resource doesn't exist)
409 - Conflict (resource already exists)
422 - Unprocessable Entity (semantic error)
429 - Too Many Requests (rate limit)

// Server Errors
500 - Internal Server Error
503 - Service Unavailable

// Usage Example
if (!user) {
  return res.status(404).json({ error: 'User not found' });
}

if (req.user.role !== 'admin') {
  return res.status(403).json({ error: 'Admin access required' });
}

res.status(201).json({ success: true, user });
```

---

## 🧪 Security Testing Commands

```bash
# Check for vulnerabilities
npm audit
npm audit fix

# Test authentication
curl -X GET http://localhost:5000/api/users
# Expected: 401

# Test NoSQL injection
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
# Expected: 400 or 401

# Test rate limiting
for i in {1..10}; do
  curl -X POST http://localhost:5000/api/login \
    -d '{"username":"test","password":"wrong"}'
done
# Expected: 429 after 5 attempts

# Test privilege escalation
curl -X POST http://localhost:5000/api/register \
  -d '{"username":"hack","email":"h@h.com","password":"Pass123","role":"admin"}'
# Expected: 400 or role should be 'user'
```

---

## 🎨 Environment Variables Template

```bash
# .env.example
NODE_ENV=development
PORT=5000

# Database
MONGO_URI=mongodb://localhost:27017/yourdb

# JWT
JWT_SECRET=your-secret-key-minimum-32-characters-long
JWT_EXPIRE=7d

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100
```

---

## ⚡ Performance Tips

```javascript
// 1. Use indexes
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });

// 2. Limit query results
const users = await User.find(query).limit(100);

// 3. Select only needed fields
const user = await User.findById(id).select('username email');

// 4. Use lean() for read-only queries
const users = await User.find().lean(); // Returns plain JS objects

// 5. Batch operations
await User.insertMany(usersArray);

// 6. Use Redis for token blacklist (production)
const redis = require('redis');
const client = redis.createClient();
await client.setex(`blacklist:${token}`, 7 * 24 * 60 * 60, 'true');
```

---

## 🔐 Production Checklist

```
Environment & Config
[ ] .env not committed to git
[ ] Strong JWT_SECRET (32+ chars)
[ ] HTTPS enabled
[ ] NODE_ENV=production
[ ] Database credentials secured
[ ] CORS restricted to production domains

Auth & Authorization
[ ] Passwords hashed (bcrypt, saltRounds >= 12)
[ ] JWT expiration set
[ ] Token blacklist on logout
[ ] Role-based access control
[ ] Ownership checks on all resources

Input Validation
[ ] All inputs validated
[ ] MongoDB inputs sanitized
[ ] Request size limited
[ ] File upload size limited
[ ] No eval() or Function() with user input

Security Middleware
[ ] Helmet configured
[ ] Rate limiting active
[ ] x-powered-by disabled
[ ] Proper CORS

Database
[ ] Schema validation enabled
[ ] Indexes created
[ ] NoSQL injection prevention
[ ] Backups configured

Monitoring
[ ] Error logging configured
[ ] Security events logged
[ ] npm audit clean
[ ] No critical vulnerabilities
```

---

## 📚 Useful Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [Node.js Security Checklist](https://blog.risingstack.com/node-js-security-checklist/)

---

## 🆘 Quick Fixes

### "My authentication isn't working"
```javascript
// Check:
1. JWT_SECRET is set in .env
2. Token is being sent in Authorization header
3. Token format: "Bearer <token>"
4. Token isn't expired
5. User exists in database
```

### "Getting CORS errors"
```javascript
// Fix:
const corsOptions = {
  origin: 'http://localhost:3000', // Your frontend URL
  credentials: true
};
app.use(cors(corsOptions));
```

### "Rate limiting not working"
```javascript
// Ensure rate limiter is applied BEFORE routes
app.use('/api/', apiLimiter);
app.post('/api/login', authLimiter, loginHandler); // authLimiter first
```

### "Validation errors not showing"
```javascript
// Add validation error handler
const errors = validationResult(req);
if (!errors.isEmpty()) {
  return res.status(400).json({ errors: errors.array() });
}
```

---

**Print this guide and keep it handy! 🔐**