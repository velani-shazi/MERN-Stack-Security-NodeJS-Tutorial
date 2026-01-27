// VULNERABLE APPLICATION - DO NOT USE IN PRODUCTION
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

// VULNERABILITY: Wide-open CORS
app.use(cors());

// VULNERABILITY: No request size limit
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// VULNERABILITY: Exposed server information
// x-powered-by header not disabled

// MongoDB Connection - VULNERABILITY: Hardcoded credentials
mongoose.connect('mongodb://admin:password123@localhost:27017/vulndb', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Schema - VULNERABILITY: No validation, no sanitization
const userSchema = new mongoose.Schema({
  username: String,
  password: String, // VULNERABILITY: Plaintext password
  email: String,
  role: String,
  balance: Number
});

const User = mongoose.model('User', userSchema);

// Post Schema - VULNERABILITY: No validation
const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: String,
  authorId: mongoose.Schema.Types.ObjectId
});

const Post = mongoose.model('Post', postSchema);

// VULNERABILITY: No rate limiting on authentication routes
app.post('/api/register', async (req, res) => {
  try {
    // VULNERABILITY: Accepts any extra fields
    const user = new User(req.body);
    
    // VULNERABILITY: No input validation
    // VULNERABILITY: Password stored in plaintext
    await user.save();
    
    // VULNERABILITY: Sends back sensitive data
    res.json({ success: true, user });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// VULNERABILITY: SQL/NoSQL Injection possible
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // VULNERABILITY: Direct query injection possible
    // VULNERABILITY: No input sanitization
    const user = await User.findOne({ 
      username: username,
      password: password // Plaintext comparison
    });
    
    if (user) {
      // VULNERABILITY: No JWT, no session management
      // VULNERABILITY: Sends full user object including password
      res.json({ 
        success: true, 
        user: user,
        // VULNERABILITY: Predictable session token
        token: Buffer.from(user._id.toString()).toString('base64')
      });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    // VULNERABILITY: Exposes internal error details
    res.json({ success: false, error: error.toString() });
  }
});

// VULNERABILITY: No authentication check
// VULNERABILITY: No authorization check
app.get('/api/users', async (req, res) => {
  try {
    // VULNERABILITY: Returns all users with passwords
    const users = await User.find({});
    res.json(users);
  } catch (error) {
    res.json({ error: error.message });
  }
});

// VULNERABILITY: NoSQL injection in query parameters
app.get('/api/users/:id', async (req, res) => {
  try {
    // VULNERABILITY: No input validation
    const user = await User.findOne({ _id: req.params.id });
    res.json(user);
  } catch (error) {
    res.json({ error: error.message });
  }
});

// VULNERABILITY: No ownership verification
app.put('/api/users/:id', async (req, res) => {
  try {
    // VULNERABILITY: Any user can update any user
    // VULNERABILITY: Can modify role, balance, etc.
    const user = await User.findByIdAndUpdate(
      req.params.id,
      req.body, // VULNERABILITY: Direct body injection
      { new: true }
    );
    res.json(user);
  } catch (error) {
    res.json({ error: error.message });
  }
});

// VULNERABILITY: No authentication
// VULNERABILITY: Accepts any input
app.post('/api/posts', async (req, res) => {
  try {
    // VULNERABILITY: No validation
    const post = new Post(req.body);
    await post.save();
    res.json(post);
  } catch (error) {
    res.json({ error: error.message });
  }
});

// VULNERABILITY: NoSQL injection via query
app.get('/api/posts/search', async (req, res) => {
  try {
    // VULNERABILITY: Direct query injection
    const posts = await Post.find(req.query);
    res.json(posts);
  } catch (error) {
    res.json({ error: error.message });
  }
});

// VULNERABILITY: No ownership check for deletion
app.delete('/api/posts/:id', async (req, res) => {
  try {
    // VULNERABILITY: Anyone can delete any post
    await Post.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.json({ error: error.message });
  }
});

// VULNERABILITY: Eval usage - Remote Code Execution
app.post('/api/calculate', (req, res) => {
  try {
    const { expression } = req.body;
    // VULNERABILITY: CRITICAL - eval() allows arbitrary code execution
    const result = eval(expression);
    res.json({ result });
  } catch (error) {
    res.json({ error: error.message });
  }
});

// VULNERABILITY: Admin route with no protection
app.get('/api/admin/stats', async (req, res) => {
  try {
    // VULNERABILITY: No role check
    const userCount = await User.countDocuments();
    const totalBalance = await User.aggregate([
      { $group: { _id: null, total: { $sum: '$balance' } } }
    ]);
    res.json({ userCount, totalBalance });
  } catch (error) {
    res.json({ error: error.message });
  }
});

// VULNERABILITY: No proper status codes
// VULNERABILITY: Always returns 200 even for errors

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Vulnerable server running on port ${PORT}`);
});

module.exports = app;