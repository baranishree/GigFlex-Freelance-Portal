require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const connectDB = require('./db');
const { User, Job } = require('./models');
const { protectRoute, authorizeRoles } = require('./middleware');

const app = express();

// Standard configurations for security and web data handling
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));

// Establish our connection to MongoDB
connectDB();

/* ================= ACCOUNT ACCOUNT PATHWAYS ================= */

// 1. Account Signup Endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ error: 'Email already registered.' });

    const user = new User({ name, email, password, role });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Secure Login Endpoint (Stores security token directly inside HTTP-Only browser cookie)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid Credentials.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid Credentials.' });

    // Generate Token containing user metadata
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Lock token inside browser security layer so frontend JavaScript hackers can't read it
    res.cookie('token', token, {
      httpOnly: true,
      secure: false, // Switch to true if deploying with real SSL HTTPS web host
      maxAge: 3600000 // Lasts exactly 1 hour
    }).json({ message: 'Login successful', role: user.role, name: user.name });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Clear Account Session Endpoint
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token').json({ message: 'Logged out successfully.' });
});

/* ================= OPERATION BUSINESS PATHWAYS ================= */

// 4. Create New Gig Posting (Strictly restricted to 'client' role accounts)
app.post('/api/jobs', protectRoute, authorizeRoles('client'), async (req, res) => {
  try {
    const { title, description, budget, category } = req.body;
    const job = new Job({
      title,
      description,
      budget,
      category,
      postedBy: req.user.id
    });
    await job.save();
    res.status(201).json(job);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Intelligent Query Engine (Allows Freelancers to dynamic filter open gigs)
app.get('/api/jobs', protectRoute, async (req, res) => {
  try {
    const { category, minBudget } = req.query;
    let queryFilter = {};

    if (category) queryFilter.category = category;
    if (minBudget) queryFilter.budget = { $gte: Number(minBudget) };

    // Fetch listings matching user selection, cross reference poster details, sort by newest
    const jobs = await Job.find(queryFilter)
      .populate('postedBy', 'name email')
      .sort({ createdAt: -1 });

    res.json(jobs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`GigFlex Server online on port ${PORT}`));
