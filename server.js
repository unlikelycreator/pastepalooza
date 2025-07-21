const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const port = 8084;

// Middleware
app.use(express.json());
app.use(cors({
  origin: 'http://127.0.0.1:5501',
  methods: ['GET', 'POST'],
  credentials: true
}));


// MongoDB Connection
mongoose.connect('mongodb+srv://hpMidas:midas@cluster0.jdd0dfh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const pasteSchema = new mongoose.Schema({
  content: { type: String, required: true },
  password: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Paste = mongoose.model('Paste', pasteSchema);

// JWT Secret
const JWT_SECRET = 'iamhritikpawar'; // Replace with a secure key in production

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Seed test users
const seedUsers = async () => {
  const users = [
    { username: 'hritik.pawar', password: 'password123' },
    { username: 'divyanshu', password: '123456' }
  ];
  for (const user of users) {
    const existingUser = await User.findOne({ username: user.username });
    if (!existingUser) {
      const hashedPassword = await bcrypt.hash(user.password, 10);
      await User.create({ username: user.username, password: hashedPassword });
    }
  }
};
seedUsers();

// Routes
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.post('/api/pastes', authenticateToken, async (req, res) => {
  const { content, password } = req.body;
  if (!content || !password) return res.status(400).json({ error: 'Content and password required' });
  const hashedPassword = await bcrypt.hash(password, 10);
  const paste = await Paste.create({
    content,
    password: hashedPassword,
    userId: req.user.id
  });
  res.json(paste);
});

app.get('/api/pastes', authenticateToken, async (req, res) => {
  const pastes = await Paste.find({ userId: req.user.id }).select('-password');
  res.json(pastes);
});

app.get('/api/users', authenticateToken, async (req, res) => {
  const users = await User.find().select('username');
  res.json(users);
});

app.get('/api/pastes/:userId', authenticateToken, async (req, res) => {
  const pastes = await Paste.find({ userId: req.params.userId }).select('-password');
  res.json(pastes);
});

app.post('/api/pastes/:id/view', authenticateToken, async (req, res) => {
  const { password } = req.body;
  const paste = await Paste.findById(req.params.id);
  if (!paste) return res.status(404).json({ error: 'Paste not found' });
  if (!(await bcrypt.compare(password, paste.password))) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  res.json({ content: paste.content });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});