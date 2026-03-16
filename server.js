const express   = require('express');
const mongoose  = require('mongoose');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const app = express();
app.use(express.json());

// ① Connect to MongoDB
mongoose.connect('mongodb+srv://cedrikvergara21_db_user:mypassword123@cluster0.up0ttjn.mongodb.net/?appName=Cluster0')
  .then(() => console.log('Connected to MongoDB!'))
  .catch(err => console.log('Error:', err));

// ② User schema with password field
const userSchema = new mongoose.Schema({
  name:     String,
  email:    { type: String, unique: true },
  password: String,
});
const User = mongoose.model('User', userSchema);

// Secret key for JWT — keep this private!
const JWT_SECRET = 'mysecretkey123';

// ③ REGISTER route
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Hash the password before saving
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({ name, email, password: hashedPassword });
  await user.save();

  res.status(201).json({ message: 'User registered successfully!' });
});

// ④ LOGIN route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'User not found' });

  // Check password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Wrong password' });

  // Create and send JWT token
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1d' });
  res.json({ message: 'Login successful!', token });
});

// ⑤ PROTECTED route — only logged in users can access
app.get('/profile', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    res.json({ name: user.name, email: user.email });
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
});

app.listen(3000, () => console.log('Running on http://localhost:3000'));