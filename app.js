const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const validator = require('validator');
const helmet = require('helmet');
const winston = require('winston');
const app = express();
const port = 3000;
const SECRET_KEY = 'mysecretkey';
// ===== LOGGER (FORCE FILE CREATE) =====
const logger = winston.createLogger({
level: 'info',
transports: [
new winston.transports.Console(),
new winston.transports.File({
filename: path.join(__dirname, 'security.log')
})
]
});
// ===== MIDDLEWARE =====
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(helmet());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// ===== MONGODB CONNECTION =====
mongoose.connect('mongodb://localhost:27017/authdb')
.then(() => {
console.log('MongoDB connected');
logger.info('MongoDB connected');
})
.catch(err => {
console.log(err);
logger.error(err.message);
});
// ===== USER SCHEMA =====
const userSchema = new mongoose.Schema({
username: String,
email: String,
password: String
});
const User = mongoose.model('User', userSchema);
// ===== ROUTES =====
// Home
app.get('/', (req, res) => {
logger.info('Home page accessed');
res.send('Server running on port 3000');
});
// Signup Page
app.get('/signup', (req, res) => {
logger.info('Signup page opened');
res.render('signup');
});
// Login Page
app.get('/login', (req, res) => {
logger.info('Login page opened');
res.render('login');
});
// ===== SIGNUP =====
app.post('/signup', async (req, res) => {
const { username, email, password } = req.body;
if (!validator.isEmail(email)) {
logger.warn('Invalid email during signup');
return res.send('Invalid email format');
}
if (!validator.isStrongPassword(password, {
minLength: 6,
minLowercase: 1,
minNumbers: 1
})) {
logger.warn('Weak password during signup');
return res.send('Password must be at least 6 characters and contain a number');
}
const hashedPassword = await bcrypt.hash(password, 10);
const user = new User({
username,
email,
password: hashedPassword
});
await user.save();
logger.info(`New user registered: ${email}`);
res.send('Signup successful. <a href="/login">Login here</a>');
});
// ===== LOGIN =====
app.post('/login', async (req, res) => {
const { email, password } = req.body;
const user = await User.findOne({ email });
if (!user) {
logger.warn(`Login failed - user not found: ${email}`);
return res.send('User not found');
}
const isMatch = await bcrypt.compare(password, user.password);
if (!isMatch) {
logger.warn(`Invalid password attempt for: ${email}`);
return res.send('Invalid password');
}
const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '1h' });
logger.info(`User logged in: ${email}`);
res.send(`
Login successful <br>
Token: ${token} <br>
<a href="/profile?token=${token}">Go to Profile</a>
`);
});
// ===== PROFILE =====
app.get('/profile', async (req, res) => {
const token = req.query.token;
if (!token) {
logger.warn('Profile access denied - no token');
return res.send('Access denied');
}
try {
const decoded = jwt.verify(token, SECRET_KEY);
const user = await User.findById(decoded.id);
logger.info(`Profile accessed by: ${user.email}`);
res.send(`
Welcome ${user.username} <br>
Email: ${user.email}
`);
} catch (err) {
logger.error('Invalid token used');
res.send('Invalid token');
}
});
// ===== START SERVER =====
app.listen(port, () => {
console.log(`Server running at http://localhost:${port}`);
logger.info('Application started');
});
