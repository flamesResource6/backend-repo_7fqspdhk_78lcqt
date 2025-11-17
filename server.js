// Express + Socket.io backend for Nigerian Traffic Monitoring Platform
import express from 'express';
import http from 'http';
import cors from 'cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { Server as SocketIOServer } from 'socket.io';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: { origin: '*', methods: ['GET','POST','PUT','DELETE'] }
});

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Static for uploaded images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Rate limiting for report creation
const createReportLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,
});

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://<username>:<password>@cluster.mongodb.net/traffic';
mongoose.connect(MONGO_URI, { dbName: process.env.MONGO_DB || 'traffic' })
  .then(()=> console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error', err));

// Mongoose Schemas
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  passwordHash: String,
  city: String,
  points: { type: Number, default: 0 },
  badges: { type: [String], default: [] },
  provider: { type: String, default: 'local' },
  isAdmin: { type: Boolean, default: false },
}, { timestamps: true });

const reportSchema = new mongoose.Schema({
  location: { lat: Number, lng: Number },
  type: { type: String, enum: ['traffic_jam','accident','pothole','police_checkpoint','roadwork','flood'] },
  desc: String,
  timestamp: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  city: String,
  photoUrl: String,
  votes: { type: Map, of: Number, default: {} },
  score: { type: Number, default: 0 },
  expiresAt: { type: Date, index: { expires: '0s' } }, // TTL index created dynamically
}, { timestamps: true });

// Set TTL to 1 hour after save
reportSchema.pre('save', function(next){
  if(!this.expiresAt){
    this.expiresAt = new Date(Date.now() + 60*60*1000);
  }
  next();
});

const routeSubscriptionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  from: String,
  to: String,
  deviceToken: String,
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Report = mongoose.model('Report', reportSchema);
const RouteSubscription = mongoose.model('RouteSubscription', routeSubscriptionSchema);

// Auth helpers
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
function authRequired(req, res, next){
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if(!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e){ return res.status(401).json({ error: 'Invalid token' }); }
}

// Multer for image uploads (local disk)
const storage = multer.diskStorage({
  destination: (req,file,cb)=> cb(null, path.join(__dirname, 'uploads')),
  filename: (req,file,cb)=> cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Socket.io handlers
io.on('connection', (socket)=>{
  console.log('client connected', socket.id);
  socket.on('disconnect', ()=> console.log('client disconnected', socket.id));
});

// Routes
app.get('/', (req,res)=> res.json({ status: 'ok', service: 'traffic-backend' }));

// Auth
app.post('/api/auth/signup', async (req,res)=>{
  try {
    const { name, email, password, city } = req.body;
    const existing = await User.findOne({ email });
    if(existing) return res.status(400).json({ error: 'Email already in use' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash, city });
    const token = jwt.sign({ id: user._id, email: user.email, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, city: user.city, points: user.points, badges: user.badges } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req,res)=>{
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if(!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, email: user.email, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, city: user.city, points: user.points, badges: user.badges } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/anonymous', async (req,res)=>{
  const anon = { id: 'anonymous', email: 'anonymous@local', isAdmin: false };
  const token = jwt.sign(anon, JWT_SECRET, { expiresIn: '1d' });
  res.json({ token, user: { id: 'anonymous', name: 'Guest', email: 'anonymous' } });
});

// Reports
app.get('/api/reports', async (req,res)=>{
  const { city } = req.query;
  const q = city ? { city } : {};
  const items = await Report.find(q).sort({ createdAt: -1 }).limit(200);
  res.json(items);
});

app.post('/api/reports', createReportLimiter, upload.single('photo'), async (req,res)=>{
  try {
    const { lat, lng, type, desc, userId, city } = req.body;
    const payload = {
      location: { lat: parseFloat(lat), lng: parseFloat(lng) },
      type, desc, city,
      userId: userId && userId !== 'anonymous' ? userId : undefined,
      photoUrl: req.file ? `/uploads/${req.file.filename}` : undefined,
    };
    const report = await Report.create(payload);
    io.emit('report:new', report);
    res.json(report);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reports/:id/vote', async (req,res)=>{
  const { id } = req.params;
  const { userId, value } = req.body; // value 1 or -1
  const r = await Report.findById(id);
  if(!r) return res.status(404).json({ error: 'Not found' });
  if(userId && userId !== 'anonymous') r.votes.set(userId, Math.sign(Number(value)));
  r.score = Array.from(r.votes.values()).reduce((a,b)=> a+b, 0);
  await r.save();
  io.emit('report:update', r);
  res.json(r);
});

// Leaderboard
app.get('/api/leaderboard', async (req,res)=>{
  const { city } = req.query;
  const pipeline = [
    { $match: city ? { city } : {} },
    { $group: { _id: '$userId', count: { $sum: 1 } } },
    { $sort: { count: -1 } },
    { $limit: 20 },
  ];
  const agg = await Report.aggregate(pipeline);
  const users = await User.find({ _id: { $in: agg.map(a=>a._id).filter(Boolean) } });
  const byId = Object.fromEntries(users.map(u=>[String(u._id), u]));
  res.json(agg.map(a=>({ user: byId[String(a._id)] || { name: 'Anonymous' }, reports: a.count })));
});

// Admin dashboard minimal endpoints
app.get('/api/admin/reports', authRequired, async (req,res)=>{
  if(!req.user.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const items = await Report.find({}).sort({ createdAt: -1 }).limit(500);
  res.json(items);
});

app.delete('/api/admin/reports/:id', authRequired, async (req,res)=>{
  if(!req.user.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  await Report.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

// Seed data
app.post('/api/seed', async (req,res)=>{
  const sample = [
    { location: { lat: 6.5244, lng: 3.3792 }, type: 'traffic_jam', desc: 'Heavy traffic on Third Mainland Bridge', city: 'Lagos' },
    { location: { lat: 9.0765, lng: 7.3986 }, type: 'roadwork', desc: 'Road maintenance causing delays', city: 'Abuja' },
    { location: { lat: 6.465422, lng: 3.406448 }, type: 'flood', desc: 'Flooded area around Lekki', city: 'Lagos' },
  ];
  const inserted = await Report.insertMany(sample);
  res.json(inserted);
});

// Health
app.get('/health', (req,res)=> res.json({ ok: true }));

const PORT = process.env.PORT || 8000;
server.listen(PORT, ()=> console.log('Server running on', PORT));
