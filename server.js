import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId } from 'mongodb';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

/* ==== Config ==== */
const {
  PORT = 8080,
  MONGODB_URI,
  JWT_SECRET,
  CORS_ORIGIN = '*'
} = process.env;

if (!MONGODB_URI || !JWT_SECRET) {
  console.error('Missing MONGODB_URI or JWT_SECRET');
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN,
  credentials: false
}));

/* ==== Mongo ==== */
/* ==== Mongo (robust connect) ==== */
const client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
console.log('Connecting to Mongo…');
await client.connect();
console.log('Mongo connected');
let db, Users, Sessions, WorkItems, Logs, Lookups, mongoReady = false;

async function connectMongoWithRetry() {
  while (!mongoReady) {
    try {
      await client.connect();
      db = client.db(); // workflow from URI
      Users = db.collection('users');
      Sessions = db.collection('sessions');
      WorkItems = db.collection('work_items');
      Logs = db.collection('workflow_log');
      Lookups = db.collection('lookups');
      mongoReady = true;
      console.log('✅ Mongo connected');
    } catch (e) {
      console.error('❌ Mongo connect failed:', e.message);
      await new Promise(r => setTimeout(r, 5000));
    }
  }
}
connectMongoWithRetry();

// Only block DB-dependent routes until ready
app.use((req,res,next)=>{
  if (!mongoReady && req.path !== '/' && !req.path.startsWith('/setup'))
    return res.status(503).json({ error: 'DB not ready' });
  next();
});


/* ==== Helpers ==== */
const ROLES = ['ADMIN','EDITOR','R1','R2','R3'];

const FSM = {
  UNASSIGNED:      { to: ['EDITING'], role: ['ADMIN'] },
  EDITING:         { to: ['EDIT_DONE'], role: ['EDITOR'] },
  EDIT_DONE:       { to: ['R1_PENDING'], role: ['ADMIN'] },   // or auto
  R1_PENDING:      { to: ['R1_IN_PROGRESS'], role: ['R1'] },
  R1_IN_PROGRESS:  { to: ['R1_APPROVED','R1_REWORK'], role: ['R1'] },
  R1_REWORK:       { to: ['EDITING'], role: ['ADMIN'] },       // or R1 send back to EDITING
  R1_APPROVED:     { to: ['R2_PENDING'], role: ['ADMIN'] },
  R2_PENDING:      { to: ['R2_IN_PROGRESS'], role: ['R2'] },
  R2_IN_PROGRESS:  { to: ['R2_APPROVED','R2_REWORK'], role: ['R2'] },
  R2_REWORK:       { to: ['EDITING'], role: ['ADMIN'] },
  R2_APPROVED:     { to: ['R3_PENDING'], role: ['ADMIN'] },
  R3_PENDING:      { to: ['R3_IN_PROGRESS'], role: ['R3'] },
  R3_IN_PROGRESS:  { to: ['R3_APPROVED','R3_REWORK'], role: ['R3'] },
  R3_REWORK:       { to: ['EDITING'], role: ['ADMIN'] },
  R3_APPROVED:     { to: [], role: [] } // final
};

function signJwt(payload, ttlSec = 8 * 60 * 60) { // 8h
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ttlSec });
}
function auth(allowed = ROLES) {
  return async (req, res, next) => {
    try {
      const hdr = req.headers.authorization || '';
      const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
      if (!token) return res.status(401).json({ error: 'No token' });
      const decoded = jwt.verify(token, JWT_SECRET);
      if (!allowed.includes(decoded.role) && !allowed.includes('*'))
        return res.status(403).json({ error: 'Forbidden' });
      req.user = decoded; // { id, username, role }
      next();
    } catch (e) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}
function requireBody(fields, req, res) {
  for (const f of fields) {
    if (req.body[f] === undefined) {
      res.status(400).json({ error: `Missing field: ${f}` });
      return false;
    }
  }
  return true;
}

/* ==== Auth endpoints ==== */
app.post('/auth/login', async (req, res) => {
  if (!requireBody(['username','password'], req, res)) return;
  const { username, password } = req.body;
  const u = await Users.findOne({ username, isActive: { $ne: false } });
  if (!u) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, u.passHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signJwt({ id: u._id.toString(), username, role: u.role });
  return res.json({ token, role: u.role, username: u.username });
});

app.post('/auth/refresh', auth(ROLES), async (req, res) => {
  const { id, username, role } = req.user;
  const token = signJwt({ id, username, role });
  res.json({ token });
});

/* ==== Admin: user management ==== */
app.post('/users/create', auth(['ADMIN']), async (req, res) => {
  if (!requireBody(['username','password','role'], req, res)) return;
  const { username, password, role } = req.body;
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  const passHash = await bcrypt.hash(password, 10);
  await Users.insertOne({ username, role, passHash, isActive: true, createdAt: new Date() });
  res.json({ ok: true });
});

/* ==== Dashboard counts ==== */
app.get('/dashboard/counts', auth(ROLES), async (req, res) => {
  const { username, role } = req.user;
  let match = {};
  if (role === 'EDITOR') match = { editor: username };
  if (role === 'R1') match = { r1: username };
  if (role === 'R2') match = { r2: username };
  if (role === 'R3') match = { r3: username };
  // ADMIN sees all
  const pipeline = [
    { $match: match },
    { $group: { _id: '$status', count: { $sum: 1 } } }
  ];
  const docs = await WorkItems.aggregate(pipeline).toArray();
  res.json({ counts: docs });
});

/* ==== List queue (server-side paging) ==== */
app.post('/work-items/list', auth(ROLES), async (req, res) => {
  const { username, role } = req.user;
  const { view = 'default', page = 0, pageSize = 50, search = '' } = req.body || {};
  const skip = Math.max(0, Number(page)) * Math.max(1, Number(pageSize));

  // basic filters by role/view
  let filter = {};
  if (role === 'EDITOR') filter.editor = username;
  if (role === 'R1') filter.r1 = username;
  if (role === 'R2') filter.r2 = username;
  if (role === 'R3') filter.r3 = username;

  // view → status mapping (tweak as you like)
  const viewMap = {
    editor_assigned: { status: 'EDITING' },
    editor_rework:   { status: { $in: ['R1_REWORK','R2_REWORK','R3_REWORK'] } },
    r1_pending:      { status: 'R1_PENDING' },
    r1_progress:     { status: 'R1_IN_PROGRESS' },
    admin_unassigned:{ status: 'UNASSIGNED' }
  };
  Object.assign(filter, viewMap[view] || {});
  if (search) filter.title = { $regex: search, $options: 'i' };

  const cursor = WorkItems.find(filter, { projection: { title: 1, status:1, lastActionAt:1, editor:1, r1:1, r2:1, r3:1, version:1 } })
                          .sort({ lastActionAt: -1 })
                          .skip(skip)
                          .limit(Math.max(1, Math.min(200, Number(pageSize))));
  const items = await cursor.toArray();
  const total = await WorkItems.countDocuments(filter);
  res.json({ items, total, page, pageSize });
});

/* ==== Transition (atomic + optimistic) ==== */
app.post('/work-items/transition', auth(ROLES), async (req, res) => {
  if (!requireBody(['id','fromStatus','toStatus','expectedVersion'], req, res)) return;
  const { username, role } = req.user;
  const { id, fromStatus, toStatus, note = '', expectedVersion } = req.body;

  // FSM check
  const rule = FSM[fromStatus];
  if (!rule || !rule.to.includes(toStatus)) return res.status(400).json({ error: 'Invalid transition' });
  if (!rule.role.includes(role) && role !== 'ADMIN') return res.status(403).json({ error: 'Not allowed for this role' });

  // Ownership check (keeps clicks minimal but safe)
  const ownerField = role === 'EDITOR' ? 'editor'
                    : role === 'R1' ? 'r1'
                    : role === 'R2' ? 'r2'
                    : role === 'R3' ? 'r3' : null;

  const filter = { _id: new ObjectId(id), status: fromStatus, version: expectedVersion };
  if (ownerField) filter[ownerField] = username;

  const update = {
    $set: { status: toStatus, lastActionAt: new Date() },
    $inc: { version: 1 }
  };

  const result = await WorkItems.findOneAndUpdate(filter, update, { returnDocument: 'after' });
  if (!result || !result.value) return res.status(409).json({ error: 'Stale data or not authorized' });

  await Logs.insertOne({ ts: new Date(), itemId: id, actor: username, from: fromStatus, to: toStatus, note });
  res.json({ ok: true, item: result.value });
});

/* ==== Assign (Admin) ==== */
app.post('/work-items/assign', auth(['ADMIN']), async (req, res) => {
  if (!requireBody(['id','stage','assignee'], req, res)) return;
  const { id, stage, assignee } = req.body; // stage: editor|r1|r2|r3
  const field = ['editor','r1','r2','r3'].includes(stage) ? stage : null;
  if (!field) return res.status(400).json({ error: 'Invalid stage' });
  const out = await WorkItems.findOneAndUpdate(
    { _id: new ObjectId(id) },
    { $set: { [field]: assignee, lastActionAt: new Date() }, $inc: { version: 1 } },
    { returnDocument: 'after' }
  );
  res.json({ ok: true, item: out.value });
});

/* ==== Health ==== */
app.get('/', (_req, res) => res.send('OK'));

// --- One-time bootstrap to create the first ADMIN (protected by SETUP_SECRET) ---
app.post('/setup/first-admin', async (req, res) => {
  const ok = req.headers['x-setup-secret'] === process.env.SETUP_SECRET;
  if (!ok) return res.status(403).json({ error: 'Forbidden' });
  const adminExists = await Users.countDocuments({ role: 'ADMIN' });
  if (adminExists) return res.status(400).json({ error: 'Admin already exists' });

  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username/password required' });
  const passHash = await bcrypt.hash(password, 10);
  await Users.insertOne({ username, passHash, role: 'ADMIN', isActive: true, createdAt: new Date() });
  res.json({ ok: true });
});

/* ==== Start ==== */
app.listen(PORT, () => {
  console.log(`API listening on :${PORT}`);
});



