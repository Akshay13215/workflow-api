// server.js (ESM)
// Run with Node 18+ and "type":"module" in package.json

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
  CORS_ORIGIN = '*',
  SETUP_SECRET
} = process.env;

if (!MONGODB_URI || !JWT_SECRET) {
  console.error('Missing MONGODB_URI or JWT_SECRET');
  process.exit(1);
}

/* ==== App ==== */
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN }));

/* ==== Mongo (connect once, prepare collections) ==== */
console.log('Connecting to Mongo…');
const client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
await client.connect();
console.log('✅ Mongo connected');

const db        = client.db(); // from URI
const Users     = db.collection('users');
const Sessions  = db.collection('sessions');
const WorkItems = db.collection('work_items');
const Logs      = db.collection('workflow_log');
const Lookups   = db.collection('lookups');
const Projects  = db.collection('projects');

// helpful indexes
await Promise.all([
  Users.createIndex({ username: 1 }, { unique: true }),
  Projects.createIndex({ key: 1 }, { unique: true }),
  WorkItems.createIndex({ status: 1, lastActionAt: -1 }),
  WorkItems.createIndex({ projectKey: 1, status: 1 }),
  WorkItems.createIndex({ editor: 1 }),
  WorkItems.createIndex({ r1: 1 }),
  WorkItems.createIndex({ r2: 1 }),
  WorkItems.createIndex({ r3: 1 }),
]);

/* ==== Auth utils ==== */
const ROLES = ['ADMIN', 'EDITOR', 'R1', 'R2', 'R3'];

function signJwt(payload, ttlSec = 8 * 60 * 60) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ttlSec });
}

function auth(allowed = ROLES) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    const token = h.replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
      const claims = jwt.verify(token, JWT_SECRET);
      if (!allowed.includes(claims.role)) return res.status(403).json({ error: 'Forbidden' });
      req.user = claims; // { id, username, role }
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

function requireBody(fields, req, res) {
  for (const f of fields) {
    if (req.body?.[f] === undefined) {
      res.status(400).json({ error: `Missing field: ${f}` });
      return false;
    }
  }
  return true;
}

/* ==== FSM (status flow) ==== */
const FSM = {
  UNASSIGNED:      { to: ['EDITING'], role: ['ADMIN'] },
  EDITING:         { to: ['EDIT_DONE'], role: ['EDITOR'] },
  EDIT_DONE:       { to: ['R1_PENDING'], role: ['ADMIN'] },
  R1_PENDING:      { to: ['R1_IN_PROGRESS'], role: ['R1'] },
  R1_IN_PROGRESS:  { to: ['R1_APPROVED','R1_REWORK'], role: ['R1'] },
  R1_REWORK:       { to: ['EDITING'], role: ['ADMIN'] },
  R1_APPROVED:     { to: ['R2_PENDING'], role: ['ADMIN'] },
  R2_PENDING:      { to: ['R2_IN_PROGRESS'], role: ['R2'] },
  R2_IN_PROGRESS:  { to: ['R2_APPROVED','R2_REWORK'], role: ['R2'] },
  R2_REWORK:       { to: ['EDITING'], role: ['ADMIN'] },
  R2_APPROVED:     { to: ['R3_PENDING'], role: ['ADMIN'] },
  R3_PENDING:      { to: ['R3_IN_PROGRESS'], role: ['R3'] },
  R3_IN_PROGRESS:  { to: ['R3_APPROVED','R3_REWORK'], role: ['R3'] },
  R3_REWORK:       { to: ['EDITING'], role: ['ADMIN'] },
  R3_APPROVED:     { to: [], role: [] }
};

/* ==== Public (no auth) ==== */
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// one-time bootstrap
app.post('/api/setup/first-admin', async (req, res) => {
  if (!SETUP_SECRET || req.headers['x-setup-secret'] !== SETUP_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const exists = await Users.countDocuments({ role: 'ADMIN' });
  if (exists) return res.status(400).json({ error: 'Admin already exists' });

  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username/password required' });

  const passHash = await bcrypt.hash(password, 10);
  await Users.insertOne({ username, passHash, role: 'ADMIN', isActive: true, createdAt: new Date() });
  res.json({ ok: true });
});

// login (public)
app.post('/api/auth/login', async (req, res) => {
  if (!requireBody(['username','password'], req, res)) return;
  const { username, password } = req.body;
  const u = await Users.findOne({ username, isActive: { $ne: false } });
  if (!u) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, u.passHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = signJwt({ id: u._id.toString(), username: u.username, role: u.role });
  res.json({ token, role: u.role, username: u.username });
});

/* ==== Auth guard (protect everything below) ==== */
app.use('/api', auth(ROLES));

/* ==== Auth (protected helpers) ==== */
app.post('/api/auth/refresh', (req, res) => {
  const { id, username, role } = req.user;
  res.json({ token: signJwt({ id, username, role }) });
});

app.get('/api/auth/me', async (req, res) => {
  const { id, username, role } = req.user;
  const u = await Users.findOne({ _id: new ObjectId(id) }, { projection: { passHash: 0 } });
  res.json({ user: { id, username, role, projects: u?.projects || [] } });
});

/* ==== Admin: users ==== */
app.post('/api/admin/users/create', auth(['ADMIN']), async (req, res) => {
  if (!requireBody(['username','password','role'], req, res)) return;
  const { username, password, role } = req.body;
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  const passHash = await bcrypt.hash(password, 10);
  await Users.insertOne({ username, role, passHash, isActive: true, createdAt: new Date() });
  res.json({ ok: true });
});

app.get('/api/admin/users/list', auth(['ADMIN']), async (_req, res) => {
  const users = await Users.find({}, { projection: { passHash: 0 } }).toArray();
  res.json({ users });
});

app.post('/api/admin/users/update-projects', auth(['ADMIN']), async (req, res) => {
  if (!requireBody(['username','projects'], req, res)) return;
  const { username, projects } = req.body;
  await Users.updateOne({ username }, { $set: { projects } });
  res.json({ ok: true });
});

/* ==== Admin: projects ==== */
// columns = [{ key, label, type, required, rolesVisible?: ['ADMIN','EDITOR','R1','R2','R3'] }]
app.post('/api/admin/projects/create', auth(['ADMIN']), async (req, res) => {
  if (!requireBody(['key','name','columns'], req, res)) return;
  const { key, name, columns = [], stages = null, isActive = true } = req.body;
  const doc = { key, name, columns, stages, isActive, createdAt: new Date() };
  await Projects.insertOne(doc);
  res.json({ ok: true, project: doc });
});

app.post('/api/admin/projects/update', auth(['ADMIN']), async (req, res) => {
  if (!requireBody(['key'], req, res)) return;
  const { key, name, columns, stages, isActive } = req.body;
  const update = {};
  if (name !== undefined) update.name = name;
  if (columns !== undefined) update.columns = columns;
  if (stages !== undefined) update.stages = stages;
  if (isActive !== undefined) update.isActive = isActive;
  const out = await Projects.findOneAndUpdate({ key }, { $set: update }, { returnDocument: 'after' });
  res.json({ ok: true, project: out.value });
});

app.get('/api/admin/projects/list', auth(['ADMIN']), async (_req, res) => {
  const projects = await Projects.find({}).sort({ name: 1 }).toArray();
  res.json({ projects });
});

/* ==== Bulk create work items ==== */
app.post('/api/work-items/bulk-create', auth(['ADMIN']), async (req, res) => {
  if (!requireBody(['projectKey','titles'], req, res)) return;
  const { projectKey, titles = [], defaults = {} } = req.body;
  if (!Array.isArray(titles) || titles.length === 0) {
    return res.status(400).json({ error: 'titles must be a non-empty array' });
  }
  const project = await Projects.findOne({ key: projectKey });
  if (!project) return res.status(400).json({ error: 'Unknown projectKey' });

  const now = new Date();
  const docs = titles.map(t => ({
    projectKey,
    title: String(t).trim(),
    status: 'UNASSIGNED',
    version: 1,
    lastActionAt: now,
    fields: defaults
  }));
  const result = await WorkItems.insertMany(docs);
  res.json({ ok: true, inserted: result.insertedCount ?? Object.keys(result.insertedIds).length });
});

/* ==== Dashboard counts ==== */
app.get('/api/dashboard/counts', auth(ROLES), async (req, res) => {
  const { username, role } = req.user;
  let match = {};
  if (role === 'EDITOR') match = { editor: username };
  if (role === 'R1') match = { r1: username };
  if (role === 'R2') match = { r2: username };
  if (role === 'R3') match = { r3: username };

  const pipeline = [{ $match: match }, { $group: { _id: '$status', count: { $sum: 1 } } }];
  const docs = await WorkItems.aggregate(pipeline).toArray();
  res.json({ counts: docs });
});

/* ==== List queue (paging) ==== */
app.post('/api/work-items/list', auth(ROLES), async (req, res) => {
  const { username, role } = req.user;
  const { view = 'default', page = 0, pageSize = 50, search = '', projectKey } = req.body || {};
  const skip = Math.max(0, Number(page)) * Math.max(1, Number(pageSize));

  const filter = {};
  if (projectKey) filter.projectKey = projectKey;
  if (role === 'EDITOR') filter.editor = username;
  if (role === 'R1') filter.r1 = username;
  if (role === 'R2') filter.r2 = username;
  if (role === 'R3') filter.r3 = username;

  const viewMap = {
    editor_assigned: { status: 'EDITING' },
    editor_rework:   { status: { $in: ['R1_REWORK','R2_REWORK','R3_REWORK'] } },
    r1_pending:      { status: 'R1_PENDING' },
    r1_progress:     { status: 'R1_IN_PROGRESS' },
    admin_unassigned:{ status: 'UNASSIGNED' }
  };
  Object.assign(filter, viewMap[view] || {});
  if (search) filter.title = { $regex: search, $options: 'i' };

  const cursor = WorkItems.find(
    filter,
    { projection: { title:1, status:1, lastActionAt:1, editor:1, r1:1, r2:1, r3:1, version:1, projectKey:1 } }
  ).sort({ lastActionAt: -1 })
   .skip(skip)
   .limit(Math.max(1, Math.min(200, Number(pageSize))));

  const items = await cursor.toArray();
  const total = await WorkItems.countDocuments(filter);
  res.json({ items, total, page, pageSize });
});

/* ==== Transition ==== */
app.post('/api/work-items/transition', auth(ROLES), async (req, res) => {
  if (!requireBody(['id','fromStatus','toStatus','expectedVersion'], req, res)) return;
  const { username, role } = req.user;
  const { id, fromStatus, toStatus, note = '', expectedVersion } = req.body;

  const rule = FSM[fromStatus];
  if (!rule || !rule.to.includes(toStatus)) return res.status(400).json({ error: 'Invalid transition' });
  if (!rule.role.includes(role) && role !== 'ADMIN') return res.status(403).json({ error: 'Not allowed for this role' });

  const ownerField =
    role === 'EDITOR' ? 'editor' :
    role === 'R1'     ? 'r1'     :
    role === 'R2'     ? 'r2'     :
    role === 'R3'     ? 'r3'     : null;

  const filter = { _id: new ObjectId(id), status: fromStatus, version: expectedVersion };
  if (ownerField) filter[ownerField] = username;

  const update = { $set: { status: toStatus, lastActionAt: new Date() }, $inc: { version: 1 } };
  const result = await WorkItems.findOneAndUpdate(filter, update, { returnDocument: 'after' });
  if (!result?.value) return res.status(409).json({ error: 'Stale data or not authorized' });

  await Logs.insertOne({ ts: new Date(), itemId: id, actor: username, from: fromStatus, to: toStatus, note });
  res.json({ ok: true, item: result.value });
});

/* ==== Assign (Admin) ==== */
app.post('/api/work-items/assign', auth(['ADMIN']), async (req, res) => {
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

/* ==== Misc ==== */
app.get('/api/meta/fsm', auth(ROLES), (_req, res) => res.json({ fsm: FSM }));
app.get('/', (_req, res) => res.send('OK'));

/* ==== Start ==== */
app.listen(PORT, () => console.log(`API listening on :${PORT}`));
