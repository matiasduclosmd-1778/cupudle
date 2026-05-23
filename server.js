require('dotenv').config();
const express  = require('express');
const crypto   = require('crypto');
const jwt      = require('jsonwebtoken');
const { neon } = require('@neondatabase/serverless');
const path     = require('path');

const app        = express();
const JWT_SECRET = process.env.JWT_SECRET || 'cupudle-dev-secret-change-in-prod';

app.use(express.json());
if (process.env.NODE_ENV !== 'production') {
  app.use(express.static(path.join(__dirname)));
}

// ── WORDS ─────────────────────────────────────────────────────────────

const WORDS = [
  'CUNEIFORME', 'FABULA',   'BUFALO',   'NOELIA',   'GLANZ',
  'CHINA',      'BROOKLYN', 'PEPA',     'GIGANTES', 'DUENDE',
  'LOCO',       'ENANO',    'TORRE',    'FACHU',    'BRUNO',
  'CABE',       'DOMENE',   'PABLO',    'GABRIEL',  'MARTIN',
  'ALEJO',      'CASTILLO', 'WHISKY',   'PORRO',    'BANDER'
];

const MS_PER_ROUND = 12 * 60 * 60 * 1000;

function getWordIndex() {
  return Math.floor(Date.now() / MS_PER_ROUND) % WORDS.length;
}
function getWord()      { return WORDS[getWordIndex()]; }
function getNextWordAt() {
  return (Math.floor(Date.now() / MS_PER_ROUND) + 1) * MS_PER_ROUND;
}

// ── DB ────────────────────────────────────────────────────────────────

function getSQL() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL no configurada');
  return neon(process.env.DATABASE_URL);
}

let schemaReady = false;

async function ensureDB() {
  const sql = getSQL();

  await sql`
    CREATE TABLE IF NOT EXISTS cupudle_users (
      key          TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      hash         TEXT NOT NULL
    )`;

  if (!schemaReady) {
    const cols = await sql`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'cupudle_rankings' AND table_schema = 'public'`;

    const hasWordIndex = cols.some(c => c.column_name === 'word_index');

    if (cols.length === 0) {
      await sql`
        CREATE TABLE cupudle_rankings (
          username   TEXT    NOT NULL,
          word_index INTEGER NOT NULL,
          attempts   INTEGER NOT NULL,
          created_at BIGINT  NOT NULL,
          PRIMARY KEY (username, word_index)
        )`;
    } else if (!hasWordIndex) {
      // Migrate: old table had only (username PK), new needs (username, word_index)
      await sql`DROP TABLE cupudle_rankings`;
      await sql`
        CREATE TABLE cupudle_rankings (
          username   TEXT    NOT NULL,
          word_index INTEGER NOT NULL,
          attempts   INTEGER NOT NULL,
          created_at BIGINT  NOT NULL,
          PRIMARY KEY (username, word_index)
        )`;
    }

    schemaReady = true;
  }

  return sql;
}

// ── HELPERS ───────────────────────────────────────────────────────────

function hashPwd(p) {
  return crypto.createHmac('sha256', 'cupudle-salt-2026').update(p).digest('hex');
}
function signToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
}
function sessionUser(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  try { return jwt.verify(auth.slice(7), JWT_SECRET).username; }
  catch { return null; }
}

// ── RUTAS ─────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password)     return res.status(400).json({ error: 'Campos requeridos' });
    if (username.trim().length < 2) return res.status(400).json({ error: 'Nombre muy corto' });
    if (password.length < 4)        return res.status(400).json({ error: 'Contraseña muy corta' });

    const sql  = await ensureDB();
    const key  = username.trim().toLowerCase();
    const name = username.trim();

    await sql`
      INSERT INTO cupudle_users (key, display_name, hash)
      VALUES (${key}, ${name}, ${hashPwd(password)})`;
    res.json({ token: signToken(name), username: name });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Ese nombre de usuario ya existe' });
    console.error('register error:', e.message);
    res.status(500).json({ error: 'Error del servidor: ' + e.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Campos requeridos' });

    const sql  = await ensureDB();
    const rows = await sql`SELECT * FROM cupudle_users WHERE key = ${username.trim().toLowerCase()}`;
    const user = rows[0];

    if (!user || user.hash !== hashPwd(password))
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

    res.json({ token: signToken(user.display_name), username: user.display_name });
  } catch (e) {
    console.error('login error:', e.message);
    res.status(500).json({ error: 'Error del servidor: ' + e.message });
  }
});

// Returns current word + whether this user already won it today
app.get('/api/status', async (req, res) => {
  try {
    const username = sessionUser(req);
    if (!username) return res.status(401).json({ error: 'No autenticado' });

    const wordIndex = getWordIndex();
    const sql       = await ensureDB();

    const rows = await sql`
      SELECT 1 FROM cupudle_rankings
      WHERE username = ${username} AND word_index = ${wordIndex}`;

    res.json({
      word:       getWord(),
      wordIndex,
      alreadyWon: rows.length > 0,
      nextWordAt: getNextWordAt()
    });
  } catch (e) {
    console.error('status error:', e.message);
    res.status(500).json({ error: 'Error del servidor: ' + e.message });
  }
});

app.get('/api/rankings', async (_req, res) => {
  try {
    const sql       = await ensureDB();
    const wordIndex = getWordIndex();
    const rows      = await sql`
      SELECT username, attempts, created_at AS date
      FROM cupudle_rankings
      WHERE word_index = ${wordIndex}
      ORDER BY attempts ASC, created_at ASC
      LIMIT 12`;
    res.json(rows);
  } catch (e) {
    console.error('rankings error:', e.message);
    res.status(500).json({ error: 'Error del servidor: ' + e.message });
  }
});

app.post('/api/win', async (req, res) => {
  try {
    const username = sessionUser(req);
    if (!username) return res.status(401).json({ error: 'Sesión expirada, iniciá sesión de nuevo' });

    const { attempts } = req.body || {};
    if (!Number.isInteger(attempts) || attempts < 1 || attempts > 6)
      return res.status(400).json({ error: 'Intentos inválidos' });

    const wordIndex = getWordIndex();
    const sql       = await ensureDB();

    try {
      await sql`
        INSERT INTO cupudle_rankings (username, word_index, attempts, created_at)
        VALUES (${username}, ${wordIndex}, ${attempts}, ${Date.now()})`;
    } catch (e) {
      if (e.code !== '23505') throw e;
      // Already recorded — return rankings anyway
    }

    const rows = await sql`
      SELECT username, attempts, created_at AS date
      FROM cupudle_rankings
      WHERE word_index = ${wordIndex}
      ORDER BY attempts ASC, created_at ASC
      LIMIT 12`;
    res.json(rows);
  } catch (e) {
    console.error('win error:', e.message);
    res.status(500).json({ error: 'Error del servidor: ' + e.message });
  }
});

// ── START ─────────────────────────────────────────────────────────────

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`\n  🎮  Cupudle en http://localhost:${PORT}\n`));
}

module.exports = app;
