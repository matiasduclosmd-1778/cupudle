require('dotenv').config();
const express  = require('express');
const crypto   = require('crypto');
const jwt      = require('jsonwebtoken');
const { neon } = require('@neondatabase/serverless');
const path     = require('path');

const app        = express();
const sql        = neon(process.env.DATABASE_URL);
const JWT_SECRET = process.env.JWT_SECRET || 'cupudle-dev-secret-change-in-prod';

app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── DB: crear tablas si no existen ───────────────────────────────────

const dbReady = (async () => {
  await sql`
    CREATE TABLE IF NOT EXISTS cupudle_users (
      key          TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      hash         TEXT NOT NULL
    )`;
  await sql`
    CREATE TABLE IF NOT EXISTS cupudle_rankings (
      username   TEXT    PRIMARY KEY,
      attempts   INTEGER NOT NULL,
      created_at BIGINT  NOT NULL
    )`;
})().catch(err => { console.error('DB init error:', err); process.exit(1); });

app.use(async (_req, _res, next) => { await dbReady; next(); });

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

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)     return res.status(400).json({ error: 'Campos requeridos' });
  if (username.trim().length < 2)  return res.status(400).json({ error: 'Nombre muy corto (mínimo 2 caracteres)' });
  if (password.length < 4)        return res.status(400).json({ error: 'Contraseña muy corta (mínimo 4 caracteres)' });

  const key  = username.trim().toLowerCase();
  const name = username.trim();
  try {
    await sql`
      INSERT INTO cupudle_users (key, display_name, hash)
      VALUES (${key}, ${name}, ${hashPwd(password)})`;
    res.json({ token: signToken(name), username: name });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Ese nombre de usuario ya existe' });
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Campos requeridos' });

  const rows = await sql`
    SELECT * FROM cupudle_users WHERE key = ${username.trim().toLowerCase()}`;
  const user = rows[0];

  if (!user || user.hash !== hashPwd(password))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

  res.json({ token: signToken(user.display_name), username: user.display_name });
});

app.get('/api/rankings', async (_req, res) => {
  const rows = await sql`
    SELECT username, attempts, created_at AS date
    FROM cupudle_rankings
    ORDER BY attempts ASC, created_at ASC
    LIMIT 12`;
  res.json(rows);
});

app.post('/api/win', async (req, res) => {
  const username = sessionUser(req);
  if (!username) return res.status(401).json({ error: 'Sesión expirada, iniciá sesión de nuevo' });

  const { attempts } = req.body || {};
  if (!Number.isInteger(attempts) || attempts < 1 || attempts > 6)
    return res.status(400).json({ error: 'Intentos inválidos' });

  await sql`
    INSERT INTO cupudle_rankings (username, attempts, created_at)
    VALUES (${username}, ${attempts}, ${Date.now()})
    ON CONFLICT (username) DO UPDATE
      SET attempts   = EXCLUDED.attempts,
          created_at = EXCLUDED.created_at
      WHERE cupudle_rankings.attempts > EXCLUDED.attempts`;

  const rows = await sql`
    SELECT username, attempts, created_at AS date
    FROM cupudle_rankings
    ORDER BY attempts ASC, created_at ASC
    LIMIT 12`;
  res.json(rows);
});

// ── START (desarrollo local) ──────────────────────────────────────────

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  dbReady.then(() =>
    app.listen(PORT, () => console.log(`\n  🎮  Cupudle en http://localhost:${PORT}\n`))
  );
}

module.exports = app;
