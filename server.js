require('dotenv').config();
const express    = require('express');
const mysql      = require('mysql2/promise');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.options('*', cors());

app.get('/',       (req, res) => res.json({ status: 'Synapse API running OK' }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

const pool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT) || 3306,
  user:     process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'railway',
  waitForConnections: true,
  connectionLimit: 10,
  connectTimeout: 20000,
});

// ── Auto-create all tables on startup ────────────────────
async function setupDatabase() {
  try {
    const conn = await pool.getConnection();
    console.log('MySQL connected successfully');

    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(100),
        role ENUM('admin','member') DEFAULT 'member',
        avatar_color VARCHAR(7) DEFAULT '#3B82F6',
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        status ENUM('todo','in_progress','review','done') DEFAULT 'todo',
        priority ENUM('low','medium','high','urgent') DEFAULT 'medium',
        creator_id INT NOT NULL,
        assignee_id INT,
        due_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (creator_id)  REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS tags (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE,
        color VARCHAR(7) DEFAULT '#6366F1'
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS task_tags (
        task_id INT NOT NULL,
        tag_id  INT NOT NULL,
        PRIMARY KEY (task_id, tag_id),
        FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
        FOREIGN KEY (tag_id)  REFERENCES tags(id)  ON DELETE CASCADE
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS task_mentions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        task_id INT NOT NULL,
        mentioned_user_id INT NOT NULL,
        mentioned_by_id   INT NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (task_id)           REFERENCES tasks(id) ON DELETE CASCADE,
        FOREIGN KEY (mentioned_user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (mentioned_by_id)   REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS smtp_config (
        id INT AUTO_INCREMENT PRIMARY KEY,
        host VARCHAR(255) NOT NULL,
        port INT NOT NULL DEFAULT 587,
        username VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        encryption ENUM('none','ssl','tls') DEFAULT 'tls',
        from_email VARCHAR(255),
        from_name  VARCHAR(100),
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS activity_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        action VARCHAR(100) NOT NULL,
        entity_type VARCHAR(50),
        entity_id INT,
        meta JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // Seed default admin user (password: Admin@1234)
    const adminHash = await bcrypt.hash('Admin@1234', 10);
    await conn.query(`
      INSERT IGNORE INTO users (username, email, password_hash, full_name, role, avatar_color)
      VALUES ('admin', 'admin@company.com', ?, 'System Admin', 'admin', '#7C5CFC')
    `, [adminHash]);

    // Seed default tags
    const defaultTags = [
      ['bug','#F87171'], ['feature','#5B8AF0'], ['design','#8B5CF6'],
      ['backend','#FBBF24'], ['frontend','#34D399'], ['urgent','#F87171']
    ];
    for (const [name, color] of defaultTags) {
      await conn.query('INSERT IGNORE INTO tags (name, color) VALUES (?,?)', [name, color]);
    }

    conn.release();
    console.log('Database tables ready');
  } catch (err) {
    console.error('Database setup error:', err.message);
  }
}

const JWT_SECRET = process.env.JWT_SECRET || 'synapse_secret_change_me';

const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

const adminOnly = (req, res, next) => {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
};

const wrap = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(err => {
    console.error('Route error:', err.message);
    res.status(500).json({ error: err.message || 'Server error' });
  });

// ── AUTH ──────────────────────────────────────────────────
app.post('/api/auth/login', wrap(async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const [rows] = await pool.query('SELECT * FROM users WHERE username = ? AND is_active = 1', [username]);
  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
  const user = rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
  pool.query('INSERT INTO activity_log (user_id, action, entity_type) VALUES (?,?,?)', [user.id, 'login', 'user']).catch(() => {});
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, full_name: user.full_name, role: user.role, avatar_color: user.avatar_color } });
}));

// ── USERS ─────────────────────────────────────────────────
app.get('/api/users', auth, wrap(async (req, res) => {
  const [rows] = await pool.query('SELECT id, username, email, full_name, role, avatar_color, is_active, created_at FROM users ORDER BY full_name');
  res.json(rows);
}));

app.post('/api/users', auth, adminOnly, wrap(async (req, res) => {
  const { username, email, password, full_name, role } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Missing required fields' });
  const hash = await bcrypt.hash(password, 10);
  const colors = ['#3B82F6','#10B981','#F59E0B','#8B5CF6','#EC4899','#06B6D4'];
  const color = colors[Math.floor(Math.random() * colors.length)];
  const [result] = await pool.query('INSERT INTO users (username, email, password_hash, full_name, role, avatar_color) VALUES (?,?,?,?,?,?)', [username, email, hash, full_name || username, role || 'member', color]);
  res.json({ id: result.insertId, username, email, full_name, role: role || 'member', avatar_color: color });
}));

app.put('/api/users/:id', auth, adminOnly, wrap(async (req, res) => {
  const { email, full_name, role, is_active, password } = req.body;
  const updates = [], vals = [];
  if (email     !== undefined) { updates.push('email=?');         vals.push(email); }
  if (full_name !== undefined) { updates.push('full_name=?');     vals.push(full_name); }
  if (role      !== undefined) { updates.push('role=?');          vals.push(role); }
  if (is_active !== undefined) { updates.push('is_active=?');     vals.push(is_active ? 1 : 0); }
  if (password)                { updates.push('password_hash=?'); vals.push(await bcrypt.hash(password, 10)); }
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  vals.push(req.params.id);
  await pool.query(`UPDATE users SET ${updates.join(',')} WHERE id=?`, vals);
  res.json({ success: true });
}));

app.delete('/api/users/:id', auth, adminOnly, wrap(async (req, res) => {
  if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot deactivate yourself' });
  await pool.query('UPDATE users SET is_active=0 WHERE id=?', [req.params.id]);
  res.json({ success: true });
}));

// ── TASKS ─────────────────────────────────────────────────
app.get('/api/tasks', auth, wrap(async (req, res) => {
  const { status, assignee, tag } = req.query;
  let sql = `SELECT t.*, u1.username as creator_username, u1.full_name as creator_name, u1.avatar_color as creator_color, u2.username as assignee_username, u2.full_name as assignee_name, u2.avatar_color as assignee_color, GROUP_CONCAT(DISTINCT tg.name ORDER BY tg.name SEPARATOR ',') as tag_names, GROUP_CONCAT(DISTINCT tg.color ORDER BY tg.name SEPARATOR ',') as tag_colors FROM tasks t LEFT JOIN users u1 ON t.creator_id=u1.id LEFT JOIN users u2 ON t.assignee_id=u2.id LEFT JOIN task_tags tt ON t.id=tt.task_id LEFT JOIN tags tg ON tt.tag_id=tg.id WHERE 1=1`;
  const params = [];
  if (status)   { sql += ' AND t.status=?';      params.push(status); }
  if (assignee) { sql += ' AND t.assignee_id=?'; params.push(assignee); }
  if (tag)      { sql += ' AND t.id IN (SELECT tt2.task_id FROM task_tags tt2 JOIN tags tg2 ON tt2.tag_id=tg2.id WHERE tg2.name=?)'; params.push(tag); }
  sql += ' GROUP BY t.id ORDER BY t.created_at DESC';
  const [rows] = await pool.query(sql, params);
  res.json(rows.map(r => ({ ...r, tags: r.tag_names ? r.tag_names.split(',').map((n,i) => ({ name: n, color: r.tag_colors?.split(',')[i] })) : [] })));
}));

app.post('/api/tasks', auth, wrap(async (req, res) => {
  const { title, description, status, priority, assignee_id, due_date, tags, mentions } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });
  const [result] = await pool.query('INSERT INTO tasks (title, description, status, priority, creator_id, assignee_id, due_date) VALUES (?,?,?,?,?,?,?)', [title, description || '', status || 'todo', priority || 'medium', req.user.id, assignee_id || null, due_date || null]);
  const taskId = result.insertId;
  if (Array.isArray(tags) && tags.length) {
    for (const tagName of tags) {
      try {
        let [tRows] = await pool.query('SELECT id FROM tags WHERE name=?', [tagName]);
        let tagId = tRows.length ? tRows[0].id : (await pool.query('INSERT INTO tags (name) VALUES (?)', [tagName]))[0].insertId;
        await pool.query('INSERT IGNORE INTO task_tags VALUES (?,?)', [taskId, tagId]);
      } catch {}
    }
  }
  if (Array.isArray(mentions) && mentions.length) {
    for (const uid of mentions) {
      try {
        await pool.query('INSERT INTO task_mentions (task_id, mentioned_user_id, mentioned_by_id) VALUES (?,?,?)', [taskId, uid, req.user.id]);
        sendMentionEmail(uid, req.user.username, title, taskId).catch(() => {});
      } catch {}
    }
  }
  pool.query('INSERT INTO activity_log (user_id, action, entity_type, entity_id) VALUES (?,?,?,?)', [req.user.id, 'create_task', 'task', taskId]).catch(() => {});
  res.json({ id: taskId });
}));

app.put('/api/tasks/:id', auth, wrap(async (req, res) => {
  const { title, description, status, priority, assignee_id, due_date } = req.body;
  await pool.query('UPDATE tasks SET title=?, description=?, status=?, priority=?, assignee_id=?, due_date=? WHERE id=?', [title, description || '', status, priority, assignee_id || null, due_date || null, req.params.id]);
  pool.query('INSERT INTO activity_log (user_id, action, entity_type, entity_id) VALUES (?,?,?,?)', [req.user.id, 'update_task', 'task', req.params.id]).catch(() => {});
  res.json({ success: true });
}));

app.delete('/api/tasks/:id', auth, wrap(async (req, res) => {
  await pool.query('DELETE FROM tasks WHERE id=?', [req.params.id]);
  res.json({ success: true });
}));

// ── TAGS ──────────────────────────────────────────────────
app.get('/api/tags', auth, wrap(async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM tags ORDER BY name');
  res.json(rows);
}));

// ── NOTIFICATIONS ─────────────────────────────────────────
app.get('/api/notifications', auth, wrap(async (req, res) => {
  const [rows] = await pool.query('SELECT tm.*, t.title as task_title, u.username as mentioned_by FROM task_mentions tm JOIN tasks t ON tm.task_id=t.id JOIN users u ON tm.mentioned_by_id=u.id WHERE tm.mentioned_user_id=? ORDER BY tm.created_at DESC LIMIT 20', [req.user.id]);
  res.json(rows);
}));

app.put('/api/notifications/:id/read', auth, wrap(async (req, res) => {
  await pool.query('UPDATE task_mentions SET is_read=1 WHERE id=? AND mentioned_user_id=?', [req.params.id, req.user.id]);
  res.json({ success: true });
}));

// ── SMTP ──────────────────────────────────────────────────
app.get('/api/admin/smtp', auth, adminOnly, wrap(async (req, res) => {
  const [rows] = await pool.query('SELECT id, host, port, username, encryption, from_email, from_name FROM smtp_config LIMIT 1');
  res.json(rows[0] || {});
}));

app.put('/api/admin/smtp', auth, adminOnly, wrap(async (req, res) => {
  const { host, port, username, password, encryption, from_email, from_name } = req.body;
  const [existing] = await pool.query('SELECT id FROM smtp_config LIMIT 1');
  if (existing.length) {
    const sets = ['host=?','port=?','username=?','encryption=?','from_email=?','from_name=?'];
    const vals = [host, port, username, encryption, from_email || '', from_name || 'Task Manager'];
    if (password) { sets.push('password=?'); vals.push(password); }
    vals.push(existing[0].id);
    await pool.query(`UPDATE smtp_config SET ${sets.join(',')} WHERE id=?`, vals);
  } else {
    await pool.query('INSERT INTO smtp_config (host, port, username, password, encryption, from_email, from_name) VALUES (?,?,?,?,?,?,?)', [host, port, username, password || '', encryption, from_email || '', from_name || 'Task Manager']);
  }
  res.json({ success: true });
}));

app.post('/api/admin/smtp/test', auth, adminOnly, wrap(async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM smtp_config LIMIT 1');
  if (!rows.length) return res.status(400).json({ error: 'SMTP not configured yet' });
  const cfg = rows[0];
  const transporter = nodemailer.createTransport({ host: cfg.host, port: cfg.port, secure: cfg.encryption === 'ssl', auth: { user: cfg.username, pass: cfg.password } });
  await transporter.verify();
  res.json({ success: true, message: 'SMTP connection verified successfully!' });
}));

app.get('/api/admin/activity', auth, adminOnly, wrap(async (req, res) => {
  const [rows] = await pool.query('SELECT al.*, u.username, u.full_name FROM activity_log al LEFT JOIN users u ON al.user_id=u.id ORDER BY al.created_at DESC LIMIT 100');
  res.json(rows);
}));

// ── EMAIL HELPER ──────────────────────────────────────────
async function sendMentionEmail(userId, mentionedBy, taskTitle, taskId) {
  const [smtpRows] = await pool.query('SELECT * FROM smtp_config LIMIT 1');
  if (!smtpRows.length) return;
  const [userRows] = await pool.query('SELECT email, full_name FROM users WHERE id=?', [userId]);
  if (!userRows.length) return;
  const cfg = smtpRows[0], user = userRows[0];
  const t = nodemailer.createTransport({ host: cfg.host, port: cfg.port, secure: cfg.encryption === 'ssl', auth: { user: cfg.username, pass: cfg.password } });
  await t.sendMail({ from: `"${cfg.from_name}" <${cfg.from_email || cfg.username}>`, to: user.email, subject: `You were mentioned in: ${taskTitle}`, html: `<p>Hi ${user.full_name}, <strong>@${mentionedBy}</strong> mentioned you in "<strong>${taskTitle}</strong>".</p>` });
}

app.use((err, req, res, next) => res.status(500).json({ error: 'Internal server error' }));

// ── START ─────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
setupDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log(`Synapse API running on port ${PORT}`));
});
