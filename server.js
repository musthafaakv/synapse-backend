// ============================================================
// Task Management System - Express.js Backend
// ============================================================
// Setup: npm install, configure .env, run node server.js
// ============================================================

require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));

// ── Database pool ─────────────────────────────────────────
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'taskmanager',
  waitForConnections: true,
  connectionLimit: 10,
});

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_production';

// ── Auth Middleware ───────────────────────────────────────
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
};

// ── Auth Routes ───────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await pool.query(
    'SELECT * FROM users WHERE username = ? AND is_active = 1', [username]
  );
  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
  const user = rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET, { expiresIn: '8h' }
  );
  await pool.query(
    'INSERT INTO activity_log (user_id, action, entity_type) VALUES (?, ?, ?)',
    [user.id, 'login', 'user']
  );
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, full_name: user.full_name, role: user.role, avatar_color: user.avatar_color } });
});

// ── User Routes ───────────────────────────────────────────
app.get('/api/users', auth, async (req, res) => {
  const [rows] = await pool.query(
    'SELECT id, username, email, full_name, role, avatar_color, is_active, created_at FROM users ORDER BY full_name'
  );
  res.json(rows);
});

app.post('/api/users', auth, adminOnly, async (req, res) => {
  const { username, email, password, full_name, role } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const colors = ['#3B82F6','#10B981','#F59E0B','#8B5CF6','#EC4899','#06B6D4'];
  const color = colors[Math.floor(Math.random() * colors.length)];
  const [result] = await pool.query(
    'INSERT INTO users (username, email, password_hash, full_name, role, avatar_color) VALUES (?,?,?,?,?,?)',
    [username, email, hash, full_name, role || 'member', color]
  );
  res.json({ id: result.insertId, username, email, full_name, role: role || 'member', avatar_color: color });
});

app.put('/api/users/:id', auth, adminOnly, async (req, res) => {
  const { email, full_name, role, is_active, password } = req.body;
  const updates = [];
  const vals = [];
  if (email !== undefined) { updates.push('email=?'); vals.push(email); }
  if (full_name !== undefined) { updates.push('full_name=?'); vals.push(full_name); }
  if (role !== undefined) { updates.push('role=?'); vals.push(role); }
  if (is_active !== undefined) { updates.push('is_active=?'); vals.push(is_active); }
  if (password) { updates.push('password_hash=?'); vals.push(await bcrypt.hash(password, 10)); }
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  vals.push(req.params.id);
  await pool.query(`UPDATE users SET ${updates.join(',')} WHERE id=?`, vals);
  res.json({ success: true });
});

app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  if (parseInt(req.params.id) === req.user.id)
    return res.status(400).json({ error: 'Cannot delete yourself' });
  await pool.query('UPDATE users SET is_active=0 WHERE id=?', [req.params.id]);
  res.json({ success: true });
});

// ── Task Routes ───────────────────────────────────────────
app.get('/api/tasks', auth, async (req, res) => {
  const { status, assignee, tag } = req.query;
  let sql = `
    SELECT t.*, 
      u1.username as creator_username, u1.full_name as creator_name, u1.avatar_color as creator_color,
      u2.username as assignee_username, u2.full_name as assignee_name, u2.avatar_color as assignee_color,
      GROUP_CONCAT(DISTINCT tg.name ORDER BY tg.name SEPARATOR ',') as tag_names,
      GROUP_CONCAT(DISTINCT tg.color ORDER BY tg.name SEPARATOR ',') as tag_colors
    FROM tasks t
    LEFT JOIN users u1 ON t.creator_id = u1.id
    LEFT JOIN users u2 ON t.assignee_id = u2.id
    LEFT JOIN task_tags tt ON t.id = tt.task_id
    LEFT JOIN tags tg ON tt.tag_id = tg.id
    WHERE 1=1
  `;
  const params = [];
  if (status) { sql += ' AND t.status=?'; params.push(status); }
  if (assignee) { sql += ' AND t.assignee_id=?'; params.push(assignee); }
  if (tag) {
    sql += ' AND t.id IN (SELECT tt2.task_id FROM task_tags tt2 JOIN tags tg2 ON tt2.tag_id=tg2.id WHERE tg2.name=?)';
    params.push(tag);
  }
  sql += ' GROUP BY t.id ORDER BY t.created_at DESC';
  const [rows] = await pool.query(sql, params);
  res.json(rows.map(r => ({
    ...r,
    tags: r.tag_names ? r.tag_names.split(',').map((n, i) => ({ name: n, color: r.tag_colors?.split(',')[i] })) : []
  })));
});

app.post('/api/tasks', auth, async (req, res) => {
  const { title, description, status, priority, assignee_id, due_date, tags, mentions } = req.body;
  const [result] = await pool.query(
    'INSERT INTO tasks (title, description, status, priority, creator_id, assignee_id, due_date) VALUES (?,?,?,?,?,?,?)',
    [title, description, status || 'todo', priority || 'medium', req.user.id, assignee_id || null, due_date || null]
  );
  const taskId = result.insertId;

  // Handle tags
  if (tags?.length) {
    for (const tagName of tags) {
      let [tRows] = await pool.query('SELECT id FROM tags WHERE name=?', [tagName]);
      let tagId;
      if (!tRows.length) {
        const [ins] = await pool.query('INSERT INTO tags (name) VALUES (?)', [tagName]);
        tagId = ins.insertId;
      } else { tagId = tRows[0].id; }
      await pool.query('INSERT IGNORE INTO task_tags VALUES (?,?)', [taskId, tagId]);
    }
  }

  // Handle @mentions — log + send email if SMTP configured
  if (mentions?.length) {
    for (const userId of mentions) {
      await pool.query(
        'INSERT INTO task_mentions (task_id, mentioned_user_id, mentioned_by_id) VALUES (?,?,?)',
        [taskId, userId, req.user.id]
      );
      await sendMentionEmail(userId, req.user.username, title, taskId);
    }
  }

  await pool.query('INSERT INTO activity_log (user_id, action, entity_type, entity_id) VALUES (?,?,?,?)',
    [req.user.id, 'create_task', 'task', taskId]);
  res.json({ id: taskId });
});

app.put('/api/tasks/:id', auth, async (req, res) => {
  const { title, description, status, priority, assignee_id, due_date } = req.body;
  await pool.query(
    'UPDATE tasks SET title=?, description=?, status=?, priority=?, assignee_id=?, due_date=? WHERE id=?',
    [title, description, status, priority, assignee_id || null, due_date || null, req.params.id]
  );
  await pool.query('INSERT INTO activity_log (user_id, action, entity_type, entity_id) VALUES (?,?,?,?)',
    [req.user.id, 'update_task', 'task', req.params.id]);
  res.json({ success: true });
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM tasks WHERE id=?', [req.params.id]);
  res.json({ success: true });
});

// ── Tags Routes ───────────────────────────────────────────
app.get('/api/tags', auth, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM tags ORDER BY name');
  res.json(rows);
});

// ── Notifications ─────────────────────────────────────────
app.get('/api/notifications', auth, async (req, res) => {
  const [rows] = await pool.query(`
    SELECT tm.*, t.title as task_title, u.username as mentioned_by
    FROM task_mentions tm
    JOIN tasks t ON tm.task_id = t.id
    JOIN users u ON tm.mentioned_by_id = u.id
    WHERE tm.mentioned_user_id = ?
    ORDER BY tm.created_at DESC LIMIT 20
  `, [req.user.id]);
  res.json(rows);
});

app.put('/api/notifications/:id/read', auth, async (req, res) => {
  await pool.query('UPDATE task_mentions SET is_read=1 WHERE id=? AND mentioned_user_id=?',
    [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ── SMTP Configuration ────────────────────────────────────
app.get('/api/admin/smtp', auth, adminOnly, async (req, res) => {
  const [rows] = await pool.query('SELECT id, host, port, username, encryption, from_email, from_name FROM smtp_config LIMIT 1');
  res.json(rows[0] || {});
});

app.put('/api/admin/smtp', auth, adminOnly, async (req, res) => {
  const { host, port, username, password, encryption, from_email, from_name } = req.body;
  const [existing] = await pool.query('SELECT id FROM smtp_config LIMIT 1');
  if (existing.length) {
    const sets = ['host=?','port=?','username=?','encryption=?','from_email=?','from_name=?'];
    const vals = [host, port, username, encryption, from_email, from_name];
    if (password) { sets.push('password=?'); vals.push(password); }
    vals.push(existing[0].id);
    await pool.query(`UPDATE smtp_config SET ${sets.join(',')} WHERE id=?`, vals);
  } else {
    await pool.query(
      'INSERT INTO smtp_config (host, port, username, password, encryption, from_email, from_name) VALUES (?,?,?,?,?,?,?)',
      [host, port, username, password, encryption, from_email, from_name]
    );
  }
  res.json({ success: true });
});

app.post('/api/admin/smtp/test', auth, adminOnly, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM smtp_config LIMIT 1');
  if (!rows.length) return res.status(400).json({ error: 'SMTP not configured' });
  const cfg = rows[0];
  try {
    const transporter = nodemailer.createTransport({
      host: cfg.host, port: cfg.port, secure: cfg.encryption === 'ssl',
      auth: { user: cfg.username, pass: cfg.password },
      tls: cfg.encryption === 'none' ? { rejectUnauthorized: false } : undefined
    });
    await transporter.verify();
    res.json({ success: true, message: 'SMTP connection verified' });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── Admin: Activity Log ───────────────────────────────────
app.get('/api/admin/activity', auth, adminOnly, async (req, res) => {
  const [rows] = await pool.query(`
    SELECT al.*, u.username, u.full_name FROM activity_log al
    LEFT JOIN users u ON al.user_id = u.id
    ORDER BY al.created_at DESC LIMIT 100
  `);
  res.json(rows);
});

// ── Helper: Send mention email ────────────────────────────
async function sendMentionEmail(userId, mentionedBy, taskTitle, taskId) {
  try {
    const [smtpRows] = await pool.query('SELECT * FROM smtp_config LIMIT 1');
    if (!smtpRows.length) return;
    const [userRows] = await pool.query('SELECT email, full_name FROM users WHERE id=?', [userId]);
    if (!userRows.length) return;
    const cfg = smtpRows[0];
    const user = userRows[0];
    const transporter = nodemailer.createTransport({
      host: cfg.host, port: cfg.port, secure: cfg.encryption === 'ssl',
      auth: { user: cfg.username, pass: cfg.password }
    });
    await transporter.sendMail({
      from: `"${cfg.from_name || 'Task Manager'}" <${cfg.from_email || cfg.username}>`,
      to: user.email,
      subject: `You were mentioned in: ${taskTitle}`,
      html: `<p>Hi ${user.full_name},</p>
             <p><strong>${mentionedBy}</strong> mentioned you in task <strong>"${taskTitle}"</strong>.</p>
             <p>Log in to view the task details.</p>`
    });
  } catch { /* Silent fail - email is non-critical */ }
}

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
