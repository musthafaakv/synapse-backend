require('dotenv').config();
const express    = require('express');
const mysql      = require('mysql2/promise');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(cors({ origin:'*', methods:['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders:['Content-Type','Authorization'] }));
app.options('*', cors());
app.get('/',       (req,res) => res.json({ status:'Synapse API OK' }));
app.get('/health', (req,res) => res.json({ status:'ok' }));

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

/* ── Auto-create all tables ── */
async function setupDatabase() {
  try {
    const conn = await pool.getConnection();
    console.log('MySQL connected');

    await conn.query(`CREATE TABLE IF NOT EXISTS users (
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
    )`);

    await conn.query(`CREATE TABLE IF NOT EXISTS tasks (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      status ENUM('todo','in_progress','review','done') DEFAULT 'todo',
      priority ENUM('low','medium','high','urgent') DEFAULT 'medium',
      creator_id INT NOT NULL,
      due_date DATE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await conn.query(`CREATE TABLE IF NOT EXISTS task_assignees (
      task_id INT NOT NULL,
      user_id INT NOT NULL,
      assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (task_id, user_id),
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await conn.query(`CREATE TABLE IF NOT EXISTS tags (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(50) NOT NULL UNIQUE,
      color VARCHAR(7) DEFAULT '#6366F1'
    )`);

    await conn.query(`CREATE TABLE IF NOT EXISTS task_tags (
      task_id INT NOT NULL,
      tag_id INT NOT NULL,
      PRIMARY KEY (task_id, tag_id),
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY (tag_id)  REFERENCES tags(id)  ON DELETE CASCADE
    )`);

    await conn.query(`CREATE TABLE IF NOT EXISTS notifications (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      task_id INT NOT NULL,
      triggered_by_id INT NOT NULL,
      type ENUM('assigned','mentioned') DEFAULT 'mentioned',
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id)         REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (task_id)         REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY (triggered_by_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await conn.query(`CREATE TABLE IF NOT EXISTS smtp_config (
      id INT AUTO_INCREMENT PRIMARY KEY,
      host VARCHAR(255) NOT NULL,
      port INT NOT NULL DEFAULT 587,
      username VARCHAR(255) NOT NULL,
      password VARCHAR(255) NOT NULL,
      encryption ENUM('none','ssl','tls') DEFAULT 'tls',
      from_email VARCHAR(255),
      from_name VARCHAR(100),
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`);

    await conn.query(`CREATE TABLE IF NOT EXISTS activity_log (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      action VARCHAR(100) NOT NULL,
      entity_type VARCHAR(50),
      entity_id INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )`);

    // Seed admin
    const hash = await bcrypt.hash('Admin@1234', 10);
    await conn.query(`INSERT IGNORE INTO users (username,email,password_hash,full_name,role,avatar_color)
      VALUES ('admin','admin@company.com',?,'System Admin','admin','#7C5CFC')`, [hash]);

    // Seed tags
    for (const [n,c] of [['bug','#F87171'],['feature','#5B8AF0'],['design','#8B5CF6'],['backend','#FBBF24'],['frontend','#34D399'],['urgent','#F87171']]) {
      await conn.query('INSERT IGNORE INTO tags (name,color) VALUES (?,?)', [n,c]);
    }

    conn.release();
    console.log('Database ready');
  } catch (e) { console.error('DB setup error:', e.message); }
}

const JWT_SECRET = process.env.JWT_SECRET || 'synapse_secret_change_me';

const auth = async (req,res,next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error:'No token provided' });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error:'Invalid token' }); }
};

const adminOnly = (req,res,next) => {
  if (req.user?.role !== 'admin') return res.status(403).json({ error:'Admin only' });
  next();
};

const wrap = fn => (req,res,next) =>
  Promise.resolve(fn(req,res,next)).catch(err => {
    console.error('Route error:', err.message);
    res.status(500).json({ error: err.message||'Server error' });
  });

/* ── AUTH ── */
app.post('/api/auth/login', wrap(async (req,res) => {
  const { username, password } = req.body;
  if (!username||!password) return res.status(400).json({ error:'Username and password required' });
  const [rows] = await pool.query('SELECT * FROM users WHERE username=? AND is_active=1', [username]);
  if (!rows.length) return res.status(401).json({ error:'Invalid credentials' });
  const user = rows[0];
  if (!await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error:'Invalid credentials' });
  const token = jwt.sign({ id:user.id, username:user.username, role:user.role }, JWT_SECRET, { expiresIn:'8h' });
  pool.query('INSERT INTO activity_log (user_id,action,entity_type) VALUES (?,?,?)', [user.id,'login','user']).catch(()=>{});
  res.json({ token, user:{ id:user.id, username:user.username, email:user.email, full_name:user.full_name, role:user.role, avatar_color:user.avatar_color } });
}));

/* ── USERS ── */
app.get('/api/users', auth, wrap(async (req,res) => {
  const [rows] = await pool.query('SELECT id,username,email,full_name,role,avatar_color,is_active,created_at FROM users ORDER BY full_name');
  res.json(rows);
}));

app.post('/api/users', auth, adminOnly, wrap(async (req,res) => {
  const { username,email,password,full_name,role } = req.body;
  if (!username||!email||!password) return res.status(400).json({ error:'Missing required fields' });
  const hash = await bcrypt.hash(password,10);
  const colors = ['#3B82F6','#10B981','#F59E0B','#8B5CF6','#EC4899','#06B6D4'];
  const color = colors[Math.floor(Math.random()*colors.length)];
  const [r] = await pool.query('INSERT INTO users (username,email,password_hash,full_name,role,avatar_color) VALUES (?,?,?,?,?,?)', [username,email,hash,full_name||username,role||'member',color]);
  res.json({ id:r.insertId, username, email, full_name, role:role||'member', avatar_color:color });
}));

app.put('/api/users/:id', auth, adminOnly, wrap(async (req,res) => {
  const { email,full_name,role,is_active,password } = req.body;
  const u=[],v=[];
  if (email     !==undefined) { u.push('email=?');         v.push(email); }
  if (full_name !==undefined) { u.push('full_name=?');     v.push(full_name); }
  if (role      !==undefined) { u.push('role=?');          v.push(role); }
  if (is_active !==undefined) { u.push('is_active=?');     v.push(is_active?1:0); }
  if (password)               { u.push('password_hash=?'); v.push(await bcrypt.hash(password,10)); }
  if (!u.length) return res.status(400).json({ error:'Nothing to update' });
  v.push(req.params.id);
  await pool.query(`UPDATE users SET ${u.join(',')} WHERE id=?`, v);
  res.json({ success:true });
}));

app.delete('/api/users/:id', auth, adminOnly, wrap(async (req,res) => {
  if (parseInt(req.params.id)===req.user.id) return res.status(400).json({ error:'Cannot deactivate yourself' });
  await pool.query('UPDATE users SET is_active=0 WHERE id=?', [req.params.id]);
  res.json({ success:true });
}));

/* ── TASKS ── */
// Users only see tasks they created OR are assigned to
app.get('/api/tasks', auth, wrap(async (req,res) => {
  const { status, tag } = req.query;
  const userId = req.user.id;
  const isAdmin = req.user.role === 'admin';

  let sql = `
    SELECT DISTINCT t.*,
      u1.username as creator_username, u1.full_name as creator_name, u1.avatar_color as creator_color,
      GROUP_CONCAT(DISTINCT CONCAT(tg.name,'::',tg.color) ORDER BY tg.name SEPARATOR '||') as tags_raw,
      GROUP_CONCAT(DISTINCT CONCAT(u2.id,'::',IFNULL(u2.full_name,''),'::',u2.username,'::',IFNULL(u2.avatar_color,'#3B82F6')) ORDER BY u2.full_name SEPARATOR '||') as assignees_raw
    FROM tasks t
    LEFT JOIN users u1 ON t.creator_id=u1.id
    LEFT JOIN task_assignees ta ON t.id=ta.task_id
    LEFT JOIN users u2 ON ta.user_id=u2.id
    LEFT JOIN task_tags tt ON t.id=tt.task_id
    LEFT JOIN tags tg ON tt.tag_id=tg.id
    WHERE (
  `;

  // Admins see all tasks; regular users only see their own
  const params = [];
  if (isAdmin) {
    sql += '1=1';
  } else {
    sql += 't.creator_id=? OR t.id IN (SELECT task_id FROM task_assignees WHERE user_id=?)';
    params.push(userId, userId);
  }
  sql += ')';

  if (status) { sql += ' AND t.status=?'; params.push(status); }
  if (tag)    { sql += ' AND t.id IN (SELECT tt2.task_id FROM task_tags tt2 JOIN tags tg2 ON tt2.tag_id=tg2.id WHERE tg2.name=?)'; params.push(tag); }
  sql += ' GROUP BY t.id ORDER BY t.created_at DESC';

  const [rows] = await pool.query(sql, params);
  res.json(rows.map(r => ({
    ...r,
    tags: r.tags_raw ? r.tags_raw.split('||').map(t => { const [name,color]=t.split('::'); return {name,color}; }) : [],
    assignees: r.assignees_raw ? r.assignees_raw.split('||').map(a => { const [id,full_name,username,avatar_color]=a.split('::'); return {id:parseInt(id),full_name,username,avatar_color}; }) : []
  })));
}));

app.post('/api/tasks', auth, wrap(async (req,res) => {
  const { title, description, status, priority, assignee_ids, due_date, tags, mentions } = req.body;
  if (!title) return res.status(400).json({ error:'Title is required' });

  const [result] = await pool.query(
    'INSERT INTO tasks (title,description,status,priority,creator_id,due_date) VALUES (?,?,?,?,?,?)',
    [title, description||'', status||'todo', priority||'medium', req.user.id, due_date||null]
  );
  const taskId = result.insertId;
  const assigneeList = Array.isArray(assignee_ids) ? assignee_ids.map(Number) : [];

  // Save all assignees
  for (const uid of assigneeList) {
    try { await pool.query('INSERT IGNORE INTO task_assignees (task_id,user_id) VALUES (?,?)', [taskId, uid]); } catch {}
  }

  // Save tags
  if (Array.isArray(tags) && tags.length) {
    for (const tagName of tags) {
      try {
        let [tRows] = await pool.query('SELECT id FROM tags WHERE name=?', [tagName]);
        const tagId = tRows.length ? tRows[0].id : (await pool.query('INSERT INTO tags (name) VALUES (?)', [tagName]))[0].insertId;
        await pool.query('INSERT IGNORE INTO task_tags VALUES (?,?)', [taskId, tagId]);
      } catch {}
    }
  }

  // Notify all assignees (except creator)
  for (const uid of assigneeList) {
    if (uid !== req.user.id) {
      try {
        await pool.query('INSERT INTO notifications (user_id,task_id,triggered_by_id,type) VALUES (?,?,?,?)', [uid, taskId, req.user.id, 'assigned']);
        sendEmail(uid, req.user.username, title, 'assigned').catch(()=>{});
      } catch {}
    }
  }

  // Notify @mentioned users in description (if not already notified as assignee)
  if (Array.isArray(mentions) && mentions.length) {
    for (const uid of mentions) {
      if (uid !== req.user.id && !assigneeList.includes(uid)) {
        try {
          await pool.query('INSERT INTO notifications (user_id,task_id,triggered_by_id,type) VALUES (?,?,?,?)', [uid, taskId, req.user.id, 'mentioned']);
          sendEmail(uid, req.user.username, title, 'mentioned').catch(()=>{});
        } catch {}
      }
    }
  }

  pool.query('INSERT INTO activity_log (user_id,action,entity_type,entity_id) VALUES (?,?,?,?)', [req.user.id,'create_task','task',taskId]).catch(()=>{});
  res.json({ id:taskId });
}));

app.put('/api/tasks/:id', auth, wrap(async (req,res) => {
  const { title, description, status, priority, assignee_ids, due_date, mentions } = req.body;
  const taskId = req.params.id;

  await pool.query(
    'UPDATE tasks SET title=?,description=?,status=?,priority=?,due_date=? WHERE id=?',
    [title, description||'', status, priority, due_date||null, taskId]
  );

  if (Array.isArray(assignee_ids)) {
    const newList = assignee_ids.map(Number);
    // Find newly added assignees to notify them
    const [oldRows] = await pool.query('SELECT user_id FROM task_assignees WHERE task_id=?', [taskId]);
    const oldList = oldRows.map(r => r.user_id);
    const newlyAdded = newList.filter(id => !oldList.includes(id));

    // Replace assignees
    await pool.query('DELETE FROM task_assignees WHERE task_id=?', [taskId]);
    for (const uid of newList) {
      try { await pool.query('INSERT IGNORE INTO task_assignees (task_id,user_id) VALUES (?,?)', [taskId, uid]); } catch {}
    }

    // Notify newly added assignees
    for (const uid of newlyAdded) {
      if (uid !== req.user.id) {
        try {
          await pool.query('INSERT INTO notifications (user_id,task_id,triggered_by_id,type) VALUES (?,?,?,?)', [uid, taskId, req.user.id, 'assigned']);
          sendEmail(uid, req.user.username, title, 'assigned').catch(()=>{});
        } catch {}
      }
    }
  }

  // Notify @mentioned users
  if (Array.isArray(mentions) && mentions.length) {
    for (const uid of mentions) {
      if (uid !== req.user.id) {
        try {
          await pool.query('INSERT INTO notifications (user_id,task_id,triggered_by_id,type) VALUES (?,?,?,?)', [uid, taskId, req.user.id, 'mentioned']);
          sendEmail(uid, req.user.username, title, 'mentioned').catch(()=>{});
        } catch {}
      }
    }
  }

  pool.query('INSERT INTO activity_log (user_id,action,entity_type,entity_id) VALUES (?,?,?,?)', [req.user.id,'update_task','task',taskId]).catch(()=>{});
  res.json({ success:true });
}));

app.delete('/api/tasks/:id', auth, wrap(async (req,res) => {
  await pool.query('DELETE FROM tasks WHERE id=?', [req.params.id]);
  res.json({ success:true });
}));

/* ── TAGS ── */
app.get('/api/tags', auth, wrap(async (req,res) => {
  const [rows] = await pool.query('SELECT * FROM tags ORDER BY name');
  res.json(rows);
}));

/* ── NOTIFICATIONS ── */
app.get('/api/notifications', auth, wrap(async (req,res) => {
  const [rows] = await pool.query(`
    SELECT n.*, t.title as task_title, u.username as triggered_by, u.full_name as triggered_by_name
    FROM notifications n
    JOIN tasks t ON n.task_id=t.id
    JOIN users u ON n.triggered_by_id=u.id
    WHERE n.user_id=?
    ORDER BY n.created_at DESC LIMIT 30
  `, [req.user.id]);
  res.json(rows);
}));

app.put('/api/notifications/:id/read', auth, wrap(async (req,res) => {
  await pool.query('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
  res.json({ success:true });
}));

app.put('/api/notifications/read-all', auth, wrap(async (req,res) => {
  await pool.query('UPDATE notifications SET is_read=1 WHERE user_id=?', [req.user.id]);
  res.json({ success:true });
}));

/* ── SMTP ── */
app.get('/api/admin/smtp', auth, adminOnly, wrap(async (req,res) => {
  const [rows] = await pool.query('SELECT id,host,port,username,encryption,from_email,from_name FROM smtp_config LIMIT 1');
  res.json(rows[0]||{});
}));

app.put('/api/admin/smtp', auth, adminOnly, wrap(async (req,res) => {
  const { host,port,username,password,encryption,from_email,from_name } = req.body;
  const [ex] = await pool.query('SELECT id FROM smtp_config LIMIT 1');
  if (ex.length) {
    const sets=['host=?','port=?','username=?','encryption=?','from_email=?','from_name=?'];
    const vals=[host,port,username,encryption,from_email||'',from_name||'Task Manager'];
    if (password) { sets.push('password=?'); vals.push(password); }
    vals.push(ex[0].id);
    await pool.query(`UPDATE smtp_config SET ${sets.join(',')} WHERE id=?`, vals);
  } else {
    await pool.query('INSERT INTO smtp_config (host,port,username,password,encryption,from_email,from_name) VALUES (?,?,?,?,?,?,?)', [host,port,username,password||'',encryption,from_email||'',from_name||'Task Manager']);
  }
  res.json({ success:true });
}));

app.post('/api/admin/smtp/test', auth, adminOnly, wrap(async (req,res) => {
  const [rows] = await pool.query('SELECT * FROM smtp_config LIMIT 1');
  if (!rows.length) return res.status(400).json({ error:'SMTP not configured yet' });
  const cfg = rows[0];
  const t = nodemailer.createTransport({ host:cfg.host, port:cfg.port, secure:cfg.encryption==='ssl', auth:{ user:cfg.username, pass:cfg.password } });
  await t.verify();
  res.json({ success:true, message:'SMTP connection verified!' });
}));

app.get('/api/admin/activity', auth, adminOnly, wrap(async (req,res) => {
  const [rows] = await pool.query('SELECT al.*,u.username,u.full_name FROM activity_log al LEFT JOIN users u ON al.user_id=u.id ORDER BY al.created_at DESC LIMIT 100');
  res.json(rows);
}));

/* ── Email helper ── */
async function sendEmail(userId, triggeredBy, taskTitle, type) {
  const [smtpRows] = await pool.query('SELECT * FROM smtp_config LIMIT 1');
  if (!smtpRows.length) return;
  const [userRows] = await pool.query('SELECT email,full_name FROM users WHERE id=?', [userId]);
  if (!userRows.length) return;
  const cfg = smtpRows[0], user = userRows[0];
  const subject = type==='assigned' ? `You were assigned to: ${taskTitle}` : `You were mentioned in: ${taskTitle}`;
  const body = type==='assigned'
    ? `<p>Hi ${user.full_name},</p><p><strong>@${triggeredBy}</strong> assigned you to the task <strong>"${taskTitle}"</strong>.</p>`
    : `<p>Hi ${user.full_name},</p><p><strong>@${triggeredBy}</strong> mentioned you in <strong>"${taskTitle}"</strong>.</p>`;
  const t = nodemailer.createTransport({ host:cfg.host, port:cfg.port, secure:cfg.encryption==='ssl', auth:{ user:cfg.username, pass:cfg.password } });
  await t.sendMail({ from:`"${cfg.from_name}" <${cfg.from_email||cfg.username}>`, to:user.email, subject, html:body });
}

app.use((err,req,res,next) => res.status(500).json({ error:'Internal server error' }));

const PORT = process.env.PORT || 3001;
setupDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log(`Synapse API on port ${PORT}`));
});
