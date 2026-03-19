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
app.get('/',       (_,res) => res.json({ status:'Synapse API OK' }));
app.get('/health', (_,res) => res.json({ status:'ok' }));

const pool = mysql.createPool({
  host: process.env.DB_HOST||'localhost', port: parseInt(process.env.DB_PORT)||3306,
  user: process.env.DB_USER||'root',     password: process.env.DB_PASS||'',
  database: process.env.DB_NAME||'railway',
  waitForConnections:true, connectionLimit:10, connectTimeout:20000,
});

/* ══════════════════════════════════════
   DATABASE SETUP
══════════════════════════════════════ */
async function setupDatabase(){
  try{
    const c = await pool.getConnection();
    console.log('✅ MySQL connected');

    await c.query(`CREATE TABLE IF NOT EXISTS users(
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      email VARCHAR(100) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      full_name VARCHAR(100),
      role ENUM('admin','supervisor','member') DEFAULT 'member',
      avatar_color VARCHAR(7) DEFAULT '#3B82F6',
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)`);

    await c.query(`CREATE TABLE IF NOT EXISTS supervisor_permissions(
      user_id INT PRIMARY KEY,
      can_approve_attendance BOOLEAN DEFAULT TRUE,
      can_view_all_attendance BOOLEAN DEFAULT TRUE,
      can_edit_tasks BOOLEAN DEFAULT TRUE,
      can_create_tasks BOOLEAN DEFAULT FALSE,
      can_view_all_tasks BOOLEAN DEFAULT TRUE,
      can_manage_holidays BOOLEAN DEFAULT FALSE,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS tasks(
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      status ENUM('todo','in_progress','review','done') DEFAULT 'todo',
      priority ENUM('low','medium','high','urgent') DEFAULT 'medium',
      creator_id INT NOT NULL,
      due_date DATE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS task_assignees(
      task_id INT NOT NULL, user_id INT NOT NULL,
      assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(task_id,user_id),
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`);

    /* task_revoked: users who have moved-away lose all access */
    await c.query(`CREATE TABLE IF NOT EXISTS task_revoked(
      task_id INT NOT NULL, user_id INT NOT NULL,
      revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(task_id,user_id),
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS tags(
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(50) NOT NULL UNIQUE,
      color VARCHAR(7) DEFAULT '#6366F1')`);

    await c.query(`CREATE TABLE IF NOT EXISTS task_tags(
      task_id INT NOT NULL, tag_id INT NOT NULL, PRIMARY KEY(task_id,tag_id),
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(tag_id)  REFERENCES tags(id)  ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS notifications(
      id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL,
      task_id INT NOT NULL, triggered_by_id INT NOT NULL,
      type VARCHAR(50) DEFAULT 'assigned',
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(triggered_by_id) REFERENCES users(id) ON DELETE CASCADE)`);

    /* task_history: immutable timeline of every action on a task */
    await c.query(`CREATE TABLE IF NOT EXISTS task_history(
      id INT AUTO_INCREMENT PRIMARY KEY,
      task_id INT NOT NULL,
      user_id INT NOT NULL,
      action VARCHAR(50) NOT NULL,
      field VARCHAR(50),
      old_value TEXT,
      new_value TEXT,
      comment TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS smtp_config(
      id INT AUTO_INCREMENT PRIMARY KEY,
      host VARCHAR(255) NOT NULL, port INT NOT NULL DEFAULT 587,
      username VARCHAR(255) NOT NULL, password VARCHAR(255) NOT NULL,
      encryption ENUM('none','ssl','tls') DEFAULT 'tls',
      from_email VARCHAR(255), from_name VARCHAR(100),
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)`);

    await c.query(`CREATE TABLE IF NOT EXISTS activity_log(
      id INT AUTO_INCREMENT PRIMARY KEY, user_id INT,
      action VARCHAR(100) NOT NULL, entity_type VARCHAR(50), entity_id INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL)`);

    await c.query(`CREATE TABLE IF NOT EXISTS attendance(
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL, work_date DATE NOT NULL,
      clock_in DATETIME, clock_out DATETIME,
      clock_in_status ENUM('pending','approved','rejected') DEFAULT 'pending',
      clock_out_status ENUM('pending','approved','rejected','na') DEFAULT 'na',
      approved_clock_in DATETIME, approved_clock_out DATETIME,
      approved_by INT, approved_at TIMESTAMP NULL,
      note TEXT, admin_note TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_user_date(user_id,work_date),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(approved_by) REFERENCES users(id) ON DELETE SET NULL)`);

    await c.query(`CREATE TABLE IF NOT EXISTS holidays(
      id INT AUTO_INCREMENT PRIMARY KEY,
      holiday_date DATE NOT NULL UNIQUE, name VARCHAR(100) NOT NULL,
      type ENUM('sunday','public','manual') DEFAULT 'manual',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

    /* ── Migrations for existing installs ── */
    await c.query(`ALTER TABLE users MODIFY COLUMN role ENUM('admin','supervisor','member') DEFAULT 'member'`).catch(()=>{});
    await c.query(`ALTER TABLE notifications MODIFY COLUMN type VARCHAR(50) DEFAULT 'assigned'`).catch(()=>{});
    /* Migrate old task_history schema if columns differ */
    await c.query(`ALTER TABLE task_history ADD COLUMN IF NOT EXISTS user_id INT NOT NULL DEFAULT 1`).catch(()=>{});
    await c.query(`ALTER TABLE task_history ADD COLUMN IF NOT EXISTS comment TEXT`).catch(()=>{});
    await c.query(`ALTER TABLE task_history MODIFY COLUMN action VARCHAR(100) NOT NULL`).catch(()=>{});
    /* rename changed_by_id → user_id if old schema exists */
    await c.query(`ALTER TABLE task_history CHANGE COLUMN changed_by_id user_id INT NOT NULL`).catch(()=>{});

    /* Seed */
    const hash = await bcrypt.hash('Admin@1234',10);
    await c.query(`INSERT IGNORE INTO users(username,email,password_hash,full_name,role,avatar_color)
      VALUES('admin','admin@company.com',?,'System Admin','admin','#7C5CFC')`,[hash]);
    for(const[n,cl] of [['bug','#F87171'],['feature','#5B8AF0'],['design','#8B5CF6'],['backend','#FBBF24'],['frontend','#34D399'],['urgent','#F87171']])
      await c.query('INSERT IGNORE INTO tags(name,color) VALUES(?,?)',[n,cl]);

    c.release();
    console.log('✅ Database ready');
  }catch(e){ console.error('DB setup error:',e.message); }
}

/* ══════════════════════════════════════
   MIDDLEWARE
══════════════════════════════════════ */
const JWT_SECRET = process.env.JWT_SECRET||'synapse_secret';

const auth = async(req,res,next)=>{
  try{
    const t = req.headers.authorization?.split(' ')[1];
    if(!t) return res.status(401).json({error:'No token'});
    req.user = jwt.verify(t,JWT_SECRET);
    if(req.user.role==='supervisor'){
      const[perms]=await pool.query('SELECT * FROM supervisor_permissions WHERE user_id=?',[req.user.id]);
      req.user.permissions = perms[0]||{};
    }
    next();
  }catch{ res.status(401).json({error:'Invalid token'}); }
};

const adminOnly=(req,res,next)=>req.user?.role==='admin'?next():res.status(403).json({error:'Admin only'});
const adminOrSupervisor=(req,res,next)=>(req.user?.role==='admin'||req.user?.role==='supervisor')?next():res.status(403).json({error:'Insufficient permissions'});
const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(e=>{console.error(e.message);res.status(500).json({error:e.message||'Server error'});});

const localDate=(d=new Date())=>{const y=d.getFullYear(),m=String(d.getMonth()+1).padStart(2,'0'),dd=String(d.getDate()).padStart(2,'0');return`${y}-${m}-${dd}`;};
const toMySQL=(val)=>{if(!val)return null;if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(val))return val;const d=new Date(val);if(isNaN(d.getTime()))return null;const p=n=>String(n).padStart(2,'0');return`${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;};

/* Check if user has active access to a task (not revoked) */
async function hasTaskAccess(taskId, userId, role){
  if(role==='admin') return 'full';
  // Check revoked first
  const[rev]=await pool.query('SELECT 1 FROM task_revoked WHERE task_id=? AND user_id=?',[taskId,userId]);
  if(rev.length) return 'none';
  // Check if supervisor with view_all_tasks
  if(role==='supervisor') return 'supervisor';
  // Check assignee or creator
  const[rows]=await pool.query(
    'SELECT 1 FROM tasks WHERE id=? AND (creator_id=? OR id IN (SELECT task_id FROM task_assignees WHERE user_id=?))',
    [taskId,userId,userId]);
  return rows.length ? 'member' : 'none';
}

async function logHistory(taskId, userId, action, field, oldVal, newVal, comment){
  await pool.query('INSERT INTO task_history(task_id,user_id,action,field,old_value,new_value,comment) VALUES(?,?,?,?,?,?,?)',
    [taskId,userId,action,field||null,oldVal||null,newVal||null,comment||null]);
}

/* ══════════════════════════════════════
   AUTH
══════════════════════════════════════ */
app.post('/api/auth/login', wrap(async(req,res)=>{
  const{username,password}=req.body;
  if(!username||!password) return res.status(400).json({error:'Username and password required'});
  const[rows]=await pool.query('SELECT * FROM users WHERE username=? AND is_active=1',[username]);
  if(!rows.length) return res.status(401).json({error:'Invalid credentials'});
  const u=rows[0];
  if(!await bcrypt.compare(password,u.password_hash)) return res.status(401).json({error:'Invalid credentials'});
  const token=jwt.sign({id:u.id,username:u.username,role:u.role},JWT_SECRET,{expiresIn:'8h'});
  let permissions={};
  if(u.role==='supervisor'){
    const[perms]=await pool.query('SELECT * FROM supervisor_permissions WHERE user_id=?',[u.id]);
    permissions=perms[0]||{};
  }
  pool.query('INSERT INTO activity_log(user_id,action,entity_type) VALUES(?,?,?)',[u.id,'login','user']).catch(()=>{});
  res.json({token,user:{id:u.id,username:u.username,email:u.email,full_name:u.full_name,role:u.role,avatar_color:u.avatar_color,permissions}});
}));

/* ══════════════════════════════════════
   USERS
══════════════════════════════════════ */
app.get('/api/users', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query(`
    SELECT u.id,u.username,u.email,u.full_name,u.role,u.avatar_color,u.is_active,u.created_at,
      sp.can_approve_attendance,sp.can_view_all_attendance,sp.can_edit_tasks,
      sp.can_create_tasks,sp.can_view_all_tasks,sp.can_manage_holidays
    FROM users u LEFT JOIN supervisor_permissions sp ON u.id=sp.user_id ORDER BY u.full_name`);
  res.json(rows);
}));

app.post('/api/users', auth, adminOnly, wrap(async(req,res)=>{
  const{username,email,password,full_name,role}=req.body;
  if(!username||!email||!password) return res.status(400).json({error:'Missing fields'});
  const hash=await bcrypt.hash(password,10);
  const colors=['#3B82F6','#10B981','#F59E0B','#8B5CF6','#EC4899','#06B6D4'];
  const color=colors[Math.floor(Math.random()*colors.length)];
  const[r]=await pool.query('INSERT INTO users(username,email,password_hash,full_name,role,avatar_color) VALUES(?,?,?,?,?,?)',
    [username,email,hash,full_name||username,role||'member',color]);
  if(role==='supervisor') await pool.query('INSERT IGNORE INTO supervisor_permissions(user_id) VALUES(?)',[r.insertId]);
  res.json({id:r.insertId,username,email,full_name,role:role||'member',avatar_color:color});
}));

app.put('/api/users/:id', auth, adminOnly, wrap(async(req,res)=>{
  const{email,full_name,role,is_active,password,permissions}=req.body;
  const uid=parseInt(req.params.id);
  const u=[],v=[];
  if(email!==undefined){u.push('email=?');v.push(email);}
  if(full_name!==undefined){u.push('full_name=?');v.push(full_name);}
  if(role!==undefined){u.push('role=?');v.push(role);}
  if(is_active!==undefined){u.push('is_active=?');v.push(is_active?1:0);}
  if(password){u.push('password_hash=?');v.push(await bcrypt.hash(password,10));}
  if(u.length){v.push(uid);await pool.query(`UPDATE users SET ${u.join(',')} WHERE id=?`,v);}
  if(role==='supervisor'||permissions){
    const[ex]=await pool.query('SELECT user_id FROM supervisor_permissions WHERE user_id=?',[uid]);
    if(!ex.length) await pool.query('INSERT INTO supervisor_permissions(user_id) VALUES(?)',[uid]);
    if(permissions){
      const pu=[],pv=[];
      for(const f of ['can_approve_attendance','can_view_all_attendance','can_edit_tasks','can_create_tasks','can_view_all_tasks','can_manage_holidays']){
        if(permissions[f]!==undefined){pu.push(`${f}=?`);pv.push(permissions[f]?1:0);}
      }
      if(pu.length){pv.push(uid);await pool.query(`UPDATE supervisor_permissions SET ${pu.join(',')} WHERE user_id=?`,pv);}
    }
  }
  if(role&&role!=='supervisor') await pool.query('DELETE FROM supervisor_permissions WHERE user_id=?',[uid]);
  res.json({success:true});
}));

app.delete('/api/users/:id', auth, adminOnly, wrap(async(req,res)=>{
  if(parseInt(req.params.id)===req.user.id) return res.status(400).json({error:'Cannot deactivate yourself'});
  await pool.query('UPDATE users SET is_active=0 WHERE id=?',[req.params.id]);
  res.json({success:true});
}));

/* ══════════════════════════════════════
   TASKS — Core CRUD
══════════════════════════════════════ */
const parseTask=r=>({...r,
  tags:r.tags_raw?r.tags_raw.split('||').map(t=>{const[name,color]=t.split('::');return{name,color};}): [],
  assignees:r.assignees_raw?r.assignees_raw.split('||').map(a=>{const[id,fn,un,ac]=a.split('::');return{id:parseInt(id),full_name:fn,username:un,avatar_color:ac};}).filter(a=>!isNaN(a.id)):[]
});

/* Task visibility:
   - Admin / supervisor(all): see everything
   - Others: creator OR assignee AND not revoked */
app.get('/api/tasks', auth, wrap(async(req,res)=>{
  const{status,tag}=req.query;
  const isAdmin=req.user.role==='admin';
  const supAll=req.user.role==='supervisor'&&req.user.permissions?.can_view_all_tasks;
  const showAll=isAdmin||supAll;
  const userId=req.user.id;
  let vis=showAll?'1=1':
    `(t.creator_id=? OR t.id IN(SELECT task_id FROM task_assignees WHERE user_id=?))
     AND t.id NOT IN(SELECT task_id FROM task_revoked WHERE user_id=?)`;
  const params=showAll?[]:[userId,userId,userId];
  let extra='';
  if(status){extra+=' AND t.status=?';params.push(status);}
  if(tag){extra+=` AND t.id IN(SELECT tt2.task_id FROM task_tags tt2 JOIN tags tg2 ON tt2.tag_id=tg2.id WHERE tg2.name=?)`;params.push(tag);}
  const sql=`SELECT DISTINCT t.*,
    u1.username as creator_username,u1.full_name as creator_name,u1.avatar_color as creator_color,
    GROUP_CONCAT(DISTINCT CONCAT(tg.name,'::',tg.color) ORDER BY tg.name SEPARATOR '||') as tags_raw,
    GROUP_CONCAT(DISTINCT CONCAT(u2.id,'::',IFNULL(u2.full_name,''),'::',u2.username,'::',IFNULL(u2.avatar_color,'#3B82F6'))
      ORDER BY u2.full_name SEPARATOR '||') as assignees_raw
  FROM tasks t
  LEFT JOIN users u1 ON t.creator_id=u1.id
  LEFT JOIN task_assignees ta ON t.id=ta.task_id
  LEFT JOIN users u2 ON ta.user_id=u2.id
  LEFT JOIN task_tags tt ON t.id=tt.task_id
  LEFT JOIN tags tg ON tt.tag_id=tg.id
  WHERE (${vis}) ${extra}
  GROUP BY t.id ORDER BY t.created_at DESC`;
  const[rows]=await pool.query(sql,params);
  res.json(rows.map(parseTask));
}));

/* Single task with access check */
app.get('/api/tasks/:id', auth, wrap(async(req,res)=>{
  const access=await hasTaskAccess(req.params.id,req.user.id,req.user.role);
  if(access==='none') return res.status(403).json({error:'Access denied'});
  const[rows]=await pool.query(`SELECT DISTINCT t.*,
    u1.username as creator_username,u1.full_name as creator_name,u1.avatar_color as creator_color,
    GROUP_CONCAT(DISTINCT CONCAT(tg.name,'::',tg.color) ORDER BY tg.name SEPARATOR '||') as tags_raw,
    GROUP_CONCAT(DISTINCT CONCAT(u2.id,'::',IFNULL(u2.full_name,''),'::',u2.username,'::',IFNULL(u2.avatar_color,'#3B82F6'))
      ORDER BY u2.full_name SEPARATOR '||') as assignees_raw
  FROM tasks t LEFT JOIN users u1 ON t.creator_id=u1.id
  LEFT JOIN task_assignees ta ON t.id=ta.task_id
  LEFT JOIN users u2 ON ta.user_id=u2.id
  LEFT JOIN task_tags tt ON t.id=tt.task_id
  LEFT JOIN tags tg ON tt.tag_id=tg.id
  WHERE t.id=? GROUP BY t.id`,[req.params.id]);
  if(!rows.length) return res.status(404).json({error:'Not found'});
  const task=parseTask(rows[0]);
  // For admin: also return list of users whose access was revoked
  if(req.user.role==='admin'){
    const[revoked]=await pool.query(
      'SELECT u.id,u.full_name,u.avatar_color FROM task_revoked tr JOIN users u ON tr.user_id=u.id WHERE tr.task_id=?',
      [req.params.id]);
    task.revoked_users=revoked;
  }
  res.json({...task,access});
}));

/* Create task */
app.post('/api/tasks', auth, wrap(async(req,res)=>{
  const isAdmin=req.user.role==='admin';
  const isSupervisor=req.user.role==='supervisor';
  const isMember=req.user.role==='member';
  const canCreate=isAdmin||(isSupervisor&&req.user.permissions?.can_create_tasks)||isMember;
  if(!canCreate) return res.status(403).json({error:'Permission denied'});

  const{title,description,status,priority,assignee_ids,due_date,tags}=req.body;
  if(!title?.trim()) return res.status(400).json({error:'Title required'});

  const[r]=await pool.query('INSERT INTO tasks(title,description,status,priority,creator_id,due_date) VALUES(?,?,?,?,?,?)',
    [title.trim(),description||'',status||'todo',priority||'medium',req.user.id,due_date||null]);
  const taskId=r.insertId;

  // Members can ONLY assign to themselves
  const rawList=Array.isArray(assignee_ids)?assignee_ids.map(Number):[];
  const aList=isMember?[req.user.id]:(rawList.length?rawList:[req.user.id]);

  for(const uid of aList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}

  // Tags
  if(Array.isArray(tags)&&tags.length){
    for(const tn of tags){try{let[tr]=await pool.query('SELECT id FROM tags WHERE name=?',[tn]);const tid=tr.length?tr[0].id:(await pool.query('INSERT INTO tags(name) VALUES(?)',[tn]))[0].insertId;await pool.query('INSERT IGNORE INTO task_tags VALUES(?,?)',[taskId,tid]);}catch{}}
  }

  // Log creation
  await logHistory(taskId,req.user.id,'created',null,null,title.trim(),null);

  // Log initial assignment
  const[aNames]=await pool.query('SELECT full_name FROM users WHERE id IN('+aList.map(()=>'?').join(',')+')',aList);
  await logHistory(taskId,req.user.id,'assigned','assignees',null,aNames.map(u=>u.full_name).join(', '),null);

  // Notify new assignees (not self)
  for(const uid of aList){
    if(uid!==req.user.id){
      try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'assigned']);sendEmail(uid,req.user.username,title,'assigned').catch(()=>{});}catch{}
    }
  }
  res.json({id:taskId});
}));

/* Full edit — admin only (or supervisor with perm).
   Regular members use the dedicated /status and /move-to endpoints */
app.put('/api/tasks/:id', auth, wrap(async(req,res)=>{
  const isAdmin=req.user.role==='admin';
  const canEdit=isAdmin||(req.user.role==='supervisor'&&req.user.permissions?.can_edit_tasks);
  if(!canEdit) return res.status(403).json({error:'Only admins and authorised supervisors can fully edit tasks'});

  const{title,description,status,priority,assignee_ids,due_date}=req.body;
  const taskId=req.params.id;
  const[old]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!old.length) return res.status(404).json({error:'Task not found'});
  const prev=old[0];

  await pool.query('UPDATE tasks SET title=?,description=?,status=?,priority=?,due_date=? WHERE id=?',
    [title||prev.title,description??prev.description,status||prev.status,priority||prev.priority,due_date||null,taskId]);

  if(prev.status!==(status||prev.status))
    await logHistory(taskId,req.user.id,'status_changed','status',prev.status,status,null);
  if(prev.priority!==(priority||prev.priority))
    await logHistory(taskId,req.user.id,'priority_changed','priority',prev.priority,priority,null);
  if((title||prev.title)!==prev.title)
    await logHistory(taskId,req.user.id,'edited','title',prev.title,title,null);

  if(Array.isArray(assignee_ids)){
    const newList=assignee_ids.map(Number);
    const[oldRows]=await pool.query('SELECT ta.user_id,u.full_name FROM task_assignees ta JOIN users u ON ta.user_id=u.id WHERE ta.task_id=?',[taskId]);
    const oldList=oldRows.map(r=>r.user_id);
    const newlyAdded=newList.filter(id=>!oldList.includes(id));
    const removed=oldList.filter(id=>!newList.includes(id));
    await pool.query('DELETE FROM task_assignees WHERE task_id=?',[taskId]);
    for(const uid of newList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}
    // Admin editing can also restore revoked access
    if(newList.length) await pool.query('DELETE FROM task_revoked WHERE task_id=? AND user_id IN('+newList.map(()=>'?').join(',')+')',[taskId,...newList]).catch(()=>{});
    if(newlyAdded.length){
      const[addNames]=await pool.query('SELECT full_name FROM users WHERE id IN('+newlyAdded.map(()=>'?').join(',')+')',newlyAdded);
      await logHistory(taskId,req.user.id,'assigned','assignees',null,addNames.map(u=>u.full_name).join(', '),null);
    }
    if(removed.length){
      const removedNames=oldRows.filter(r=>removed.includes(r.user_id)).map(r=>r.full_name);
      await logHistory(taskId,req.user.id,'unassigned','assignees',removedNames.join(', '),null,null);
    }
    for(const uid of newlyAdded){
      if(uid!==req.user.id){try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'assigned']);sendEmail(uid,req.user.username,title,'assigned').catch(()=>{});}catch{}}
    }
  }
  res.json({success:true});
}));

app.delete('/api/tasks/:id', auth, adminOnly, wrap(async(req,res)=>{
  await pool.query('DELETE FROM tasks WHERE id=?',[req.params.id]);
  res.json({success:true});
}));

/* ══════════════════════════════════════
   TASK STATUS CHANGE — any active assignee
   Requires a comment. Immutable once saved.
══════════════════════════════════════ */
app.post('/api/tasks/:id/status', auth, wrap(async(req,res)=>{
  const taskId=req.params.id;
  const userId=req.user.id;
  const{new_status,comment}=req.body;

  if(!new_status) return res.status(400).json({error:'new_status required'});
  if(!comment?.trim()) return res.status(400).json({error:'A comment is required when changing status'});

  const access=await hasTaskAccess(taskId,userId,req.user.role);
  if(access==='none') return res.status(403).json({error:'You do not have access to this task'});

  // Non-admins must be an active assignee
  if(req.user.role!=='admin'){
    const[assigned]=await pool.query('SELECT 1 FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);
    if(!assigned.length) return res.status(403).json({error:'Only current assignees can change task status'});
  }

  const[taskRows]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!taskRows.length) return res.status(404).json({error:'Task not found'});
  const prev=taskRows[0];

  if(prev.status===new_status) return res.status(400).json({error:'Task already has this status'});

  await pool.query('UPDATE tasks SET status=? WHERE id=?',[new_status,taskId]);
  await logHistory(taskId,userId,'status_changed','status',prev.status,new_status,comment.trim());

  // Notify all other assignees
  const[assignees]=await pool.query('SELECT user_id FROM task_assignees WHERE task_id=? AND user_id!=?',[taskId,userId]);
  for(const a of assignees){
    try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[a.user_id,taskId,userId,'status_changed']);}catch{}
  }
  res.json({success:true});
}));

/* ══════════════════════════════════════
   TASK COMMENT — any active member
   Comments are immutable (no edit/delete except admin)
══════════════════════════════════════ */
app.post('/api/tasks/:id/comment', auth, wrap(async(req,res)=>{
  const taskId=req.params.id;
  const userId=req.user.id;
  const{comment}=req.body;
  if(!comment?.trim()) return res.status(400).json({error:'Comment cannot be empty'});
  const access=await hasTaskAccess(taskId,userId,req.user.role);
  if(access==='none') return res.status(403).json({error:'Access denied'});
  await logHistory(taskId,userId,'comment',null,null,null,comment.trim());
  res.json({success:true});
}));

/* Admin can delete a history entry (comment/note) */
app.delete('/api/tasks/:tid/history/:hid', auth, adminOnly, wrap(async(req,res)=>{
  await pool.query('DELETE FROM task_history WHERE id=? AND task_id=?',[req.params.hid,req.params.tid]);
  res.json({success:true});
}));

/* ══════════════════════════════════════
   MOVE TO — transfer task to new person(s)
   Moving user loses ALL access (revoked).
   Admin can move without losing access.
══════════════════════════════════════ */
app.post('/api/tasks/:id/move-to', auth, wrap(async(req,res)=>{
  const taskId=req.params.id;
  const userId=req.user.id;
  const isAdmin=req.user.role==='admin';
  const{new_assignee_ids,comment}=req.body;

  if(!Array.isArray(new_assignee_ids)||!new_assignee_ids.length)
    return res.status(400).json({error:'At least one new assignee required'});

  const access=await hasTaskAccess(taskId,userId,req.user.role);
  if(access==='none') return res.status(403).json({error:'You have no access to this task'});

  // Non-admins must currently be an assignee to move
  if(!isAdmin){
    const[assigned]=await pool.query('SELECT 1 FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);
    if(!assigned.length) return res.status(403).json({error:'Only current assignees can move this task'});
  }

  const[taskRows]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!taskRows.length) return res.status(404).json({error:'Task not found'});
  const task=taskRows[0];

  // Get current assignees for log
  const[oldRows]=await pool.query('SELECT ta.user_id,u.full_name FROM task_assignees ta JOIN users u ON ta.user_id=u.id WHERE ta.task_id=?',[taskId]);
  const oldNames=oldRows.map(r=>r.full_name).join(', ')||'—';

  const newList=new_assignee_ids.map(Number);

  // Replace all assignees
  await pool.query('DELETE FROM task_assignees WHERE task_id=?',[taskId]);
  for(const uid of newList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}

  // Revoke access from the moving user (unless admin or they're also in the new list)
  if(!isAdmin&&!newList.includes(userId)){
    await pool.query('INSERT IGNORE INTO task_revoked(task_id,user_id) VALUES(?,?)',[taskId,userId]);
  }

  const[newNames]=await pool.query('SELECT full_name FROM users WHERE id IN('+newList.map(()=>'?').join(',')+')',newList);
  const newNamesStr=newNames.map(u=>u.full_name).join(', ');

  await logHistory(taskId,userId,'moved','assignees',oldNames,newNamesStr,comment||null);

  // Notify new assignees
  for(const uid of newList){
    if(uid!==userId){
      try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,userId,'reassigned']);sendEmail(uid,req.user.username,task.title,'reassigned').catch(()=>{});}catch{}
    }
  }
  res.json({success:true});
}));

/* Mark complete & optionally reassign */
app.post('/api/tasks/:id/complete', auth, wrap(async(req,res)=>{
  const taskId=req.params.id;
  const userId=req.user.id;
  const isAdmin=req.user.role==='admin';
  const{new_assignee_ids,comment}=req.body;

  if(!isAdmin){
    const[assigned]=await pool.query('SELECT 1 FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);
    if(!assigned.length) return res.status(403).json({error:'Not assigned to this task'});
  }
  const[taskRows]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!taskRows.length) return res.status(404).json({error:'Not found'});
  const task=taskRows[0];

  await pool.query('UPDATE tasks SET status=? WHERE id=?',['done',taskId]);
  await logHistory(taskId,userId,'status_changed','status',task.status,'done',comment||null);

  const newList=Array.isArray(new_assignee_ids)?new_assignee_ids.map(Number):[];
  if(newList.length){
    // Remove current user, add new assignees
    await pool.query('DELETE FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);
    for(const uid of newList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}
    if(!isAdmin&&!newList.includes(userId))
      await pool.query('INSERT IGNORE INTO task_revoked(task_id,user_id) VALUES(?,?)',[taskId,userId]);
    const[nn]=await pool.query('SELECT full_name FROM users WHERE id IN('+newList.map(()=>'?').join(',')+')',newList);
    await logHistory(taskId,userId,'moved','assignees','(completed)',nn.map(u=>u.full_name).join(', '),null);
    for(const uid of newList){
      if(uid!==userId){try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,userId,'reassigned']);sendEmail(uid,req.user.username,task.title,'reassigned').catch(()=>{});}catch{}}
    }
  }
  res.json({success:true});
}));

/* ══════════════════════════════════════
   TASK HISTORY / TIMELINE
   Visible to all current task members + admin
══════════════════════════════════════ */
app.get('/api/tasks/:id/history', auth, wrap(async(req,res)=>{
  const taskId=req.params.id;
  const access=await hasTaskAccess(taskId,req.user.id,req.user.role);
  // Even revoked users can see the history (read-only), admin always sees
  const[rows]=await pool.query(`
    SELECT th.*,
      u.full_name as actor_name, u.username as actor_username,
      u.avatar_color as actor_color, u.role as actor_role
    FROM task_history th JOIN users u ON th.user_id=u.id
    WHERE th.task_id=? ORDER BY th.created_at ASC`,[taskId]);
  res.json(rows);
}));

/* ══════════════════════════════════════
   TAGS
══════════════════════════════════════ */
app.get('/api/tags', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query('SELECT * FROM tags ORDER BY name'); res.json(rows);
}));

/* ══════════════════════════════════════
   NOTIFICATIONS
══════════════════════════════════════ */
app.get('/api/notifications', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query(`
    SELECT n.*,t.title as task_title,u.username as triggered_by,u.full_name as triggered_by_name
    FROM notifications n JOIN tasks t ON n.task_id=t.id JOIN users u ON n.triggered_by_id=u.id
    WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 30`,[req.user.id]);
  res.json(rows);
}));
app.put('/api/notifications/:id/read', auth, wrap(async(req,res)=>{
  await pool.query('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?',[req.params.id,req.user.id]); res.json({success:true});
}));
app.put('/api/notifications/read-all', auth, wrap(async(req,res)=>{
  await pool.query('UPDATE notifications SET is_read=1 WHERE user_id=?',[req.user.id]); res.json({success:true});
}));

/* ══════════════════════════════════════
   ATTENDANCE
══════════════════════════════════════ */
async function ensureSundaysHolidays(startDate,endDate){
  const start=new Date(startDate+'T12:00:00'),end=new Date(endDate+'T12:00:00');
  for(let d=new Date(start);d<=end;d.setDate(d.getDate()+1)){
    if(d.getDay()===0){const ds=localDate(d);await pool.query('INSERT IGNORE INTO holidays(holiday_date,name,type) VALUES(?,?,?)',[ds,'Sunday','sunday']).catch(()=>{});}
  }
}

app.post('/api/attendance/clock-in', auth, wrap(async(req,res)=>{
  if(req.user.role==='admin') return res.status(403).json({error:'Administrators manage attendance through the panel, not clock in.'});
  const userId=req.user.id,now=new Date(),today=localDate(now);
  const[hols]=await pool.query('SELECT * FROM holidays WHERE holiday_date=?',[today]);
  if(hols.length) return res.status(400).json({error:`Today is a holiday: ${hols[0].name}`});
  const[ex]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  if(ex.length) return res.status(400).json({error:'Already clocked in today'});
  await pool.query('INSERT INTO attendance(user_id,work_date,clock_in,clock_in_status) VALUES(?,?,?,?)',[userId,today,now,'pending']);
  await ensureSundaysHolidays(today.slice(0,7)+'-01',localDate(new Date(now.getFullYear(),now.getMonth()+1,0)));
  res.json({success:true,message:'Clocked in. Awaiting approval.',clock_in:now,status:'pending'});
}));

app.post('/api/attendance/clock-out', auth, wrap(async(req,res)=>{
  if(req.user.role==='admin') return res.status(403).json({error:'Administrators do not clock out.'});
  const userId=req.user.id,now=new Date(),today=localDate(now);
  const[rows]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  if(!rows.length) return res.status(400).json({error:'You have not clocked in today'});
  if(rows[0].clock_out) return res.status(400).json({error:'Already clocked out today'});
  await pool.query('UPDATE attendance SET clock_out=?,clock_out_status=? WHERE id=?',[now,'pending',rows[0].id]);
  res.json({success:true,message:'Clocked out. Awaiting approval.',clock_out:now,status:'pending'});
}));

app.get('/api/attendance/today', auth, wrap(async(req,res)=>{
  if(req.user.role==='admin') return res.json({record:null,holiday:null,today:localDate(),isAdmin:true});
  const today=localDate(new Date());
  const[rows]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[req.user.id,today]);
  const[hols]=await pool.query('SELECT * FROM holidays WHERE holiday_date=?',[today]);
  res.json({record:rows[0]||null,holiday:hols[0]||null,today,isAdmin:false});
}));

app.get('/api/attendance/my', auth, wrap(async(req,res)=>{
  if(req.user.role==='admin') return res.json({report:[],stats:{},year:new Date().getFullYear(),month:new Date().getMonth()+1});
  const userId=req.user.id,{year,month}=req.query;
  const y=parseInt(year)||new Date().getFullYear(),m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`,lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;
  await ensureSundaysHolidays(startDate,endDate);
  const[records]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date BETWEEN ? AND ? ORDER BY work_date',[userId,startDate,endDate]);
  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ? ORDER BY holiday_date',[startDate,endDate]);
  const report=[],holidayMap={},recordMap={};
  holidays.forEach(h=>holidayMap[h.holiday_date]=h);records.forEach(r=>recordMap[r.work_date]=r);
  for(let d=1;d<=lastD;d++){
    const dateStr=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`,dow=new Date(dateStr+'T12:00:00').getDay(),today=localDate(new Date());
    if(dateStr>today){report.push({date:dateStr,day_of_week:dow,type:'future'});continue;}
    if(holidayMap[dateStr]){report.push({date:dateStr,day_of_week:dow,type:'holiday',holiday_name:holidayMap[dateStr].name,holiday_type:holidayMap[dateStr].type});continue;}
    if(recordMap[dateStr]){report.push({date:dateStr,day_of_week:dow,type:'attendance',...recordMap[dateStr]});continue;}
    report.push({date:dateStr,day_of_week:dow,type:'absent'});
  }
  const stats={approved:report.filter(d=>d.type==='attendance'&&d.clock_in_status==='approved').length,pending:report.filter(d=>d.type==='attendance'&&d.clock_in_status==='pending').length,absent:report.filter(d=>d.type==='absent').length,holidays:report.filter(d=>d.type==='holiday').length,total_work_hours:records.filter(r=>r.approved_clock_in&&r.approved_clock_out).reduce((s,r)=>s+(new Date(r.approved_clock_out)-new Date(r.approved_clock_in))/3600000,0).toFixed(1)};
  res.json({report,stats,year:y,month:m});
}));

app.get('/api/admin/attendance', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_view_all_attendance) return res.status(403).json({error:'Permission denied'});
  const{year,month,user_id,status}=req.query;
  const y=parseInt(year)||new Date().getFullYear(),m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`,lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;
  await ensureSundaysHolidays(startDate,endDate);
  let sql=`SELECT a.*,u.full_name,u.username,u.avatar_color,ab.full_name as approver_name,ab.username as approver_username,ab.avatar_color as approver_avatar_color,ab.role as approver_role FROM attendance a JOIN users u ON a.user_id=u.id LEFT JOIN users ab ON a.approved_by=ab.id WHERE a.work_date BETWEEN ? AND ?`;
  const params=[startDate,endDate];
  if(user_id){sql+=' AND a.user_id=?';params.push(user_id);}
  if(status==='pending'){sql+=" AND(a.clock_in_status='pending' OR a.clock_out_status='pending')";}else if(status){sql+=' AND a.clock_in_status=?';params.push(status);}
  sql+=' ORDER BY a.work_date DESC,u.full_name';
  const[records]=await pool.query(sql,params);
  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ?',[startDate,endDate]);
  const[users]=await pool.query("SELECT id,full_name,username,avatar_color FROM users WHERE is_active=1 AND role='member' ORDER BY full_name");
  const holidayMap={},userReports={};holidays.forEach(h=>holidayMap[h.holiday_date]=h);
  for(const u of users){
    userReports[u.id]={user:u,days:[]};const userRecs={};records.filter(r=>r.user_id===u.id).forEach(r=>userRecs[r.work_date]=r);
    for(let d=1;d<=lastD;d++){const ds=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`,today=localDate(new Date());if(ds>today)continue;if(holidayMap[ds]){userReports[u.id].days.push({date:ds,type:'holiday',name:holidayMap[ds].name,holiday_type:holidayMap[ds].type});continue;}if(userRecs[ds]){userReports[u.id].days.push({date:ds,type:'attendance',...userRecs[ds]});continue;}userReports[u.id].days.push({date:ds,type:'absent'});}
  }
  const[[totals]]=await pool.query(`SELECT COUNT(*) as total,SUM(clock_in_status='pending') as pending,SUM(clock_in_status='approved') as approved,SUM(clock_in_status='rejected') as rejected FROM attendance WHERE work_date BETWEEN ? AND ?`,[startDate,endDate]);
  res.json({records,holidays,userReports:Object.values(userReports),stats:totals,year:y,month:m});
}));

app.put('/api/admin/attendance/:id', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_approve_attendance) return res.status(403).json({error:'Permission denied'});
  const{clock_in_status,clock_out_status,approved_clock_in,approved_clock_out,admin_note}=req.body;
  const id=req.params.id;
  const[rows]=await pool.query('SELECT * FROM attendance WHERE id=?',[id]);
  if(!rows.length) return res.status(404).json({error:'Record not found'});
  const rec=rows[0];const u=[],v=[];
  if(clock_in_status!==undefined){u.push('clock_in_status=?');v.push(clock_in_status);if(clock_in_status==='approved'){const cin=approved_clock_in!==undefined?approved_clock_in:rec.clock_in;u.push('approved_clock_in=?');v.push(toMySQL(cin));u.push('approved_by=?');v.push(req.user.id);u.push('approved_at=NOW()');}}
  if(clock_out_status!==undefined){u.push('clock_out_status=?');v.push(clock_out_status);if(clock_out_status==='approved'){const cout=approved_clock_out!==undefined?approved_clock_out:rec.clock_out;u.push('approved_clock_out=?');v.push(toMySQL(cout));if(clock_in_status===undefined){u.push('approved_by=?');v.push(req.user.id);u.push('approved_at=NOW()');}}}
  if(clock_in_status===undefined&&clock_out_status===undefined){if(approved_clock_in!==undefined){u.push('approved_clock_in=?');v.push(toMySQL(approved_clock_in));}if(approved_clock_out!==undefined){u.push('approved_clock_out=?');v.push(toMySQL(approved_clock_out));}}
  if(admin_note!==undefined){u.push('admin_note=?');v.push(admin_note);}
  if(!u.length) return res.status(400).json({error:'Nothing to update'});
  v.push(id);await pool.query(`UPDATE attendance SET ${u.join(',')} WHERE id=?`,v);
  res.json({success:true});
}));

app.post('/api/admin/attendance/bulk-approve', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_approve_attendance) return res.status(403).json({error:'Permission denied'});
  const{ids}=req.body;
  if(!Array.isArray(ids)||!ids.length) return res.status(400).json({error:'No IDs'});
  await pool.query(`UPDATE attendance SET clock_in_status='approved',approved_by=?,approved_at=NOW(),approved_clock_in=COALESCE(approved_clock_in,clock_in),approved_clock_out=COALESCE(approved_clock_out,clock_out) WHERE id IN(${ids.map(()=>'?').join(',')}) AND clock_in_status='pending'`,[req.user.id,...ids]);
  res.json({success:true});
}));

app.get('/api/admin/attendance/stats', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_view_all_attendance) return res.status(403).json({error:'Permission denied'});
  const{year,month}=req.query;const y=parseInt(year)||new Date().getFullYear(),m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`,lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;
  await ensureSundaysHolidays(startDate,endDate);
  const[[overall]]=await pool.query(`SELECT COUNT(*) as total_checkins,SUM(clock_in_status='pending') as pending,SUM(clock_in_status='approved') as approved,SUM(clock_in_status='rejected') as rejected,COUNT(DISTINCT user_id) as unique_users FROM attendance WHERE work_date BETWEEN ? AND ?`,[startDate,endDate]);
  const[perUser]=await pool.query(`SELECT u.id,u.full_name,u.username,u.avatar_color,COUNT(a.id) as check_ins,SUM(a.clock_in_status='approved') as approved,SUM(a.clock_in_status='pending') as pending,SUM(a.clock_in_status='rejected') as rejected FROM users u LEFT JOIN attendance a ON u.id=a.user_id AND a.work_date BETWEEN ? AND ? WHERE u.is_active=1 AND u.role='member' GROUP BY u.id ORDER BY approved DESC`,[startDate,endDate]);
  const[daily]=await pool.query(`SELECT work_date as date,COUNT(*) as total,SUM(clock_in_status='approved') as approved,SUM(clock_in_status='pending') as pending FROM attendance WHERE work_date BETWEEN ? AND ? GROUP BY work_date ORDER BY work_date`,[startDate,endDate]);
  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ? ORDER BY holiday_date',[startDate,endDate]);
  const today=localDate(new Date()),holidayDates=new Set(holidays.map(h=>h.holiday_date));
  let workingDays=0;for(let d=1;d<=lastD;d++){const ds=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;if(ds<=today&&!holidayDates.has(ds))workingDays++;}
  res.json({overall,perUser,daily,holidays,workingDays,year:y,month:m});
}));

app.post('/api/admin/holidays', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_manage_holidays) return res.status(403).json({error:'Permission denied'});
  const{holiday_date,name}=req.body;
  if(!holiday_date||!name) return res.status(400).json({error:'Date and name required'});
  await pool.query('INSERT IGNORE INTO holidays(holiday_date,name,type) VALUES(?,?,?)',[holiday_date,name,'manual']);
  res.json({success:true});
}));
app.delete('/api/admin/holidays/:date', auth, adminOnly, wrap(async(req,res)=>{
  await pool.query('DELETE FROM holidays WHERE holiday_date=? AND type!=?',[req.params.date,'sunday']);
  res.json({success:true});
}));

/* ══════════════════════════════════════
   ADMIN TASK STATS (comprehensive)
══════════════════════════════════════ */
app.get('/api/admin/stats', auth, adminOnly, wrap(async(req,res)=>{
  const[[totals]]=await pool.query(`SELECT COUNT(*) as total_tasks,SUM(status='todo') as todo,SUM(status='in_progress') as in_progress,SUM(status='review') as review,SUM(status='done') as done,SUM(priority='urgent') as urgent,SUM(priority='high') as high,SUM(priority='medium') as medium,SUM(priority='low') as low_p,SUM(due_date<CURDATE() AND status!='done') as overdue,SUM(due_date>=CURDATE() AND due_date<=DATE_ADD(CURDATE(),INTERVAL 7 DAY) AND status!='done') as due_this_week FROM tasks`);
  const[[userStats]]=await pool.query(`SELECT COUNT(*) as total,SUM(role='admin') as admins,SUM(role='supervisor') as supervisors,SUM(role='member') as members,SUM(is_active=1) as active FROM users`);
  const[perUser]=await pool.query(`SELECT u.id,u.full_name,u.avatar_color,u.username,u.role,COUNT(DISTINCT ta.task_id) as assigned,SUM(t.status='done') as completed,SUM(t.status='in_progress') as in_progress,SUM(t.status='todo') as todo,SUM(t.status='review') as review,SUM(t.due_date<CURDATE() AND t.status!='done') as overdue FROM users u LEFT JOIN task_assignees ta ON u.id=ta.user_id LEFT JOIN tasks t ON ta.task_id=t.id WHERE u.is_active=1 GROUP BY u.id ORDER BY assigned DESC`);
  const[daily30]=await pool.query(`SELECT DATE(created_at) as date,status,COUNT(*) as count FROM tasks WHERE created_at>=DATE_SUB(CURDATE(),INTERVAL 30 DAY) GROUP BY DATE(created_at),status ORDER BY date`);
  const[movements]=await pool.query(`SELECT th.*,t.title as task_title,u.full_name as actor_name,u.avatar_color,u.role as actor_role FROM task_history th JOIN tasks t ON th.task_id=t.id JOIN users u ON th.user_id=u.id ORDER BY th.created_at DESC LIMIT 80`);
  const[byPriority]=await pool.query(`SELECT priority,COUNT(*) as count,SUM(status='done') as done,SUM(status!='done') as open FROM tasks GROUP BY priority ORDER BY FIELD(priority,'urgent','high','medium','low')`);
  const[byTag]=await pool.query(`SELECT tg.name,tg.color,COUNT(tt.task_id) as count,SUM(t.status='done') as done FROM tags tg LEFT JOIN task_tags tt ON tg.id=tt.tag_id LEFT JOIN tasks t ON tt.task_id=t.id GROUP BY tg.id ORDER BY count DESC LIMIT 10`);
  const[statusTransitions]=await pool.query(`SELECT old_value as from_status,new_value as to_status,COUNT(*) as count FROM task_history WHERE action='status_changed' AND created_at>=DATE_SUB(CURDATE(),INTERVAL 30 DAY) GROUP BY old_value,new_value ORDER BY count DESC`);
  const[weeklyCompletion]=await pool.query(`SELECT YEAR(th.created_at) as year,WEEK(th.created_at,1) as week,MIN(DATE(th.created_at)) as week_start,COUNT(*) as completed FROM task_history th WHERE th.action='status_changed' AND th.new_value='done' AND th.created_at>=DATE_SUB(CURDATE(),INTERVAL 8 WEEK) GROUP BY YEAR(th.created_at),WEEK(th.created_at,1) ORDER BY year,week`);
  const[activity]=await pool.query(`SELECT al.*,u.full_name,u.avatar_color,u.role FROM activity_log al LEFT JOIN users u ON al.user_id=u.id ORDER BY al.created_at DESC LIMIT 30`);
  const[[monthStats]]=await pool.query(`SELECT SUM(MONTH(created_at)=MONTH(CURDATE()) AND YEAR(created_at)=YEAR(CURDATE())) as created_this_month,SUM(status='done' AND MONTH(updated_at)=MONTH(CURDATE()) AND YEAR(updated_at)=YEAR(CURDATE())) as completed_this_month FROM tasks`);
  res.json({totals,userStats,perUser,daily30,movements,byPriority,byTag,statusTransitions,weeklyCompletion,activity,monthStats});
}));

/* ══════════════════════════════════════
   SMTP
══════════════════════════════════════ */
app.get('/api/admin/smtp', auth, adminOnly, wrap(async(req,res)=>{const[r]=await pool.query('SELECT id,host,port,username,encryption,from_email,from_name FROM smtp_config LIMIT 1');res.json(r[0]||{});}));
app.put('/api/admin/smtp', auth, adminOnly, wrap(async(req,res)=>{
  const{host,port,username,password,encryption,from_email,from_name}=req.body;
  const[ex]=await pool.query('SELECT id FROM smtp_config LIMIT 1');
  if(ex.length){const s=['host=?','port=?','username=?','encryption=?','from_email=?','from_name=?'],v=[host,port,username,encryption,from_email||'',from_name||'Task Manager'];if(password){s.push('password=?');v.push(password);}v.push(ex[0].id);await pool.query(`UPDATE smtp_config SET ${s.join(',')} WHERE id=?`,v);}
  else await pool.query('INSERT INTO smtp_config(host,port,username,password,encryption,from_email,from_name) VALUES(?,?,?,?,?,?,?)',[host,port,username,password||'',encryption,from_email||'',from_name||'Task Manager']);
  res.json({success:true});
}));
app.post('/api/admin/smtp/test', auth, adminOnly, wrap(async(req,res)=>{
  const[rows]=await pool.query('SELECT * FROM smtp_config LIMIT 1');if(!rows.length) return res.status(400).json({error:'SMTP not configured'});
  const cfg=rows[0],t=nodemailer.createTransport({host:cfg.host,port:cfg.port,secure:cfg.encryption==='ssl',auth:{user:cfg.username,pass:cfg.password}});
  await t.verify();res.json({success:true,message:'SMTP connection verified!'});
}));

async function sendEmail(userId,by,title,type){
  const[sr]=await pool.query('SELECT * FROM smtp_config LIMIT 1');if(!sr.length)return;
  const[ur]=await pool.query('SELECT email,full_name FROM users WHERE id=?',[userId]);if(!ur.length)return;
  const cfg=sr[0],u=ur[0];
  const subs={assigned:`Assigned: ${title}`,reassigned:`Reassigned to you: ${title}`,status_changed:`Status update on: ${title}`};
  const bods={assigned:`<p>Hi ${u.full_name},</p><p><b>@${by}</b> assigned you to <b>"${title}"</b>.</p>`,reassigned:`<p>Hi ${u.full_name},</p><p><b>@${by}</b> moved <b>"${title}"</b> to you.</p>`,status_changed:`<p>Hi ${u.full_name},</p><p>Status was updated on <b>"${title}"</b> by @${by}.</p>`};
  const t=nodemailer.createTransport({host:cfg.host,port:cfg.port,secure:cfg.encryption==='ssl',auth:{user:cfg.username,pass:cfg.password}});
  await t.sendMail({from:`"${cfg.from_name}"<${cfg.from_email||cfg.username}>`,to:u.email,subject:subs[type]||subs.assigned,html:bods[type]||bods.assigned});
}

app.use((err,req,res,next)=>res.status(500).json({error:'Internal server error'}));
const PORT=process.env.PORT||3001;
setupDatabase().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`🚀 Synapse API on port ${PORT}`)));
