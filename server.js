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
   ATTENDANCE RULES
   All times are compared in HH:MM format (server local time)
══════════════════════════════════════ */
const RULES = {
  office: {
    // Clock-in window 08:45–09:10 → auto-approved
    ci_auto_start: '08:45', ci_auto_end: '09:10',
    // Clock-out window 17:45–18:30 → auto-approved
    co_auto_start: '17:45', co_auto_end: '18:30',
  },
  field: {
    // On-time: up to 09:35 → auto-approved; after → late+pending
    ci_ontime_until: '09:15',
    ci_late_until:   '09:35',   // allowed but auto-approved as on-time up to here
    ci_late_flag:    '09:35',   // beyond this → flagged late, needs approval
    // Clock-out: 18:00–19:00 → auto-approved; before 18:00 → early+pending
    co_early_before: '18:00',
    co_auto_end:     '19:00',
  },
};

function timeHHMM(d){ // extract HH:MM from a Date object
  return String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0');
}
function timeGte(a,b){ return a>=b; } // "a >= b" in HH:MM string compare
function timeLte(a,b){ return a<=b; }
function timeBetween(t,from,to){ return t>=from && t<=to; }

// Returns {clock_in_status, flag, auto_approved, approved_clock_in}
function evaluateClockIn(now, category){
  const t = timeHHMM(now);
  if(category==='office'){
    if(timeBetween(t, RULES.office.ci_auto_start, RULES.office.ci_auto_end)){
      return {clock_in_status:'approved', flag:'on_time', approved_clock_in:now};
    }
    return {clock_in_status:'pending', flag: t<RULES.office.ci_auto_start?'early':'late'};
  }
  if(category==='field'){
    if(timeLte(t, RULES.field.ci_late_until)){
      return {clock_in_status:'approved', flag:'on_time', approved_clock_in:now};
    }
    // After 09:35 → late, needs approval
    return {clock_in_status:'pending', flag:'late'};
  }
  // unknown category → pending
  return {clock_in_status:'pending', flag:'on_time'};
}

function evaluateClockOut(now, category){
  const t = timeHHMM(now);
  if(category==='office'){
    if(timeBetween(t, RULES.office.co_auto_start, RULES.office.co_auto_end)){
      return {clock_out_status:'approved', flag:'on_time', approved_clock_out:now};
    }
    return {clock_out_status:'pending', flag: t<RULES.office.co_auto_start?'early':'late'};
  }
  if(category==='field'){
    if(t<RULES.field.co_early_before){
      // Early departure → needs approval
      return {clock_out_status:'pending', flag:'early'};
    }
    if(timeLte(t, RULES.field.co_auto_end)){
      return {clock_out_status:'approved', flag:'on_time', approved_clock_out:now};
    }
    // After 19:00 → pending (very late)
    return {clock_out_status:'pending', flag:'late'};
  }
  return {clock_out_status:'pending', flag:'on_time'};
}

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
      employee_category ENUM('office','field') DEFAULT 'office',
      department VARCHAR(100) DEFAULT '',
      avatar_color VARCHAR(7) DEFAULT '#3B82F6',
      is_active BOOLEAN DEFAULT TRUE,
      must_change_password BOOLEAN DEFAULT FALSE,
      last_login_at TIMESTAMP NULL,
      last_login_ip VARCHAR(64) DEFAULT NULL,
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
      title VARCHAR(255) NOT NULL, description TEXT,
      status ENUM('todo','in_progress','review','done') DEFAULT 'todo',
      priority ENUM('low','medium','high','urgent') DEFAULT 'medium',
      creator_id INT NOT NULL, due_date DATE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS task_assignees(
      task_id INT NOT NULL, user_id INT NOT NULL,
      assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(task_id,user_id),
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS task_revoked(
      task_id INT NOT NULL, user_id INT NOT NULL,
      revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(task_id,user_id),
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS tags(
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(50) NOT NULL UNIQUE, color VARCHAR(7) DEFAULT '#6366F1')`);

    await c.query(`CREATE TABLE IF NOT EXISTS task_tags(
      task_id INT NOT NULL, tag_id INT NOT NULL, PRIMARY KEY(task_id,tag_id),
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(tag_id)  REFERENCES tags(id)  ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS notifications(
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      task_id INT DEFAULT NULL,
      triggered_by_id INT DEFAULT NULL,
      type VARCHAR(80) DEFAULT 'assigned',
      title VARCHAR(255) DEFAULT NULL,
      message TEXT DEFAULT NULL,
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(triggered_by_id) REFERENCES users(id) ON DELETE SET NULL)`);

    await c.query(`CREATE TABLE IF NOT EXISTS task_history(
      id INT AUTO_INCREMENT PRIMARY KEY,
      task_id INT NOT NULL, user_id INT NOT NULL,
      action VARCHAR(100) NOT NULL, field VARCHAR(50),
      old_value TEXT, new_value TEXT, comment TEXT,
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
      clock_in_flag ENUM('on_time','late','early') DEFAULT 'on_time',
      clock_out_flag ENUM('on_time','late','early') DEFAULT 'on_time',
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

    /* Leave Applications */
    await c.query(`CREATE TABLE IF NOT EXISTS leave_applications(
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      leave_type ENUM('medical','emergency','annual','half_day','others') NOT NULL,
      start_date DATE NOT NULL,
      end_date DATE NOT NULL,
      half_day_period ENUM('morning','afternoon') DEFAULT NULL,
      half_day_start TIME DEFAULT NULL,
      half_day_end TIME DEFAULT NULL,
      reason TEXT NOT NULL,
      status ENUM('pending','approved','rejected') DEFAULT 'pending',
      reviewed_by INT DEFAULT NULL,
      reviewed_at TIMESTAMP NULL,
      reviewer_note TEXT,
      admin_override BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(reviewed_by) REFERENCES users(id) ON DELETE SET NULL)`);

    /* Per-supervisor approvals for annual leave (requires ALL supervisors to approve) */
    await c.query(`CREATE TABLE IF NOT EXISTS leave_approvals(
      id INT AUTO_INCREMENT PRIMARY KEY,
      leave_id INT NOT NULL,
      supervisor_id INT NOT NULL,
      decision ENUM('pending','approved','rejected') DEFAULT 'pending',
      note TEXT,
      decided_at TIMESTAMP NULL,
      UNIQUE KEY uniq_leave_sup(leave_id,supervisor_id),
      FOREIGN KEY(leave_id) REFERENCES leave_applications(id) ON DELETE CASCADE,
      FOREIGN KEY(supervisor_id) REFERENCES users(id) ON DELETE CASCADE)`);

    /* Migrations */
    await c.query(`ALTER TABLE users MODIFY COLUMN role ENUM('admin','supervisor','member') DEFAULT 'member'`).catch(()=>{});
    await c.query(`ALTER TABLE users ADD COLUMN employee_category ENUM('office','field') DEFAULT 'office'`).catch(()=>{});
    await c.query(`ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT FALSE`).catch(()=>{});
    await c.query(`ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP NULL`).catch(()=>{});
    await c.query(`ALTER TABLE notifications MODIFY COLUMN task_id INT DEFAULT NULL`).catch(()=>{});
    await c.query(`ALTER TABLE notifications MODIFY COLUMN triggered_by_id INT DEFAULT NULL`).catch(()=>{});
    await c.query(`ALTER TABLE notifications ADD COLUMN title VARCHAR(255) DEFAULT NULL`).catch(()=>{});
    await c.query(`ALTER TABLE notifications ADD COLUMN message TEXT DEFAULT NULL`).catch(()=>{});
    await c.query(`ALTER TABLE users ADD COLUMN last_login_ip VARCHAR(64) DEFAULT NULL`).catch(()=>{});
    await c.query(`ALTER TABLE users ADD COLUMN department VARCHAR(100) DEFAULT ''`).catch(()=>{});
    await c.query(`ALTER TABLE notifications MODIFY COLUMN type VARCHAR(50) DEFAULT 'assigned'`).catch(()=>{});
    await c.query(`ALTER TABLE task_history CHANGE COLUMN changed_by_id user_id INT NOT NULL`).catch(()=>{});
    await c.query(`ALTER TABLE task_history ADD COLUMN user_id INT NOT NULL DEFAULT 1`).catch(()=>{});
    await c.query(`ALTER TABLE task_history MODIFY COLUMN action VARCHAR(100) NOT NULL`).catch(()=>{});
    // attendance flag columns
    await c.query(`ALTER TABLE attendance ADD COLUMN clock_in_flag ENUM('on_time','late','early') DEFAULT 'on_time'`).catch(()=>{});
    await c.query(`ALTER TABLE attendance ADD COLUMN clock_out_flag ENUM('on_time','late','early') DEFAULT 'on_time'`).catch(()=>{});

    const cols = ['comment','field','old_value','new_value'];
    for(const col of cols){
      const[rows]=await c.query(`SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='task_history' AND COLUMN_NAME=?`,[col]);
      if(!rows.length) await c.query(`ALTER TABLE task_history ADD COLUMN ${col} ${col==='field'?'VARCHAR(50)':'TEXT'}`);
    }

    /* Seed */
    const hash = await bcrypt.hash('Admin@1234',10);
    await c.query(`INSERT IGNORE INTO users(username,email,password_hash,full_name,role,avatar_color) VALUES('admin','admin@company.com',?,'System Admin','admin','#7C5CFC')`,[hash]);
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

/* Task access helper */
async function hasTaskAccess(taskId, userId, role){
  if(role==='admin') return 'full';
  const[rev]=await pool.query('SELECT 1 FROM task_revoked WHERE task_id=? AND user_id=?',[taskId,userId]);
  if(rev.length) return 'none';
  if(role==='supervisor') return 'supervisor';
  const[rows]=await pool.query('SELECT 1 FROM tasks WHERE id=? AND (creator_id=? OR id IN (SELECT task_id FROM task_assignees WHERE user_id=?))',[taskId,userId,userId]);
  return rows.length ? 'member' : 'none';
}
async function logHistory(taskId, userId, action, field, oldVal, newVal, comment){
  await pool.query('INSERT INTO task_history(task_id,user_id,action,field,old_value,new_value,comment) VALUES(?,?,?,?,?,?,?)',[taskId,userId,action,field||null,oldVal||null,newVal||null,comment||null]);
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
  if(u.role==='supervisor'){const[perms]=await pool.query('SELECT * FROM supervisor_permissions WHERE user_id=?',[u.id]);permissions=perms[0]||{};}
  // Capture real client IP (behind proxies)
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
           || req.headers['x-real-ip']
           || req.socket?.remoteAddress
           || 'unknown';
  pool.query('UPDATE users SET last_login_at=NOW(),last_login_ip=? WHERE id=?',[ip,u.id]).catch(()=>{});
  pool.query('INSERT INTO activity_log(user_id,action,entity_type) VALUES(?,?,?)',[u.id,'login','user']).catch(()=>{});
  res.json({token,user:{id:u.id,username:u.username,email:u.email,full_name:u.full_name,role:u.role,employee_category:u.employee_category||'office',department:u.department||'',avatar_color:u.avatar_color,permissions,must_change_password:u.must_change_password?true:false,last_login_at:u.last_login_at,last_login_ip:u.last_login_ip}});
}));

/* ══════════════════════════════════════
   USERS
══════════════════════════════════════ */
app.get('/api/users', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query(`
    SELECT u.id,u.username,u.email,u.full_name,u.role,u.employee_category,u.department,
      u.avatar_color,u.is_active,u.must_change_password,u.last_login_at,u.last_login_ip,u.created_at,
      sp.can_approve_attendance,sp.can_view_all_attendance,sp.can_edit_tasks,
      sp.can_create_tasks,sp.can_view_all_tasks,sp.can_manage_holidays
    FROM users u LEFT JOIN supervisor_permissions sp ON u.id=sp.user_id ORDER BY u.full_name`);
  res.json(rows);
}));

app.post('/api/users', auth, adminOnly, wrap(async(req,res)=>{
  const{username,email,password,full_name,role,employee_category,department}=req.body;
  if(!username||!email||!password) return res.status(400).json({error:'Missing fields'});
  const hash=await bcrypt.hash(password,10);
  const colors=['#3B82F6','#10B981','#F59E0B','#8B5CF6','#EC4899','#06B6D4'];
  const color=colors[Math.floor(Math.random()*colors.length)];
  const[r]=await pool.query('INSERT INTO users(username,email,password_hash,full_name,role,employee_category,department,avatar_color) VALUES(?,?,?,?,?,?,?,?)',
    [username,email,hash,full_name||username,role||'member',employee_category||'office',department||'',color]);
  if(role==='supervisor') await pool.query('INSERT IGNORE INTO supervisor_permissions(user_id) VALUES(?)',[r.insertId]);
  res.json({id:r.insertId,username,email,full_name,role:role||'member',employee_category:employee_category||'office',department:department||'',avatar_color:color});
}));

app.put('/api/users/:id', auth, adminOnly, wrap(async(req,res)=>{
  const{email,full_name,role,is_active,password,permissions,employee_category,department}=req.body;
  const uid=parseInt(req.params.id);
  const u=[],v=[];
  if(email!==undefined){u.push('email=?');v.push(email);}
  if(full_name!==undefined){u.push('full_name=?');v.push(full_name);}
  if(role!==undefined){u.push('role=?');v.push(role);}
  if(is_active!==undefined){u.push('is_active=?');v.push(is_active?1:0);}
  if(password){
    u.push('password_hash=?');v.push(await bcrypt.hash(password,10));
    // If admin sets a new password, default force-change to true unless explicitly false
    const forceChange=req.body.must_change_password;
    u.push('must_change_password=?');v.push(forceChange===false?0:1);
  }
  if(req.body.must_change_password===false){u.push('must_change_password=?');v.push(0);}
  if(employee_category!==undefined){u.push('employee_category=?');v.push(employee_category);}
  if(department!==undefined){u.push('department=?');v.push(department);}
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

/* Permanent hard-delete — removes employee + all attendance records */
app.delete('/api/users/:id/permanent', auth, adminOnly, wrap(async(req,res)=>{
  const uid=parseInt(req.params.id);
  if(uid===req.user.id) return res.status(400).json({error:'Cannot delete yourself'});
  // Check they are not the only admin
  const[admins]=await pool.query("SELECT id FROM users WHERE role='admin' AND is_active=1");
  const[target]=await pool.query('SELECT role FROM users WHERE id=?',[uid]);
  if(target[0]?.role==='admin'&&admins.length<=1)
    return res.status(400).json({error:'Cannot delete the last admin account'});
  // Hard delete — cascades to attendance, task_assignees, notifications etc
  await pool.query('DELETE FROM users WHERE id=?',[uid]);
  res.json({success:true});
}));

/* ══════════════════════════════════════
   TASKS — Core CRUD
══════════════════════════════════════ */
const parseTask=r=>({...r,
  tags:r.tags_raw?r.tags_raw.split('||').map(t=>{const[name,color]=t.split('::');return{name,color};}): [],
  assignees:r.assignees_raw?r.assignees_raw.split('||').map(a=>{const[id,fn,un,ac]=a.split('::');return{id:parseInt(id),full_name:fn,username:un,avatar_color:ac};}).filter(a=>!isNaN(a.id)):[]
});

app.get('/api/tasks', auth, wrap(async(req,res)=>{
  const{status,tag}=req.query;
  const isAdmin=req.user.role==='admin';
  const supAll=req.user.role==='supervisor'&&req.user.permissions?.can_view_all_tasks;
  const showAll=isAdmin||supAll;
  const userId=req.user.id;
  let vis=showAll?'1=1':`(t.creator_id=? OR t.id IN(SELECT task_id FROM task_assignees WHERE user_id=?)) AND t.id NOT IN(SELECT task_id FROM task_revoked WHERE user_id=?)`;
  const params=showAll?[]:[userId,userId,userId];
  let extra='';
  if(status){extra+=' AND t.status=?';params.push(status);}
  if(tag){extra+=` AND t.id IN(SELECT tt2.task_id FROM task_tags tt2 JOIN tags tg2 ON tt2.tag_id=tg2.id WHERE tg2.name=?)`;params.push(tag);}
  const sql=`SELECT DISTINCT t.*,u1.username as creator_username,u1.full_name as creator_name,u1.avatar_color as creator_color,
    GROUP_CONCAT(DISTINCT CONCAT(tg.name,'::',tg.color) ORDER BY tg.name SEPARATOR '||') as tags_raw,
    GROUP_CONCAT(DISTINCT CONCAT(u2.id,'::',IFNULL(u2.full_name,''),'::',u2.username,'::',IFNULL(u2.avatar_color,'#3B82F6')) ORDER BY u2.full_name SEPARATOR '||') as assignees_raw
  FROM tasks t LEFT JOIN users u1 ON t.creator_id=u1.id LEFT JOIN task_assignees ta ON t.id=ta.task_id
  LEFT JOIN users u2 ON ta.user_id=u2.id LEFT JOIN task_tags tt ON t.id=tt.task_id LEFT JOIN tags tg ON tt.tag_id=tg.id
  WHERE (${vis}) ${extra} GROUP BY t.id ORDER BY t.created_at DESC`;
  const[rows]=await pool.query(sql,params);
  res.json(rows.map(parseTask));
}));

app.get('/api/tasks/:id', auth, wrap(async(req,res)=>{
  const access=await hasTaskAccess(req.params.id,req.user.id,req.user.role);
  if(access==='none') return res.status(403).json({error:'Access denied'});
  const[rows]=await pool.query(`SELECT DISTINCT t.*,u1.username as creator_username,u1.full_name as creator_name,u1.avatar_color as creator_color,
    GROUP_CONCAT(DISTINCT CONCAT(tg.name,'::',tg.color) ORDER BY tg.name SEPARATOR '||') as tags_raw,
    GROUP_CONCAT(DISTINCT CONCAT(u2.id,'::',IFNULL(u2.full_name,''),'::',u2.username,'::',IFNULL(u2.avatar_color,'#3B82F6')) ORDER BY u2.full_name SEPARATOR '||') as assignees_raw
  FROM tasks t LEFT JOIN users u1 ON t.creator_id=u1.id LEFT JOIN task_assignees ta ON t.id=ta.task_id
  LEFT JOIN users u2 ON ta.user_id=u2.id LEFT JOIN task_tags tt ON t.id=tt.task_id LEFT JOIN tags tg ON tt.tag_id=tg.id
  WHERE t.id=? GROUP BY t.id`,[req.params.id]);
  if(!rows.length) return res.status(404).json({error:'Not found'});
  const task=parseTask(rows[0]);
  if(req.user.role==='admin'){
    const[revoked]=await pool.query('SELECT u.id,u.full_name,u.avatar_color FROM task_revoked tr JOIN users u ON tr.user_id=u.id WHERE tr.task_id=?',[req.params.id]);
    task.revoked_users=revoked;
  }
  res.json({...task,access});
}));

app.post('/api/tasks', auth, wrap(async(req,res)=>{
  const isAdmin=req.user.role==='admin',isSupervisor=req.user.role==='supervisor',isMember=req.user.role==='member';
  const canCreate=isAdmin||(isSupervisor&&req.user.permissions?.can_create_tasks)||isMember;
  if(!canCreate) return res.status(403).json({error:'Permission denied'});
  const{title,description,status,priority,assignee_ids,due_date,tags}=req.body;
  if(!title?.trim()) return res.status(400).json({error:'Title required'});
  const[r]=await pool.query('INSERT INTO tasks(title,description,status,priority,creator_id,due_date) VALUES(?,?,?,?,?,?)',[title.trim(),description||'',status||'todo',priority||'medium',req.user.id,due_date||null]);
  const taskId=r.insertId;
  const rawList=Array.isArray(assignee_ids)?assignee_ids.map(Number):[];
  const aList=isMember?[req.user.id]:(rawList.length?rawList:[req.user.id]);
  for(const uid of aList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}
  if(Array.isArray(tags)&&tags.length){for(const tn of tags){try{let[tr]=await pool.query('SELECT id FROM tags WHERE name=?',[tn]);const tid=tr.length?tr[0].id:(await pool.query('INSERT INTO tags(name) VALUES(?)',[tn]))[0].insertId;await pool.query('INSERT IGNORE INTO task_tags VALUES(?,?)',[taskId,tid]);}catch{}}}
  await logHistory(taskId,req.user.id,'created',null,null,title.trim(),null);
  const[aNames]=await pool.query('SELECT full_name FROM users WHERE id IN('+aList.map(()=>'?').join(',')+')',aList);
  await logHistory(taskId,req.user.id,'assigned','assignees',null,aNames.map(u=>u.full_name).join(', '),null);
  for(const uid of aList){if(uid!==req.user.id){try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'assigned']);sendEmail(uid,req.user.username,title,'assigned').catch(()=>{});}catch{}}}
  res.json({id:taskId});
}));

app.put('/api/tasks/:id', auth, wrap(async(req,res)=>{
  const isAdmin=req.user.role==='admin';
  const canEdit=isAdmin||(req.user.role==='supervisor'&&req.user.permissions?.can_edit_tasks);
  if(!canEdit) return res.status(403).json({error:'Only admins and authorised supervisors can fully edit tasks'});
  const{title,description,status,priority,assignee_ids,due_date}=req.body;
  const taskId=req.params.id;
  const[old]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!old.length) return res.status(404).json({error:'Task not found'});
  const prev=old[0];
  await pool.query('UPDATE tasks SET title=?,description=?,status=?,priority=?,due_date=? WHERE id=?',[title||prev.title,description??prev.description,status||prev.status,priority||prev.priority,due_date||null,taskId]);
  if(prev.status!==(status||prev.status)) await logHistory(taskId,req.user.id,'status_changed','status',prev.status,status,null);
  if(prev.priority!==(priority||prev.priority)) await logHistory(taskId,req.user.id,'priority_changed','priority',prev.priority,priority,null);
  if((title||prev.title)!==prev.title) await logHistory(taskId,req.user.id,'edited','title',prev.title,title,null);
  if(Array.isArray(assignee_ids)){
    const newList=assignee_ids.map(Number);
    const[oldRows]=await pool.query('SELECT ta.user_id,u.full_name FROM task_assignees ta JOIN users u ON ta.user_id=u.id WHERE ta.task_id=?',[taskId]);
    const oldList=oldRows.map(r=>r.user_id);
    const newlyAdded=newList.filter(id=>!oldList.includes(id)),removed=oldList.filter(id=>!newList.includes(id));
    await pool.query('DELETE FROM task_assignees WHERE task_id=?',[taskId]);
    for(const uid of newList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}
    if(newList.length) await pool.query('DELETE FROM task_revoked WHERE task_id=? AND user_id IN('+newList.map(()=>'?').join(',')+')',[taskId,...newList]).catch(()=>{});
    if(newlyAdded.length){const[addNames]=await pool.query('SELECT full_name FROM users WHERE id IN('+newlyAdded.map(()=>'?').join(',')+')',newlyAdded);await logHistory(taskId,req.user.id,'assigned','assignees',null,addNames.map(u=>u.full_name).join(', '),null);}
    if(removed.length){const removedNames=oldRows.filter(r=>removed.includes(r.user_id)).map(r=>r.full_name);await logHistory(taskId,req.user.id,'unassigned','assignees',removedNames.join(', '),null,null);}
    for(const uid of newlyAdded){if(uid!==req.user.id){try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'assigned']);sendEmail(uid,req.user.username,title,'assigned').catch(()=>{});}catch{}}}
  }
  res.json({success:true});
}));

app.delete('/api/tasks/:id', auth, adminOnly, wrap(async(req,res)=>{
  await pool.query('DELETE FROM tasks WHERE id=?',[req.params.id]);res.json({success:true});
}));

app.post('/api/tasks/:id/status', auth, wrap(async(req,res)=>{
  const taskId=req.params.id,userId=req.user.id,{new_status,comment}=req.body;
  if(!new_status) return res.status(400).json({error:'new_status required'});
  if(!comment?.trim()) return res.status(400).json({error:'A comment is required when changing status'});
  const access=await hasTaskAccess(taskId,userId,req.user.role);
  if(access==='none') return res.status(403).json({error:'You do not have access to this task'});
  if(req.user.role!=='admin'){const[assigned]=await pool.query('SELECT 1 FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);if(!assigned.length) return res.status(403).json({error:'Only current assignees can change task status'});}
  const[taskRows]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!taskRows.length) return res.status(404).json({error:'Task not found'});
  const prev=taskRows[0];
  if(prev.status===new_status) return res.status(400).json({error:'Task already has this status'});
  await pool.query('UPDATE tasks SET status=? WHERE id=?',[new_status,taskId]);
  await logHistory(taskId,userId,'status_changed','status',prev.status,new_status,comment.trim());
  const[assignees]=await pool.query('SELECT user_id FROM task_assignees WHERE task_id=? AND user_id!=?',[taskId,userId]);
  for(const a of assignees){try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[a.user_id,taskId,userId,'status_changed']);}catch{}}
  res.json({success:true});
}));

app.post('/api/tasks/:id/comment', auth, wrap(async(req,res)=>{
  const taskId=req.params.id,userId=req.user.id,{comment}=req.body;
  if(!comment?.trim()) return res.status(400).json({error:'Comment cannot be empty'});
  const access=await hasTaskAccess(taskId,userId,req.user.role);
  if(access==='none') return res.status(403).json({error:'Access denied'});
  await logHistory(taskId,userId,'comment',null,null,null,comment.trim());
  res.json({success:true});
}));

app.delete('/api/tasks/:tid/history/:hid', auth, adminOnly, wrap(async(req,res)=>{
  await pool.query('DELETE FROM task_history WHERE id=? AND task_id=?',[req.params.hid,req.params.tid]);
  res.json({success:true});
}));

app.post('/api/tasks/:id/move-to', auth, wrap(async(req,res)=>{
  const taskId=req.params.id,userId=req.user.id,isAdmin=req.user.role==='admin';
  const{new_assignee_ids,comment}=req.body;
  if(!Array.isArray(new_assignee_ids)||!new_assignee_ids.length) return res.status(400).json({error:'At least one new assignee required'});
  const access=await hasTaskAccess(taskId,userId,req.user.role);
  if(access==='none') return res.status(403).json({error:'You have no access to this task'});
  if(!isAdmin){const[assigned]=await pool.query('SELECT 1 FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);if(!assigned.length) return res.status(403).json({error:'Only current assignees can move this task'});}
  const[taskRows]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!taskRows.length) return res.status(404).json({error:'Task not found'});
  const task=taskRows[0];
  const[oldRows]=await pool.query('SELECT ta.user_id,u.full_name FROM task_assignees ta JOIN users u ON ta.user_id=u.id WHERE ta.task_id=?',[taskId]);
  const oldNames=oldRows.map(r=>r.full_name).join(', ')||'—';
  const newList=new_assignee_ids.map(Number);
  await pool.query('DELETE FROM task_assignees WHERE task_id=?',[taskId]);
  for(const uid of newList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}
  if(!isAdmin&&!newList.includes(userId)) await pool.query('INSERT IGNORE INTO task_revoked(task_id,user_id) VALUES(?,?)',[taskId,userId]);
  const[newNames]=await pool.query('SELECT full_name FROM users WHERE id IN('+newList.map(()=>'?').join(',')+')',newList);
  await logHistory(taskId,userId,'moved','assignees',oldNames,newNames.map(u=>u.full_name).join(', '),comment||null);
  for(const uid of newList){if(uid!==userId){try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,userId,'reassigned']);sendEmail(uid,req.user.username,task.title,'reassigned').catch(()=>{});}catch{}}}
  res.json({success:true});
}));

app.post('/api/tasks/:id/complete', auth, wrap(async(req,res)=>{
  const taskId=req.params.id,userId=req.user.id,isAdmin=req.user.role==='admin';
  const{new_assignee_ids,comment}=req.body;
  if(!isAdmin){const[assigned]=await pool.query('SELECT 1 FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);if(!assigned.length) return res.status(403).json({error:'Not assigned to this task'});}
  const[taskRows]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!taskRows.length) return res.status(404).json({error:'Not found'});
  const task=taskRows[0];
  await pool.query('UPDATE tasks SET status=? WHERE id=?',['done',taskId]);
  await logHistory(taskId,userId,'status_changed','status',task.status,'done',comment||null);
  const newList=Array.isArray(new_assignee_ids)?new_assignee_ids.map(Number):[];
  if(newList.length){
    await pool.query('DELETE FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);
    for(const uid of newList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}
    if(!isAdmin&&!newList.includes(userId)) await pool.query('INSERT IGNORE INTO task_revoked(task_id,user_id) VALUES(?,?)',[taskId,userId]);
    const[nn]=await pool.query('SELECT full_name FROM users WHERE id IN('+newList.map(()=>'?').join(',')+')',newList);
    await logHistory(taskId,userId,'moved','assignees','(completed)',nn.map(u=>u.full_name).join(', '),null);
    for(const uid of newList){if(uid!==userId){try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,userId,'reassigned']);sendEmail(uid,req.user.username,task.title,'reassigned').catch(()=>{});}catch{}}}
  }
  res.json({success:true});
}));

app.get('/api/tasks/:id/history', auth, wrap(async(req,res)=>{
  const taskId=req.params.id;
  const access=await hasTaskAccess(taskId,req.user.id,req.user.role);
  if(access==='none'&&req.user.role!=='admin') return res.status(403).json({error:'Access denied'});
  const[rows]=await pool.query(`SELECT th.*,u.full_name as actor_name,u.username as actor_username,u.avatar_color as actor_color,u.role as actor_role FROM task_history th JOIN users u ON th.user_id=u.id WHERE th.task_id=? ORDER BY th.created_at ASC`,[taskId]);
  res.json(rows);
}));

/* ══════════════════════════════════════
   TAGS & NOTIFICATIONS
══════════════════════════════════════ */
app.get('/api/tags', auth, wrap(async(req,res)=>{const[rows]=await pool.query('SELECT * FROM tags ORDER BY name');res.json(rows);}));
app.get('/api/notifications', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query(`
    SELECT n.*,
      t.title as task_title,
      u.username as triggered_by,
      u.full_name as triggered_by_name,
      u.avatar_color as triggered_by_color
    FROM notifications n
    LEFT JOIN tasks t ON n.task_id=t.id
    LEFT JOIN users u ON n.triggered_by_id=u.id
    WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 50`,[req.user.id]);
  res.json(rows);
}));
app.put('/api/notifications/:id/read', auth, wrap(async(req,res)=>{await pool.query('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?',[req.params.id,req.user.id]);res.json({success:true});}));
app.put('/api/notifications/read-all', auth, wrap(async(req,res)=>{await pool.query('UPDATE notifications SET is_read=1 WHERE user_id=?',[req.user.id]);res.json({success:true});}));

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
  if(req.user.role==='admin') return res.status(403).json({error:'Administrators manage attendance through the panel.'});
  const userId=req.user.id,now=new Date(),today=localDate(now);

  // Fetch user's category
  const[urows]=await pool.query('SELECT employee_category FROM users WHERE id=?',[userId]);
  const category=(urows[0]?.employee_category)||'office';

  const[hols]=await pool.query('SELECT * FROM holidays WHERE holiday_date=?',[today]);
  if(hols.length) return res.status(400).json({error:`Today is a holiday: ${hols[0].name}`});
  const[ex]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  if(ex.length) return res.status(400).json({error:'Already clocked in today'});

  const eval_=evaluateClockIn(now,category);
  const insertData={
    user_id:userId, work_date:today, clock_in:now,
    clock_in_status:eval_.clock_in_status,
    clock_in_flag:eval_.flag,
  };
  if(eval_.approved_clock_in){
    insertData.approved_clock_in=eval_.approved_clock_in;
  }

  await pool.query(`INSERT INTO attendance(user_id,work_date,clock_in,clock_in_status,clock_in_flag,approved_clock_in) VALUES(?,?,?,?,?,?)`,
    [userId,today,now,eval_.clock_in_status,eval_.flag,eval_.approved_clock_in||null]);

  await ensureSundaysHolidays(today.slice(0,7)+'-01',localDate(new Date(now.getFullYear(),now.getMonth()+1,0)));

  const msg=eval_.clock_in_status==='approved'
    ? (eval_.flag==='on_time'?'Clocked in — on time ✓':'Clocked in — recorded')
    : (eval_.flag==='late'?'Clocked in late — awaiting manager approval':'Clocked in — awaiting approval');

  res.json({success:true,message:msg,clock_in:now,status:eval_.clock_in_status,flag:eval_.flag,category,rules:getRulesForCategory(category)});
  // If late arrival flagged → alert admins & supervisors
  if(eval_.flag==='late'){
    const[uInfo]=await pool.query('SELECT full_name FROM users WHERE id=?',[userId]);
    const uName=uInfo[0]?.full_name||'An employee';
    await notifyAdmins({triggeredById:userId,type:'late_arrival',title:'Late Arrival',message:`${uName} clocked in late at ${timeHHMM(now)} on ${today}.`}).catch(()=>{});
    await notifySupervisors({triggeredById:userId,type:'late_arrival',title:'Late Arrival',message:`${uName} clocked in late at ${timeHHMM(now)} on ${today}.`}).catch(()=>{});
  }
}));

app.post('/api/attendance/clock-out', auth, wrap(async(req,res)=>{
  if(req.user.role==='admin') return res.status(403).json({error:'Administrators do not clock out.'});
  const userId=req.user.id,now=new Date(),today=localDate(now);

  const[urows]=await pool.query('SELECT employee_category FROM users WHERE id=?',[userId]);
  const category=(urows[0]?.employee_category)||'office';

  const[rows]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  if(!rows.length) return res.status(400).json({error:'You have not clocked in today'});
  if(rows[0].clock_out) return res.status(400).json({error:'Already clocked out today'});

  const eval_=evaluateClockOut(now,category);
  let approved_co=eval_.approved_clock_out||null;

  await pool.query('UPDATE attendance SET clock_out=?,clock_out_status=?,clock_out_flag=?,approved_clock_out=? WHERE id=?',
    [now,eval_.clock_out_status,eval_.flag,approved_co,rows[0].id]);

  const msg=eval_.clock_out_status==='approved'
    ? 'Clocked out — recorded ✓'
    : (eval_.flag==='early'?'Early clock-out flagged — awaiting manager approval':'Clocked out — awaiting approval');

  res.json({success:true,message:msg,clock_out:now,status:eval_.clock_out_status,flag:eval_.flag});
  if(eval_.flag==='early'){
    const[uInfo]=await pool.query('SELECT full_name FROM users WHERE id=?',[userId]);
    const uName=uInfo[0]?.full_name||'An employee';
    await notifyAdmins({triggeredById:userId,type:'early_departure',title:'Early Departure',message:`${uName} clocked out early at ${timeHHMM(now)} on ${today}.`}).catch(()=>{});
    await notifySupervisors({triggeredById:userId,type:'early_departure',title:'Early Departure',message:`${uName} clocked out early at ${timeHHMM(now)} on ${today}.`}).catch(()=>{});
  }
}));

function getRulesForCategory(cat){
  if(cat==='office') return {
    ci:'08:45 – 09:10 (auto-approved)',co:'17:45 – 18:30 (auto-approved)',type:'office'
  };
  return {
    ci:'Up to 09:35 on-time; after = late (needs approval)',co:'18:00 – 19:00 auto-approved; before 18:00 = early (needs approval)',type:'field'
  };
}

app.get('/api/attendance/today', auth, wrap(async(req,res)=>{
  if(req.user.role==='admin') return res.json({record:null,holiday:null,today:localDate(),isAdmin:true});
  const userId=req.user.id,today=localDate(new Date());
  const[rows]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  const[hols]=await pool.query('SELECT * FROM holidays WHERE holiday_date=?',[today]);
  const[urows]=await pool.query('SELECT employee_category,department FROM users WHERE id=?',[userId]);
  const category=(urows[0]?.employee_category)||'office';
  res.json({record:rows[0]||null,holiday:hols[0]||null,today,isAdmin:false,category,rules:getRulesForCategory(category)});
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
    const ds=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`,dow=new Date(ds+'T12:00:00').getDay(),today=localDate(new Date());
    if(ds>today){report.push({date:ds,day_of_week:dow,type:'future'});continue;}
    if(holidayMap[ds]){report.push({date:ds,day_of_week:dow,type:'holiday',holiday_name:holidayMap[ds].name,holiday_type:holidayMap[ds].type});continue;}
    if(recordMap[ds]){report.push({date:ds,day_of_week:dow,type:'attendance',...recordMap[ds]});continue;}
    report.push({date:ds,day_of_week:dow,type:'absent'});
  }
  const stats={
    approved:report.filter(d=>d.type==='attendance'&&d.clock_in_status==='approved').length,
    pending:report.filter(d=>d.type==='attendance'&&d.clock_in_status==='pending').length,
    late:report.filter(d=>d.type==='attendance'&&d.clock_in_flag==='late').length,
    absent:report.filter(d=>d.type==='absent').length,
    holidays:report.filter(d=>d.type==='holiday').length,
    total_work_hours:records.filter(r=>r.approved_clock_in&&r.approved_clock_out).reduce((s,r)=>s+(new Date(r.approved_clock_out)-new Date(r.approved_clock_in))/3600000,0).toFixed(1)
  };
  res.json({report,stats,year:y,month:m});
}));

/* Admin: all attendance records */
app.get('/api/admin/attendance', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_view_all_attendance) return res.status(403).json({error:'Permission denied'});
  const{year,month,user_id,status,category}=req.query;
  const y=parseInt(year)||new Date().getFullYear(),m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`,lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;
  await ensureSundaysHolidays(startDate,endDate);
  let sql=`SELECT a.*,u.full_name,u.username,u.avatar_color,u.employee_category,u.department,
    ab.full_name as approver_name,ab.username as approver_username,ab.avatar_color as approver_avatar_color,ab.role as approver_role
    FROM attendance a JOIN users u ON a.user_id=u.id LEFT JOIN users ab ON a.approved_by=ab.id
    WHERE a.work_date BETWEEN ? AND ?`;
  const params=[startDate,endDate];
  if(user_id){sql+=' AND a.user_id=?';params.push(user_id);}
  if(category){sql+=' AND u.employee_category=?';params.push(category);}
  if(status==='pending'){sql+=" AND(a.clock_in_status='pending' OR a.clock_out_status='pending')";}
  else if(status==='late'){sql+=" AND a.clock_in_flag='late'";}
  else if(status==='early'){sql+=" AND a.clock_out_flag='early'";}
  else if(status){sql+=' AND a.clock_in_status=?';params.push(status);}
  sql+=' ORDER BY a.work_date DESC,u.full_name';
  const[records]=await pool.query(sql,params);
  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ?',[startDate,endDate]);
  // Build per-user day reports — include all members + supervisors who clock in
  const[users]=await pool.query(`SELECT id,full_name,username,avatar_color,employee_category,department FROM users WHERE is_active=1 AND role IN('member','supervisor') ORDER BY full_name`);
  const holidayMap={},userReports={};holidays.forEach(h=>holidayMap[h.holiday_date]=h);
  for(const u of users){
    userReports[u.id]={user:u,days:[]};const userRecs={};records.filter(r=>r.user_id===u.id).forEach(r=>userRecs[r.work_date]=r);
    for(let d=1;d<=lastD;d++){
      const ds=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`,today=localDate(new Date());
      if(ds>today)continue;
      if(holidayMap[ds]){userReports[u.id].days.push({date:ds,type:'holiday',name:holidayMap[ds].name,holiday_type:holidayMap[ds].type});continue;}
      if(userRecs[ds]){userReports[u.id].days.push({date:ds,type:'attendance',...userRecs[ds]});continue;}
      userReports[u.id].days.push({date:ds,type:'absent'});
    }
  }
  const[[totals]]=await pool.query(`SELECT COUNT(*) as total,SUM(clock_in_status='pending') as pending,SUM(clock_in_status='approved') as approved,SUM(clock_in_status='rejected') as rejected,SUM(clock_in_flag='late') as late_checkins,SUM(clock_out_flag='early') as early_checkouts FROM attendance WHERE work_date BETWEEN ? AND ?`,[startDate,endDate]);
  res.json({records,holidays,userReports:Object.values(userReports),stats:totals,year:y,month:m});
}));

app.put('/api/admin/attendance/:id', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_approve_attendance) return res.status(403).json({error:'Permission denied'});
  const{clock_in_status,clock_out_status,approved_clock_in,approved_clock_out,admin_note}=req.body;
  const id=req.params.id;
  const[rows]=await pool.query('SELECT * FROM attendance WHERE id=?',[id]);
  if(!rows.length) return res.status(404).json({error:'Record not found'});
  const rec=rows[0];const u=[],v=[];
  if(clock_in_status!==undefined){
    u.push('clock_in_status=?');v.push(clock_in_status);
    if(clock_in_status==='approved'){
      const cin=approved_clock_in!==undefined?approved_clock_in:rec.clock_in;
      u.push('approved_clock_in=?');v.push(toMySQL(cin));
      u.push('approved_by=?');v.push(req.user.id);
      u.push('approved_at=NOW()');
    }
    if(clock_in_status==='rejected'){u.push('approved_by=?');v.push(req.user.id);u.push('approved_at=NOW()');}
  }
  if(clock_out_status!==undefined){
    u.push('clock_out_status=?');v.push(clock_out_status);
    if(clock_out_status==='approved'){
      const cout=approved_clock_out!==undefined?approved_clock_out:rec.clock_out;
      u.push('approved_clock_out=?');v.push(toMySQL(cout));
      if(clock_in_status===undefined){u.push('approved_by=?');v.push(req.user.id);u.push('approved_at=NOW()');}
    }
  }
  if(clock_in_status===undefined&&clock_out_status===undefined){
    if(approved_clock_in!==undefined){u.push('approved_clock_in=?');v.push(toMySQL(approved_clock_in));}
    if(approved_clock_out!==undefined){u.push('approved_clock_out=?');v.push(toMySQL(approved_clock_out));}
  }
  if(admin_note!==undefined){u.push('admin_note=?');v.push(admin_note);}
  if(!u.length) return res.status(400).json({error:'Nothing to update'});
  v.push(id);await pool.query(`UPDATE attendance SET ${u.join(',')} WHERE id=?`,v);
  // Notify the employee about their attendance status change
  try{
    const statusMsg=clock_in_status||clock_out_status;
    if(statusMsg==='approved'||statusMsg==='rejected'){
      const[recRow]=await pool.query('SELECT user_id,work_date FROM attendance WHERE id=?',[id]);
      if(recRow.length){
        const[revName]=await pool.query('SELECT full_name FROM users WHERE id=?',[req.user.id]);
        const rn=revName[0]?.full_name||'Manager';
        const isApproved=statusMsg==='approved';
        await notify({
          userId:recRow[0].user_id, triggeredById:req.user.id,
          type:`attendance_${statusMsg}`,
          title:`Attendance ${isApproved?'Approved ✓':'Rejected ✗'}`,
          message:`Your attendance for ${recRow[0].work_date} has been ${statusMsg} by ${rn}.${admin_note?' Note: '+admin_note:''}`
        }).catch(()=>{});
      }
    }
  }catch{}
  res.json({success:true});
}));

app.post('/api/admin/attendance/bulk-approve', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_approve_attendance) return res.status(403).json({error:'Permission denied'});
  const{ids}=req.body;
  if(!Array.isArray(ids)||!ids.length) return res.status(400).json({error:'No IDs'});
  await pool.query(`UPDATE attendance SET clock_in_status='approved',approved_by=?,approved_at=NOW(),approved_clock_in=COALESCE(approved_clock_in,clock_in),approved_clock_out=COALESCE(approved_clock_out,clock_out) WHERE id IN(${ids.map(()=>'?').join(',')}) AND clock_in_status='pending'`,[req.user.id,...ids]);
  res.json({success:true});
}));

/* Admin attendance stats — comprehensive with category breakdown */
app.get('/api/admin/attendance/stats', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_view_all_attendance) return res.status(403).json({error:'Permission denied'});
  const{year,month}=req.query;
  const y=parseInt(year)||new Date().getFullYear(),m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`,lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;
  await ensureSundaysHolidays(startDate,endDate);

  // Overall
  const[[overall]]=await pool.query(`SELECT
    COUNT(*) as total_checkins,
    SUM(clock_in_status='pending') as pending,
    SUM(clock_in_status='approved') as approved,
    SUM(clock_in_status='rejected') as rejected,
    SUM(clock_in_flag='late') as late_checkins,
    SUM(clock_out_flag='early') as early_checkouts,
    COUNT(DISTINCT user_id) as unique_users
    FROM attendance WHERE work_date BETWEEN ? AND ?`,[startDate,endDate]);

  // Per employee with category
  const[perUser]=await pool.query(`SELECT
    u.id,u.full_name,u.username,u.avatar_color,u.employee_category,u.department,
    COUNT(a.id) as check_ins,
    COALESCE(SUM(a.clock_in_status='approved'),0) as approved,
    COALESCE(SUM(a.clock_in_status='pending'),0) as pending,
    COALESCE(SUM(a.clock_in_status='rejected'),0) as rejected,
    COALESCE(SUM(a.clock_in_flag='late'),0) as late,
    COALESCE(SUM(a.clock_out_flag='early'),0) as early_out
    FROM users u
    LEFT JOIN attendance a ON u.id=a.user_id AND a.work_date BETWEEN ? AND ?
    WHERE u.is_active=1 AND u.role IN('member','supervisor')
    GROUP BY u.id ORDER BY u.employee_category,u.full_name`,[startDate,endDate]);

  // Daily breakdown
  const[daily]=await pool.query(`SELECT
    work_date as date,
    COUNT(*) as total,
    SUM(clock_in_status='approved') as approved,
    SUM(clock_in_status='pending') as pending,
    SUM(clock_in_flag='late') as late
    FROM attendance WHERE work_date BETWEEN ? AND ? GROUP BY work_date ORDER BY work_date`,[startDate,endDate]);

  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ? ORDER BY holiday_date',[startDate,endDate]);

  // Compute working days up to today
  const today=localDate(new Date()),holidayDates=new Set(holidays.map(h=>h.holiday_date));
  let workingDays=0;
  for(let d=1;d<=lastD;d++){
    const ds=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    if(ds<=today&&!holidayDates.has(ds))workingDays++;
  }

  // Category totals
  const[[office]]=await pool.query(`SELECT COUNT(DISTINCT u.id) as total_users,
    COALESCE(SUM(a.clock_in_status='approved'),0) as approved,
    COALESCE(SUM(a.clock_in_status='pending'),0) as pending,
    COALESCE(SUM(a.clock_in_flag='late'),0) as late
    FROM users u LEFT JOIN attendance a ON u.id=a.user_id AND a.work_date BETWEEN ? AND ?
    WHERE u.is_active=1 AND u.employee_category='office' AND u.role IN('member','supervisor')`,[startDate,endDate]);
  const[[field]]=await pool.query(`SELECT COUNT(DISTINCT u.id) as total_users,
    COALESCE(SUM(a.clock_in_status='approved'),0) as approved,
    COALESCE(SUM(a.clock_in_status='pending'),0) as pending,
    COALESCE(SUM(a.clock_in_flag='late'),0) as late,
    COALESCE(SUM(a.clock_out_flag='early'),0) as early_out
    FROM users u LEFT JOIN attendance a ON u.id=a.user_id AND a.work_date BETWEEN ? AND ?
    WHERE u.is_active=1 AND u.employee_category='field' AND u.role IN('member','supervisor')`,[startDate,endDate]);

  res.json({overall,perUser,daily,holidays,workingDays,office,field,year:y,month:m});
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
   ADMIN SELF-SERVICE ACCOUNT ROUTES
══════════════════════════════════════ */
/* Get current admin's own full info including login history */
app.get('/api/auth/me', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query(
    'SELECT id,username,email,full_name,role,avatar_color,last_login_at,last_login_ip,must_change_password,created_at FROM users WHERE id=?',
    [req.user.id]);
  if(!rows.length) return res.status(404).json({error:'Not found'});
  res.json(rows[0]);
}));

/* Admin updates own email */
app.put('/api/auth/change-email', auth, adminOnly, wrap(async(req,res)=>{
  const{email,password}=req.body;
  if(!email?.trim()) return res.status(400).json({error:'Email required'});
  // Verify current password
  const[rows]=await pool.query('SELECT password_hash FROM users WHERE id=?',[req.user.id]);
  if(!rows.length) return res.status(404).json({error:'User not found'});
  if(!await bcrypt.compare(password,rows[0].password_hash))
    return res.status(400).json({error:'Current password incorrect'});
  // Check unique
  const[existing]=await pool.query('SELECT id FROM users WHERE email=? AND id!=?',[email.trim(),req.user.id]);
  if(existing.length) return res.status(400).json({error:'Email already in use'});
  await pool.query('UPDATE users SET email=? WHERE id=?',[email.trim(),req.user.id]);
  res.json({success:true,message:'Email updated successfully'});
}));

/* ══════════════════════════════════════
   PASSWORD CHANGE (forced or voluntary)
══════════════════════════════════════ */
app.post('/api/auth/change-password', auth, wrap(async(req,res)=>{
  const{current_password,new_password}=req.body;
  if(!new_password||new_password.length<8) return res.status(400).json({error:'New password must be at least 8 characters'});
  const[rows]=await pool.query('SELECT * FROM users WHERE id=?',[req.user.id]);
  if(!rows.length) return res.status(404).json({error:'User not found'});
  const u=rows[0];
  // If not a forced change, verify current password
  if(!u.must_change_password){
    if(!current_password) return res.status(400).json({error:'Current password required'});
    if(!await bcrypt.compare(current_password,u.password_hash)) return res.status(400).json({error:'Current password is incorrect'});
  }
  const hash=await bcrypt.hash(new_password,10);
  await pool.query('UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?',[hash,req.user.id]);
  res.json({success:true,message:'Password changed successfully'});
}));

/* Admin: force-reset any user's password */
app.post('/api/admin/users/:id/reset-password', auth, adminOnly, wrap(async(req,res)=>{
  const{new_password,force_change}=req.body;
  if(!new_password||new_password.length<6) return res.status(400).json({error:'Password must be at least 6 characters'});
  const hash=await bcrypt.hash(new_password,10);
  const mustChange=force_change===false?0:1;
  await pool.query('UPDATE users SET password_hash=?,must_change_password=? WHERE id=?',[hash,mustChange,req.params.id]);
  res.json({success:true,message:mustChange?'Password reset. User will be prompted to change it on next login.':'Password reset successfully.'});
}));

/* ══════════════════════════════════════
   LEAVE APPLICATIONS  — v5
   Annual leave requires ALL supervisors
   to individually approve before final
   status becomes 'approved'.
══════════════════════════════════════ */

const LEAVE_CONFIG = {
  medical:   { days:12,  reason:false, label:'Medical Leave',   allSupervisors:false },
  emergency: { days:6,   reason:true,  label:'Emergency Leave', allSupervisors:false },
  annual:    { days:14,  reason:false, label:'Annual Leave',    allSupervisors:true  },
  half_day:  { days:99,  reason:true,  label:'Half Day',        allSupervisors:false },
  others:    { days:5,   reason:true,  label:'Other Leave',     allSupervisors:false },
};

/* Ensure every active supervisor has an approval row for this leave */
async function ensureApprovalRows(leaveId){
  const[sups]=await pool.query(
    "SELECT id FROM users WHERE role='supervisor' AND is_active=1");
  for(const sup of sups){
    await pool.query(
      'INSERT IGNORE INTO leave_approvals(leave_id,supervisor_id,decision) VALUES(?,?,?)',
      [leaveId, sup.id, 'pending']).catch(()=>{});
  }
  return sups.length;
}

/* After each supervisor decision, check if we can finalise */
async function tryFinalise(leaveId){
  const[[leave]]=await pool.query(
    'SELECT * FROM leave_applications WHERE id=?',[leaveId]);
  if(!leave||leave.status!=='pending') return; // already done

  const[rows]=await pool.query(
    'SELECT * FROM leave_approvals WHERE leave_id=?',[leaveId]);

  if(!rows.length) return; // no supervisors exist yet

  // Any rejection → reject immediately
  const rej = rows.find(r=>r.decision==='rejected');
  if(rej){
    await pool.query(
      "UPDATE leave_applications SET status='rejected',reviewed_by=?,reviewed_at=NOW() WHERE id=?",
      [rej.supervisor_id, leaveId]);
    return;
  }

  // All must have approved (none still pending)
  const allDone  = rows.every(r=>r.decision!=='pending');
  const allApproved = rows.every(r=>r.decision==='approved');

  if(allDone && allApproved){
    // Find who gave the last approval to set as reviewer
    const last = rows.sort((a,b)=>new Date(b.decided_at)-new Date(a.decided_at))[0];
    await pool.query(
      "UPDATE leave_applications SET status='approved',reviewed_by=?,reviewed_at=NOW() WHERE id=?",
      [last.supervisor_id, leaveId]);
    // Notify applicant — all supervisors approved
    const[[leaveRow]]=await pool.query('SELECT * FROM leave_applications WHERE id=?',[leaveId]);
    if(leaveRow){
      const lbl3=LEAVE_CONFIG[leaveRow.leave_type]?.label||leaveRow.leave_type;
      await notify({
        userId:leaveRow.user_id,
        type:'leave_approved',
        title:`${lbl3} Approved ✓`,
        message:`All supervisors have approved your ${lbl3} from ${leaveRow.start_date} to ${leaveRow.end_date}. Your leave is confirmed.`
      }).catch(()=>{});
      await notifyAdmins({
        triggeredById:leaveRow.user_id,
        type:'leave_fully_approved',
        title:`Annual Leave Fully Approved`,
        message:`All supervisors approved the annual leave for user ID ${leaveRow.user_id} (${leaveRow.start_date} – ${leaveRow.end_date}).`
      }).catch(()=>{});
    }
  }
}

/* ── Submit leave ── */
app.post('/api/leave', auth, wrap(async(req,res)=>{
  if(req.user.role==='admin')
    return res.status(403).json({error:'Admins use the override feature for leave.'});

  const{leave_type,start_date,end_date,reason,
        half_day_period,half_day_start,half_day_end}=req.body;

  const cfg = LEAVE_CONFIG[leave_type];
  if(!cfg) return res.status(400).json({error:'Invalid leave type'});
  if(!start_date||!end_date) return res.status(400).json({error:'Dates required'});
  if(cfg.reason&&!reason?.trim())
    return res.status(400).json({error:`Reason required for ${cfg.label}`});

  if(leave_type==='half_day'){
    if(!half_day_period)        return res.status(400).json({error:'Select Morning or Afternoon'});
    if(!half_day_start||!half_day_end) return res.status(400).json({error:'Time range required'});
    if(start_date!==end_date)   return res.status(400).json({error:'Half day must be a single day'});
  }

  const[overlap]=await pool.query(
    "SELECT id FROM leave_applications WHERE user_id=? AND status!='rejected' AND NOT(end_date<? OR start_date>?)",
    [req.user.id,start_date,end_date]);
  if(overlap.length)
    return res.status(400).json({error:'You already have a leave covering this period'});

  const[r]=await pool.query(
    `INSERT INTO leave_applications
      (user_id,leave_type,start_date,end_date,reason,half_day_period,half_day_start,half_day_end)
     VALUES(?,?,?,?,?,?,?,?)`,
    [req.user.id,leave_type,start_date,end_date,
     reason?.trim()||'',half_day_period||null,half_day_start||null,half_day_end||null]);

  const leaveId = r.insertId;
  let supCount  = 0;

  if(cfg.allSupervisors){
    supCount = await ensureApprovalRows(leaveId);
  }

  const msg = cfg.allSupervisors
    ? `Annual leave submitted — requires approval from all ${supCount} supervisor(s)`
    : 'Leave submitted — awaiting approval';

  // Notify all supervisors + admins about the new leave request
  const[applicant]=await pool.query('SELECT full_name FROM users WHERE id=?',[req.user.id]);
  const applicantName=applicant[0]?.full_name||'An employee';
  const leaveLabel=cfg.label;
  await notifySupervisors({
    triggeredById:req.user.id, type:'leave_submitted',
    title:`New ${leaveLabel} Request`,
    message:`${applicantName} submitted a ${leaveLabel} request from ${start_date} to ${end_date}.`
  });
  await notifyAdmins({
    triggeredById:req.user.id, type:'leave_submitted',
    title:`New ${leaveLabel} Request`,
    message:`${applicantName} submitted a ${leaveLabel} request from ${start_date} to ${end_date}.`
  });

  res.json({success:true, id:leaveId, message:msg});
}));

/* ── My applications ── */
app.get('/api/leave/my', auth, wrap(async(req,res)=>{
  const y=parseInt(req.query.year)||new Date().getFullYear();
  const[rows]=await pool.query(`
    SELECT la.*,rv.full_name as reviewer_name,rv.avatar_color as reviewer_color
    FROM leave_applications la
    LEFT JOIN users rv ON la.reviewed_by=rv.id
    WHERE la.user_id=? AND YEAR(la.start_date)=?
    ORDER BY la.created_at DESC`,[req.user.id,y]);

  for(const row of rows){
    if(LEAVE_CONFIG[row.leave_type]?.allSupervisors){
      await ensureApprovalRows(row.id); // ensure rows exist even for old applications
      const[approvals]=await pool.query(`
        SELECT la.decision,la.note,la.decided_at,
          u.full_name as supervisor_name,u.avatar_color,u.id as supervisor_id
        FROM leave_approvals la
        JOIN users u ON la.supervisor_id=u.id
        WHERE la.leave_id=? ORDER BY u.full_name`,[row.id]);
      row.supervisor_approvals=approvals;
    }
  }

  // Usage summary
  const usage={};
  for(const[t,cfg] of Object.entries(LEAVE_CONFIG)){
    const used=rows.filter(r=>r.leave_type===t&&r.status==='approved')
      .reduce((sum,r)=>sum+(t==='half_day'?0.5:Math.round((new Date(r.end_date)-new Date(r.start_date))/86400000)+1),0);
    usage[t]={used,allowed:cfg.days,label:cfg.label};
  }
  res.json({applications:rows,usage,year:y});
}));

/* ── Admin/Supervisor: all applications ── */
app.get('/api/admin/leave', auth, adminOrSupervisor, wrap(async(req,res)=>{
  const{status,year,user_id}=req.query;
  // NOTE: No month filter — leave applications are managed by YEAR only.
  // A leave submitted in Jan with April dates should show in the year view.
  const y=parseInt(year)||new Date().getFullYear();
  let sql=`SELECT la.*,
    u.full_name,u.username,u.avatar_color,u.employee_category,u.department,
    rv.full_name as reviewer_name,rv.avatar_color as reviewer_color
    FROM leave_applications la
    JOIN users u ON la.user_id=u.id
    LEFT JOIN users rv ON la.reviewed_by=rv.id
    WHERE la.user_id IS NOT NULL
    AND (YEAR(la.start_date)=? OR YEAR(la.end_date)=? OR YEAR(la.created_at)=?)`;
  const params=[y,y,y];
  if(status){sql+=' AND la.status=?';params.push(status);}
  if(user_id){sql+=' AND la.user_id=?';params.push(user_id);}
  sql+=' ORDER BY la.created_at DESC';
  const[rows]=await pool.query(sql,params);

  for(const row of rows){
    if(LEAVE_CONFIG[row.leave_type]?.allSupervisors){
      await ensureApprovalRows(row.id); // backfill rows for old applications
      const[approvals]=await pool.query(`
        SELECT la.decision,la.note,la.decided_at,
          u.full_name as supervisor_name,u.avatar_color,u.id as supervisor_id,u.role
        FROM leave_approvals la
        JOIN users u ON la.supervisor_id=u.id
        WHERE la.leave_id=? ORDER BY u.full_name`,[row.id]);
      row.supervisor_approvals=approvals;
    }
  }

  const[summary]=await pool.query(
    `SELECT leave_type,status,COUNT(*) as count FROM leave_applications
     WHERE (YEAR(start_date)=? OR YEAR(end_date)=? OR YEAR(created_at)=?)
     GROUP BY leave_type,status`,[y,y,y]);

  res.json({applications:rows,summary,year:y});
}));

/* ── Supervisor/Admin approve or reject ── */
app.put('/api/admin/leave/:id', auth, adminOrSupervisor, wrap(async(req,res)=>{
  const{status,reviewer_note,admin_override}=req.body;
  const id=parseInt(req.params.id);
  if(!['approved','rejected'].includes(status))
    return res.status(400).json({error:'Invalid status'});

  const[[leave]]=await pool.query('SELECT * FROM leave_applications WHERE id=?',[id]);
  if(!leave) return res.status(404).json({error:'Application not found'});

  // Supervisors cannot approve their own leave
  if(req.user.role==='supervisor'&&leave.user_id===req.user.id)
    return res.status(403).json({error:'You cannot approve your own leave application'});

  const cfg = LEAVE_CONFIG[leave.leave_type];

  if(cfg?.allSupervisors && req.user.role==='supervisor'){
    // ── Annual leave: record this supervisor's individual decision ──
    // Make sure the row exists first
    await pool.query(
      'INSERT IGNORE INTO leave_approvals(leave_id,supervisor_id,decision) VALUES(?,?,?)',
      [id, req.user.id, 'pending']).catch(()=>{});

    const affected = await pool.query(
      `UPDATE leave_approvals SET decision=?,note=?,decided_at=NOW()
       WHERE leave_id=? AND supervisor_id=?`,
      [status, reviewer_note||null, id, req.user.id]);

    // Re-check and finalise
    await tryFinalise(id);

    // Notify applicant of this supervisor's individual decision
    const[supUser]=await pool.query('SELECT full_name FROM users WHERE id=?',[req.user.id]);
    const supName=supUser[0]?.full_name||'A supervisor';
    const lbl2=LEAVE_CONFIG[leave.leave_type]?.label||leave.leave_type;
    if(status==='rejected'){
      await notify({
        userId:leave.user_id, triggeredById:req.user.id,
        type:'leave_rejected',
        title:'Leave Application Rejected',
        message:`Your ${lbl2} request was rejected by ${supName}.${reviewer_note?' Note: '+reviewer_note:''}`
      }).catch(()=>{});
    } else {
      await notify({
        userId:leave.user_id, triggeredById:req.user.id,
        type:'leave_pending_approvals',
        title:'Leave Approval Progress',
        message:`${supName} approved your ${lbl2} request. Waiting for remaining supervisors.`
      }).catch(()=>{});
    }
    res.json({success:true, message: status==='approved'
      ? 'Your approval recorded. Leave will be approved once all supervisors approve.'
      : 'Leave application rejected.'});

  } else {
    // ── Direct decision: admin override OR non-annual leave ──
    await pool.query(
      `UPDATE leave_applications
       SET status=?,reviewed_by=?,reviewed_at=NOW(),reviewer_note=?,admin_override=?
       WHERE id=?`,
      [status, req.user.id, reviewer_note||null,
       req.user.role==='admin'&&admin_override?1:0, id]);

    if(status==='approved'){
      const s=new Date(leave.start_date+'T12:00:00'),e=new Date(leave.end_date+'T12:00:00');
      for(let d=new Date(s);d<=e;d.setDate(d.getDate()+1)){
        await pool.query(
          "UPDATE attendance SET admin_note=CONCAT(COALESCE(admin_note,''),' [On Approved Leave]') WHERE user_id=? AND work_date=?",
          [leave.user_id,localDate(d)]).catch(()=>{});
      }
    }
    // Notify applicant
    const[rev]=await pool.query('SELECT full_name FROM users WHERE id=?',[req.user.id]);
    const revName=rev[0]?.full_name||'Manager';
    const lbl=LEAVE_CONFIG[leave.leave_type]?.label||leave.leave_type;
    await notify({
      userId:leave.user_id, triggeredById:req.user.id,
      type:`leave_${status}`,
      title:`Leave ${status==='approved'?'Approved ✓':'Rejected ✗'}`,
      message:`Your ${lbl} request (${leave.start_date}${leave.start_date!==leave.end_date?' to '+leave.end_date:''}) has been ${status} by ${revName}.${reviewer_note?' Note: '+reviewer_note:''}`
    }).catch(()=>{});
    res.json({success:true});
  }
}));

/* ── Admin force-override (bypasses supervisor chain) ── */
app.post('/api/admin/leave/:id/override', auth, adminOnly, wrap(async(req,res)=>{
  const{status,reviewer_note}=req.body;
  if(!status) return res.status(400).json({error:'Status required'});
  await pool.query(
    `UPDATE leave_applications SET status=?,reviewed_by=?,reviewed_at=NOW(),
     reviewer_note=?,admin_override=1 WHERE id=?`,
    [status, req.user.id, reviewer_note||'Admin override', req.params.id]);
  res.json({success:true});
}));

/* ── Delete / withdraw ── */
app.delete('/api/leave/:id', auth, wrap(async(req,res)=>{
  const[[rec]]=await pool.query('SELECT * FROM leave_applications WHERE id=?',[req.params.id]);
  if(!rec) return res.status(404).json({error:'Not found'});
  if(req.user.role!=='admin'){
    if(rec.user_id!==req.user.id) return res.status(403).json({error:'Access denied'});
    if(rec.status!=='pending') return res.status(400).json({error:'Only pending applications can be withdrawn'});
  }
  await pool.query('DELETE FROM leave_applications WHERE id=?',[req.params.id]);
  res.json({success:true});
}));


/* ══════════════════════════════════════
   ADMIN TASK STATS
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
   EMAIL / SMTP  (Gmail-first)
══════════════════════════════════════ */

/* Build a nodemailer transporter from stored config */
async function getTransporter(){
  const[rows]=await pool.query('SELECT * FROM smtp_config LIMIT 1');
  if(!rows.length) return null;
  const cfg=rows[0];
  // Gmail quick-setup: if host is gmail, use service shortcut
  if(cfg.host==='smtp.gmail.com'||cfg.host==='gmail'){
    return nodemailer.createTransport({
      service:'gmail',
      auth:{user:cfg.username, pass:cfg.password}
    });
  }
  return nodemailer.createTransport({
    host:cfg.host, port:cfg.port,
    secure:cfg.encryption==='ssl',
    auth:{user:cfg.username, pass:cfg.password}
  });
}

/* In-app notification + optional email */
async function notify({userId, triggeredById=null, taskId=null, type, title, message, sendMail=true}){
  // Insert in-app notification
  await pool.query(
    'INSERT INTO notifications(user_id,task_id,triggered_by_id,type,title,message) VALUES(?,?,?,?,?,?)',
    [userId, taskId||null, triggeredById||null, type, title||null, message||null]
  ).catch(()=>{});

  // Also send email if configured
  if(sendMail){
    try{
      const tr=await getTransporter();
      if(!tr) return;
      const[sr]=await pool.query('SELECT * FROM smtp_config LIMIT 1');
      const[ur]=await pool.query('SELECT email,full_name FROM users WHERE id=?',[userId]);
      if(!ur.length) return;
      const cfg=sr[0], u=ur[0];
      const html=`<div style="font-family:sans-serif;max-width:560px;margin:0 auto;">
        <div style="background:#5B8AF0;padding:18px 24px;border-radius:8px 8px 0 0;">
          <h2 style="color:#fff;margin:0;font-size:16px;">CloudCraft Workspace</h2>
        </div>
        <div style="background:#f9fafb;padding:24px;border-radius:0 0 8px 8px;border:1px solid #e5e7eb;">
          <p style="margin-bottom:8px;color:#374151;">Hi <b>${u.full_name}</b>,</p>
          <h3 style="color:#111827;margin-bottom:12px;">${title||type}</h3>
          <p style="color:#6b7280;line-height:1.6;">${message||''}</p>
          <hr style="border:none;border-top:1px solid #e5e7eb;margin:20px 0;"/>
          <p style="font-size:12px;color:#9ca3af;">CloudCraft Workspace — automated notification</p>
        </div>
      </div>`;
      await tr.sendMail({
        from:`"${cfg.from_name||'CloudCraft'}" <${cfg.from_email||cfg.username}>`,
        to: u.email,
        subject: title||`Notification: ${type}`,
        html
      });
    }catch(e){ console.error('Email send error:',e.message); }
  }
}

/* Legacy wrapper — keep old call sites working */
async function sendEmail(userId, by, title, type){
  const msgs={
    assigned:   `@${by} assigned you to task: "${title}"`,
    reassigned: `@${by} moved task "${title}" to you`,
    status_changed: `Status updated on task "${title}" by @${by}`,
  };
  const labels={assigned:'Task Assigned',reassigned:'Task Reassigned',status_changed:'Task Status Updated'};
  await notify({userId, type, title:labels[type]||type, message:msgs[type]||title, sendMail:true}).catch(()=>{});
}

/* Notify all admins */
async function notifyAdmins(opts){
  const[admins]=await pool.query("SELECT id FROM users WHERE role='admin' AND is_active=1");
  for(const a of admins) await notify({...opts, userId:a.id}).catch(()=>{});
}

/* Notify all supervisors */
async function notifySupervisors(opts){
  const[sups]=await pool.query("SELECT id FROM users WHERE role='supervisor' AND is_active=1");
  for(const s of sups) await notify({...opts, userId:s.id}).catch(()=>{});
}

app.get('/api/admin/smtp', auth, adminOnly, wrap(async(req,res)=>{
  const[r]=await pool.query('SELECT id,host,port,username,encryption,from_email,from_name FROM smtp_config LIMIT 1');
  res.json(r[0]||{});
}));

app.put('/api/admin/smtp', auth, adminOnly, wrap(async(req,res)=>{
  const{host,port,username,password,encryption,from_email,from_name,gmail_mode}=req.body;
  // Gmail quick-setup
  const h=gmail_mode?'smtp.gmail.com':host;
  const p=gmail_mode?587:port;
  const enc=gmail_mode?'tls':encryption;
  const[ex]=await pool.query('SELECT id FROM smtp_config LIMIT 1');
  if(ex.length){
    const cols=['host=?','port=?','username=?','encryption=?','from_email=?','from_name=?'];
    const vals=[h,p,username,enc,from_email||username||'',from_name||'CloudCraft'];
    if(password){cols.push('password=?');vals.push(password);}
    vals.push(ex[0].id);
    await pool.query(`UPDATE smtp_config SET ${cols.join(',')} WHERE id=?`,vals);
  } else {
    await pool.query(
      'INSERT INTO smtp_config(host,port,username,password,encryption,from_email,from_name) VALUES(?,?,?,?,?,?,?)',
      [h,p,username,password||'',enc,from_email||username||'',from_name||'CloudCraft']);
  }
  res.json({success:true});
}));

app.post('/api/admin/smtp/test', auth, adminOnly, wrap(async(req,res)=>{
  const tr=await getTransporter();
  if(!tr) return res.status(400).json({error:'Email not configured. Please save settings first.'});
  await tr.verify();
  res.json({success:true,message:'Connection verified! Email is working ✓'});
}));

/* Send a test email to admin */
app.post('/api/admin/smtp/test-send', auth, adminOnly, wrap(async(req,res)=>{
  const tr=await getTransporter();
  if(!tr) return res.status(400).json({error:'Email not configured'});
  const[rows]=await pool.query('SELECT * FROM smtp_config LIMIT 1');
  const[ur]=await pool.query('SELECT email,full_name FROM users WHERE id=?',[req.user.id]);
  if(!ur.length) return res.status(404).json({error:'User not found'});
  const cfg=rows[0],u=ur[0];
  await tr.sendMail({
    from:`"${cfg.from_name||'CloudCraft'}" <${cfg.from_email||cfg.username}>`,
    to: u.email,
    subject: 'CloudCraft — Email Test',
    html: `<p>Hi ${u.full_name},</p><p>Your email notification system is working correctly! ✓</p><p>— CloudCraft Workspace</p>`
  });
  res.json({success:true,message:`Test email sent to ${u.email}`});
}));

app.use((err,req,res,next)=>res.status(500).json({error:'Internal server error'}));
const PORT=process.env.PORT||3001;
setupDatabase().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`🚀 Synapse API on port ${PORT}`)));
