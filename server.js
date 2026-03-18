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

/* ══════════════════════════════════════════════════
   DATABASE SETUP
══════════════════════════════════════════════════ */
async function setupDatabase(){
  try{
    const c = await pool.getConnection();
    console.log('✅ MySQL connected');

    // Users — role includes supervisor
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

    // Supervisor permissions — admin configures per supervisor
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
      type ENUM('assigned','mentioned','completed','reassigned') DEFAULT 'assigned',
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(triggered_by_id) REFERENCES users(id) ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS task_history(
      id INT AUTO_INCREMENT PRIMARY KEY, task_id INT NOT NULL,
      changed_by_id INT NOT NULL, action VARCHAR(100) NOT NULL,
      old_value TEXT, new_value TEXT, field VARCHAR(50),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(changed_by_id) REFERENCES users(id) ON DELETE CASCADE)`);

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

    // Attendance — only members & supervisors clock in/out
    await c.query(`CREATE TABLE IF NOT EXISTS attendance(
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      work_date DATE NOT NULL,
      clock_in DATETIME,
      clock_out DATETIME,
      clock_in_status ENUM('pending','approved','rejected') DEFAULT 'pending',
      clock_out_status ENUM('pending','approved','rejected','na') DEFAULT 'na',
      approved_clock_in DATETIME,
      approved_clock_out DATETIME,
      approved_by INT,
      approved_at TIMESTAMP NULL,
      note TEXT,
      admin_note TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_user_date(user_id,work_date),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(approved_by) REFERENCES users(id) ON DELETE SET NULL)`);

    await c.query(`CREATE TABLE IF NOT EXISTS holidays(
      id INT AUTO_INCREMENT PRIMARY KEY,
      holiday_date DATE NOT NULL UNIQUE,
      name VARCHAR(100) NOT NULL,
      type ENUM('sunday','public','manual') DEFAULT 'manual',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

    // Seed admin
    const hash = await bcrypt.hash('Admin@1234',10);
    await c.query(`INSERT IGNORE INTO users(username,email,password_hash,full_name,role,avatar_color)
      VALUES('admin','admin@company.com',?,'System Admin','admin','#7C5CFC')`,[hash]);

    // Seed tags
    for(const[n,cl] of [['bug','#F87171'],['feature','#5B8AF0'],['design','#8B5CF6'],['backend','#FBBF24'],['frontend','#34D399'],['urgent','#F87171']])
      await c.query('INSERT IGNORE INTO tags(name,color) VALUES(?,?)',[n,cl]);

    // ── Migrate existing tables if needed ──
    // Add 'supervisor' to role ENUM if not already there
    await c.query(`ALTER TABLE users MODIFY COLUMN role ENUM('admin','supervisor','member') DEFAULT 'member'`).catch(()=>{});
    // Ensure supervisor_permissions table exists (may be missing on older installs)
    // Already handled above via CREATE TABLE IF NOT EXISTS

    c.release();
    console.log('✅ Database ready');
  }catch(e){ console.error('DB setup error:',e.message); }
}

/* ══════════════════════════════════════════════════
   MIDDLEWARE & HELPERS
══════════════════════════════════════════════════ */
const JWT_SECRET = process.env.JWT_SECRET||'synapse_secret';

const auth = async(req,res,next)=>{
  try{
    const t = req.headers.authorization?.split(' ')[1];
    if(!t) return res.status(401).json({error:'No token'});
    req.user = jwt.verify(t,JWT_SECRET);
    // Load supervisor permissions if applicable
    if(req.user.role==='supervisor'){
      const[perms]=await pool.query('SELECT * FROM supervisor_permissions WHERE user_id=?',[req.user.id]);
      req.user.permissions = perms[0] || {};
    }
    next();
  }catch{ res.status(401).json({error:'Invalid token'}); }
};

const adminOnly = (req,res,next)=>
  req.user?.role==='admin' ? next() : res.status(403).json({error:'Admin only'});

const adminOrSupervisor = (req,res,next)=>
  (req.user?.role==='admin'||req.user?.role==='supervisor') ? next() : res.status(403).json({error:'Insufficient permissions'});

// Permission checker for supervisors
const hasPerm = (perm) => (req,res,next)=>{
  if(req.user?.role==='admin') return next();
  if(req.user?.role==='supervisor' && req.user.permissions?.[perm]) return next();
  return res.status(403).json({error:`Permission denied: ${perm} required`});
};

const wrap = fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(e=>{
  console.error(e.message); res.status(500).json({error:e.message||'Server error'});
});

const localDate = (d=new Date())=>{
  const y=d.getFullYear(),m=String(d.getMonth()+1).padStart(2,'0'),dd=String(d.getDate()).padStart(2,'0');
  return `${y}-${m}-${dd}`;
};

const toMySQL = (val)=>{
  if(!val) return null;
  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(val)) return val;
  const d=new Date(val);
  if(isNaN(d.getTime())) return null;
  const p=n=>String(n).padStart(2,'0');
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};

/* ══════════════════════════════════════════════════
   AUTH
══════════════════════════════════════════════════ */
app.post('/api/auth/login', wrap(async(req,res)=>{
  const{username,password}=req.body;
  if(!username||!password) return res.status(400).json({error:'Username and password required'});
  const[rows]=await pool.query('SELECT * FROM users WHERE username=? AND is_active=1',[username]);
  if(!rows.length) return res.status(401).json({error:'Invalid credentials'});
  const u=rows[0];
  if(!await bcrypt.compare(password,u.password_hash)) return res.status(401).json({error:'Invalid credentials'});
  const token=jwt.sign({id:u.id,username:u.username,role:u.role},JWT_SECRET,{expiresIn:'8h'});
  // Load permissions for supervisors
  let permissions={};
  if(u.role==='supervisor'){
    const[perms]=await pool.query('SELECT * FROM supervisor_permissions WHERE user_id=?',[u.id]);
    permissions = perms[0]||{};
  }
  pool.query('INSERT INTO activity_log(user_id,action,entity_type) VALUES(?,?,?)',[u.id,'login','user']).catch(()=>{});
  res.json({token,user:{id:u.id,username:u.username,email:u.email,full_name:u.full_name,role:u.role,avatar_color:u.avatar_color,permissions}});
}));

/* ══════════════════════════════════════════════════
   USERS
══════════════════════════════════════════════════ */
app.get('/api/users', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query(`
    SELECT u.id,u.username,u.email,u.full_name,u.role,u.avatar_color,u.is_active,u.created_at,
      sp.can_approve_attendance,sp.can_view_all_attendance,sp.can_edit_tasks,
      sp.can_create_tasks,sp.can_view_all_tasks,sp.can_manage_holidays
    FROM users u
    LEFT JOIN supervisor_permissions sp ON u.id=sp.user_id
    ORDER BY u.full_name`);
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
  // Auto-create default permissions for supervisors
  if(role==='supervisor'){
    await pool.query('INSERT IGNORE INTO supervisor_permissions(user_id) VALUES(?)',[r.insertId]);
  }
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
  if(u.length){ v.push(uid); await pool.query(`UPDATE users SET ${u.join(',')} WHERE id=?`,v); }

  // Update supervisor permissions
  if(role==='supervisor'||permissions){
    const[existing]=await pool.query('SELECT user_id FROM supervisor_permissions WHERE user_id=?',[uid]);
    if(!existing.length){
      await pool.query('INSERT INTO supervisor_permissions(user_id) VALUES(?)',[uid]);
    }
    if(permissions){
      const pu=[],pv=[];
      const permFields=['can_approve_attendance','can_view_all_attendance','can_edit_tasks','can_create_tasks','can_view_all_tasks','can_manage_holidays'];
      for(const f of permFields){
        if(permissions[f]!==undefined){ pu.push(`${f}=?`); pv.push(permissions[f]?1:0); }
      }
      if(pu.length){ pv.push(uid); await pool.query(`UPDATE supervisor_permissions SET ${pu.join(',')} WHERE user_id=?`,pv); }
    }
  }
  // Remove permissions if demoted from supervisor
  if(role&&role!=='supervisor'){
    await pool.query('DELETE FROM supervisor_permissions WHERE user_id=?',[uid]);
  }
  res.json({success:true});
}));

app.delete('/api/users/:id', auth, adminOnly, wrap(async(req,res)=>{
  if(parseInt(req.params.id)===req.user.id) return res.status(400).json({error:'Cannot deactivate yourself'});
  await pool.query('UPDATE users SET is_active=0 WHERE id=?',[req.params.id]);
  res.json({success:true});
}));

// Get supervisor permissions for a specific user
app.get('/api/users/:id/permissions', auth, adminOnly, wrap(async(req,res)=>{
  const[rows]=await pool.query('SELECT * FROM supervisor_permissions WHERE user_id=?',[req.params.id]);
  res.json(rows[0]||{});
}));

/* ══════════════════════════════════════════════════
   TASKS
══════════════════════════════════════════════════ */
const parseTask = r=>({...r,
  tags: r.tags_raw ? r.tags_raw.split('||').map(t=>{const[name,color]=t.split('::');return{name,color};}) : [],
  assignees: r.assignees_raw ? r.assignees_raw.split('||').map(a=>{const[id,fn,un,ac]=a.split('::');return{id:parseInt(id),full_name:fn,username:un,avatar_color:ac};}).filter(a=>!isNaN(a.id)) : []
});

app.get('/api/tasks', auth, wrap(async(req,res)=>{
  const{status,tag}=req.query;
  const isAdmin=req.user.role==='admin';
  const isSupervisorAll=req.user.role==='supervisor'&&req.user.permissions?.can_view_all_tasks;
  const showAll=isAdmin||isSupervisorAll;
  const userId=req.user.id;

  let vis=showAll ? '1=1' : '(t.creator_id=? OR t.id IN (SELECT task_id FROM task_assignees WHERE user_id=?))';
  const params=showAll?[]:[userId,userId];
  let extra='';
  if(status){extra+=' AND t.status=?';params.push(status);}
  if(tag){extra+=` AND t.id IN (SELECT tt2.task_id FROM task_tags tt2 JOIN tags tg2 ON tt2.tag_id=tg2.id WHERE tg2.name=?)`;params.push(tag);}

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

app.post('/api/tasks', auth, wrap(async(req,res)=>{
  // Admins and supervisors with can_create_tasks can create
  const isAdmin=req.user.role==='admin';
  const canCreate=isAdmin||(req.user.role==='supervisor'&&req.user.permissions?.can_create_tasks)||req.user.role==='member';
  if(!canCreate) return res.status(403).json({error:'Permission denied'});

  const{title,description,status,priority,assignee_ids,due_date,tags,mentions}=req.body;
  if(!title) return res.status(400).json({error:'Title required'});
  const[r]=await pool.query('INSERT INTO tasks(title,description,status,priority,creator_id,due_date) VALUES(?,?,?,?,?,?)',
    [title,description||'',status||'todo',priority||'medium',req.user.id,due_date||null]);
  const taskId=r.insertId;
  // Members can only assign to themselves; admins/supervisors can assign to anyone
  const isMember=req.user.role==='member';
  const rawList=Array.isArray(assignee_ids)?assignee_ids.map(Number):[];
  const aList=isMember?[req.user.id]:rawList.length?rawList:[req.user.id];
  for(const uid of aList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}
  if(Array.isArray(tags)&&tags.length){
    for(const tn of tags){
      try{
        let[tr]=await pool.query('SELECT id FROM tags WHERE name=?',[tn]);
        const tid=tr.length?tr[0].id:(await pool.query('INSERT INTO tags(name) VALUES(?)',[tn]))[0].insertId;
        await pool.query('INSERT IGNORE INTO task_tags VALUES(?,?)',[taskId,tid]);
      }catch{}
    }
  }
  for(const uid of aList){
    if(uid!==req.user.id){
      try{
        await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'assigned']);
        sendEmail(uid,req.user.username,title,'assigned').catch(()=>{});
      }catch{}
    }
  }
  if(Array.isArray(mentions)&&mentions.length){
    for(const uid of mentions){
      if(uid!==req.user.id&&!aList.includes(uid)){
        try{
          await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'mentioned']);
          sendEmail(uid,req.user.username,title,'mentioned').catch(()=>{});
        }catch{}
      }
    }
  }
  await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,new_value) VALUES(?,?,?,?)',[taskId,req.user.id,'created',title]);
  // Log initial assignment
  if(aList.length){
    const[aNames]=await pool.query('SELECT full_name FROM users WHERE id IN ('+aList.map(()=>'?').join(',')+')',aList);
    const names=aNames.map(u=>u.full_name).join(', ');
    await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,field,new_value) VALUES(?,?,?,?,?)',[taskId,req.user.id,'assigned','assignees',names]);
  }
  res.json({id:taskId});
}));

// Edit: Admin full edit, Supervisor with can_edit_tasks can edit (no delete)
app.put('/api/tasks/:id', auth, wrap(async(req,res)=>{
  const isAdmin=req.user.role==='admin';
  const canEdit=isAdmin||(req.user.role==='supervisor'&&req.user.permissions?.can_edit_tasks);
  if(!canEdit) return res.status(403).json({error:'Permission denied: cannot edit tasks'});

  const{title,description,status,priority,assignee_ids,due_date,mentions}=req.body;
  const taskId=req.params.id;
  const[old]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!old.length) return res.status(404).json({error:'Task not found'});
  const prev=old[0];
  await pool.query('UPDATE tasks SET title=?,description=?,status=?,priority=?,due_date=? WHERE id=?',
    [title,description||'',status,priority,due_date||null,taskId]);
  if(prev.status!==status){
    await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,field,old_value,new_value) VALUES(?,?,?,?,?,?)',
      [taskId,req.user.id,'status_changed','status',prev.status,status]);
  }
  if(prev.priority!==priority){
    await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,field,old_value,new_value) VALUES(?,?,?,?,?,?)',
      [taskId,req.user.id,'priority_changed','priority',prev.priority,priority]);
  }
  if(Array.isArray(assignee_ids)){
    const newList=assignee_ids.map(Number);
    const[oldRows]=await pool.query('SELECT ta.user_id,u.full_name FROM task_assignees ta JOIN users u ON ta.user_id=u.id WHERE ta.task_id=?',[taskId]);
    const oldList=oldRows.map(r=>r.user_id);
    const newlyAdded=newList.filter(id=>!oldList.includes(id));
    const removed=oldList.filter(id=>!newList.includes(id));
    await pool.query('DELETE FROM task_assignees WHERE task_id=?',[taskId]);
    for(const uid of newList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}
    if(newlyAdded.length){
      const[addedNames]=await pool.query('SELECT full_name FROM users WHERE id IN ('+newlyAdded.map(()=>'?').join(',')+')',newlyAdded);
      await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,field,new_value) VALUES(?,?,?,?,?)',[taskId,req.user.id,'assigned','assignees',addedNames.map(u=>u.full_name).join(', ')]);
    }
    if(removed.length){
      const removedNames=oldRows.filter(r=>removed.includes(r.user_id)).map(r=>r.full_name);
      await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,field,old_value) VALUES(?,?,?,?,?)',[taskId,req.user.id,'unassigned','assignees',removedNames.join(', ')]);
    }
    for(const uid of newlyAdded){
      if(uid!==req.user.id){
        try{
          await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'assigned']);
          sendEmail(uid,req.user.username,title,'assigned').catch(()=>{});
        }catch{}
      }
    }
  }
  pool.query('INSERT INTO activity_log(user_id,action,entity_type,entity_id) VALUES(?,?,?,?)',[req.user.id,'update_task','task',taskId]).catch(()=>{});
  res.json({success:true});
}));

// Delete: Admin only — supervisors cannot delete
app.delete('/api/tasks/:id', auth, adminOnly, wrap(async(req,res)=>{
  await pool.query('DELETE FROM tasks WHERE id=?',[req.params.id]);
  res.json({success:true});
}));

app.post('/api/tasks/:id/complete-reassign', auth, wrap(async(req,res)=>{
  const{new_assignee_ids}=req.body;
  const taskId=req.params.id;
  const userId=req.user.id;
  const isAdmin=req.user.role==='admin';
  const[assigned]=await pool.query('SELECT * FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);
  if(!assigned.length&&!isAdmin) return res.status(403).json({error:'Not assigned to this task'});
  const[taskRows]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!taskRows.length) return res.status(404).json({error:'Task not found'});
  const task=taskRows[0];
  await pool.query('UPDATE tasks SET status=? WHERE id=?',['done',taskId]);
  await pool.query('DELETE FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);
  const newList=Array.isArray(new_assignee_ids)?new_assignee_ids.map(Number):[];
  for(const uid of newList){
    try{
      await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);
      await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,userId,'reassigned']);
      sendEmail(uid,req.user.username,task.title,'reassigned').catch(()=>{});
    }catch{}
  }
  await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,field,old_value,new_value) VALUES(?,?,?,?,?,?)',
    [taskId,userId,'status_changed','status',task.status,'done']);
  if(newList.length){
    const[completedNames]=await pool.query('SELECT full_name FROM users WHERE id IN ('+newList.map(()=>'?').join(',')+')',newList);
    await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,field,new_value) VALUES(?,?,?,?,?)',
      [taskId,userId,'moved','assignees',completedNames.map(u=>u.full_name).join(', ')]);
  }
  res.json({success:true});
}));

/* ── Task History (all task members can view) ── */
app.get('/api/tasks/:id/history', auth, wrap(async(req,res)=>{
  const taskId=req.params.id;
  const userId=req.user.id;
  const isAdmin=req.user.role==='admin';
  const isSupervisorAll=req.user.role==='supervisor'&&req.user.permissions?.can_view_all_tasks;
  if(!isAdmin&&!isSupervisorAll){
    // Verify user is creator or assignee
    const[access]=await pool.query(
      'SELECT id FROM tasks WHERE id=? AND (creator_id=? OR id IN (SELECT task_id FROM task_assignees WHERE user_id=?))',
      [taskId,userId,userId]);
    if(!access.length) return res.status(403).json({error:'Access denied'});
  }
  const[rows]=await pool.query(`
    SELECT th.*,
      u.full_name as actor_name, u.username as actor_username,
      u.avatar_color as actor_color, u.role as actor_role
    FROM task_history th
    JOIN users u ON th.changed_by_id=u.id
    WHERE th.task_id=?
    ORDER BY th.created_at ASC`,[taskId]);
  res.json(rows);
}));

/* ── Move To: any task member can reassign (move) without marking done ── */
app.post('/api/tasks/:id/move-to', auth, wrap(async(req,res)=>{
  const{new_assignee_ids,note}=req.body;
  const taskId=req.params.id;
  const userId=req.user.id;
  const isAdmin=req.user.role==='admin';
  const isSupervisor=req.user.role==='supervisor';

  // Check access: must be creator, assignee, admin, or supervisor
  const[access]=await pool.query(
    'SELECT id FROM tasks WHERE id=? AND (creator_id=? OR id IN (SELECT task_id FROM task_assignees WHERE user_id=?))',
    [taskId,userId,userId]);
  if(!access.length&&!isAdmin&&!isSupervisor) return res.status(403).json({error:'Not a member of this task'});

  const[taskRows]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!taskRows.length) return res.status(404).json({error:'Task not found'});
  const task=taskRows[0];

  // Get old assignees for logging
  const[oldRows]=await pool.query('SELECT ta.user_id,u.full_name FROM task_assignees ta JOIN users u ON ta.user_id=u.id WHERE ta.task_id=?',[taskId]);
  const oldNames=oldRows.map(r=>r.full_name).join(', ');

  const newList=Array.isArray(new_assignee_ids)?new_assignee_ids.map(Number):[];
  if(!newList.length) return res.status(400).json({error:'At least one assignee required'});

  // Replace assignees
  await pool.query('DELETE FROM task_assignees WHERE task_id=?',[taskId]);
  for(const uid of newList){
    try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}
  }

  // Get new assignee names for log
  const[newNames]=await pool.query('SELECT full_name FROM users WHERE id IN ('+newList.map(()=>'?').join(',')+')',newList);
  const newNamesStr=newNames.map(u=>u.full_name).join(', ');

  // Log the movement
  await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,field,old_value,new_value) VALUES(?,?,?,?,?,?)',
    [taskId,userId,'moved','assignees',oldNames,newNamesStr]);
  if(note){
    await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,new_value) VALUES(?,?,?,?)',
      [taskId,userId,'note',note]);
  }

  // Notify new assignees
  for(const uid of newList){
    if(uid!==userId){
      try{
        await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,userId,'reassigned']);
        sendEmail(uid,req.user.username,task.title,'reassigned').catch(()=>{});
      }catch{}
    }
  }
  res.json({success:true});
}));

/* ══════════════════════════════════════════════════
   TAGS
══════════════════════════════════════════════════ */
app.get('/api/tags', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query('SELECT * FROM tags ORDER BY name');
  res.json(rows);
}));

/* ══════════════════════════════════════════════════
   NOTIFICATIONS
══════════════════════════════════════════════════ */
app.get('/api/notifications', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query(`
    SELECT n.*,t.title as task_title,u.username as triggered_by,u.full_name as triggered_by_name
    FROM notifications n JOIN tasks t ON n.task_id=t.id JOIN users u ON n.triggered_by_id=u.id
    WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 30`,[req.user.id]);
  res.json(rows);
}));
app.put('/api/notifications/:id/read', auth, wrap(async(req,res)=>{
  await pool.query('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?',[req.params.id,req.user.id]);
  res.json({success:true});
}));
app.put('/api/notifications/read-all', auth, wrap(async(req,res)=>{
  await pool.query('UPDATE notifications SET is_read=1 WHERE user_id=?',[req.user.id]);
  res.json({success:true});
}));

/* ══════════════════════════════════════════════════
   ATTENDANCE — Clock in/out only for members & supervisors
══════════════════════════════════════════════════ */
async function ensureSundaysHolidays(startDate,endDate){
  const start=new Date(startDate+'T12:00:00');
  const end=new Date(endDate+'T12:00:00');
  for(let d=new Date(start);d<=end;d.setDate(d.getDate()+1)){
    if(d.getDay()===0){
      const ds=localDate(d);
      await pool.query('INSERT IGNORE INTO holidays(holiday_date,name,type) VALUES(?,?,?)',[ds,'Sunday','sunday']).catch(()=>{});
    }
  }
}

app.post('/api/attendance/clock-in', auth, wrap(async(req,res)=>{
  // ONLY members and supervisors can clock in — not admins
  if(req.user.role==='admin') return res.status(403).json({error:'Administrators do not clock in. Attendance management is done through the admin panel.'});

  const userId=req.user.id;
  const now=new Date();
  const today=localDate(now);
  const[hols]=await pool.query('SELECT * FROM holidays WHERE holiday_date=?',[today]);
  if(hols.length) return res.status(400).json({error:`Today is a holiday: ${hols[0].name}`});
  const[existing]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  if(existing.length) return res.status(400).json({error:'Already clocked in today'});
  await pool.query('INSERT INTO attendance(user_id,work_date,clock_in,clock_in_status) VALUES(?,?,?,?)',[userId,today,now,'pending']);
  const firstDay=today.slice(0,7)+'-01';
  const lastDay=new Date(now.getFullYear(),now.getMonth()+1,0);
  await ensureSundaysHolidays(firstDay,localDate(lastDay));
  res.json({success:true,message:'Clocked in. Awaiting approval.',clock_in:now,status:'pending'});
}));

app.post('/api/attendance/clock-out', auth, wrap(async(req,res)=>{
  if(req.user.role==='admin') return res.status(403).json({error:'Administrators do not clock out.'});
  const userId=req.user.id;
  const now=new Date();
  const today=localDate(now);
  const[rows]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  if(!rows.length) return res.status(400).json({error:'You have not clocked in today'});
  const rec=rows[0];
  if(rec.clock_out) return res.status(400).json({error:'Already clocked out today'});
  await pool.query('UPDATE attendance SET clock_out=?,clock_out_status=? WHERE id=?',[now,'pending',rec.id]);
  res.json({success:true,message:'Clocked out. Awaiting approval.',clock_out:now,status:'pending'});
}));

app.get('/api/attendance/today', auth, wrap(async(req,res)=>{
  if(req.user.role==='admin') return res.json({record:null,holiday:null,today:localDate(),isAdmin:true});
  const userId=req.user.id;
  const today=localDate(new Date());
  const[rows]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  const[hols]=await pool.query('SELECT * FROM holidays WHERE holiday_date=?',[today]);
  res.json({record:rows[0]||null,holiday:hols[0]||null,today,isAdmin:false});
}));

app.get('/api/attendance/my', auth, wrap(async(req,res)=>{
  if(req.user.role==='admin') return res.json({report:[],stats:{},year:new Date().getFullYear(),month:new Date().getMonth()+1});
  const userId=req.user.id;
  const{year,month}=req.query;
  const y=parseInt(year)||new Date().getFullYear();
  const m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`;
  const lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;
  await ensureSundaysHolidays(startDate,endDate);
  const[records]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date BETWEEN ? AND ? ORDER BY work_date',[userId,startDate,endDate]);
  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ? ORDER BY holiday_date',[startDate,endDate]);
  const report=[];
  const holidayMap={};holidays.forEach(h=>holidayMap[h.holiday_date]=h);
  const recordMap={};records.forEach(r=>recordMap[r.work_date]=r);
  for(let d=1;d<=lastD;d++){
    const dateStr=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    const dayOfWeek=new Date(dateStr+'T12:00:00').getDay();
    const today=localDate(new Date());
    if(dateStr>today){report.push({date:dateStr,day_of_week:dayOfWeek,type:'future'});continue;}
    if(holidayMap[dateStr]){report.push({date:dateStr,day_of_week:dayOfWeek,type:'holiday',holiday_name:holidayMap[dateStr].name,holiday_type:holidayMap[dateStr].type});continue;}
    if(recordMap[dateStr]){report.push({date:dateStr,day_of_week:dayOfWeek,type:'attendance',...recordMap[dateStr]});continue;}
    report.push({date:dateStr,day_of_week:dayOfWeek,type:'absent'});
  }
  const stats={
    approved:report.filter(d=>d.type==='attendance'&&d.clock_in_status==='approved').length,
    pending:report.filter(d=>d.type==='attendance'&&d.clock_in_status==='pending').length,
    absent:report.filter(d=>d.type==='absent').length,
    holidays:report.filter(d=>d.type==='holiday').length,
    total_work_hours:records.filter(r=>r.approved_clock_in&&r.approved_clock_out).reduce((s,r)=>s+(new Date(r.approved_clock_out)-new Date(r.approved_clock_in))/3600000,0).toFixed(1),
  };
  res.json({report,stats,year:y,month:m});
}));

/* ── Admin/Supervisor attendance management ── */
app.get('/api/admin/attendance', auth, adminOrSupervisor, wrap(async(req,res)=>{
  // Supervisors need can_view_all_attendance
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_view_all_attendance)
    return res.status(403).json({error:'Permission denied'});

  const{year,month,user_id,status}=req.query;
  const y=parseInt(year)||new Date().getFullYear();
  const m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`;
  const lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;
  await ensureSundaysHolidays(startDate,endDate);

  let sql=`SELECT a.*,u.full_name,u.username,u.avatar_color,
    ab.full_name as approver_name, ab.username as approver_username, ab.avatar_color as approver_avatar_color, ab.role as approver_role
    FROM attendance a JOIN users u ON a.user_id=u.id
    LEFT JOIN users ab ON a.approved_by=ab.id
    WHERE a.work_date BETWEEN ? AND ?`;
  const params=[startDate,endDate];
  if(user_id){sql+=' AND a.user_id=?';params.push(user_id);}
  if(status==='pending'){sql+=" AND (a.clock_in_status='pending' OR a.clock_out_status='pending')";}
  else if(status==='approved'){sql+=" AND a.clock_in_status='approved'";}
  else if(status==='rejected'){sql+=" AND a.clock_in_status='rejected'";}
  sql+=' ORDER BY a.work_date DESC, u.full_name';

  const[records]=await pool.query(sql,params);
  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ?',[startDate,endDate]);
  const[users]=await pool.query("SELECT id,full_name,username,avatar_color FROM users WHERE is_active=1 AND role='member' ORDER BY full_name");

  const holidayMap={};holidays.forEach(h=>holidayMap[h.holiday_date]=h);
  const userReports={};
  for(const u of users){
    userReports[u.id]={user:u,days:[]};
    const userRecs={};records.filter(r=>r.user_id===u.id).forEach(r=>userRecs[r.work_date]=r);
    for(let d=1;d<=lastD;d++){
      const ds=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
      const today=localDate(new Date());
      if(ds>today)continue;
      if(holidayMap[ds]){userReports[u.id].days.push({date:ds,type:'holiday',name:holidayMap[ds].name,holiday_type:holidayMap[ds].type});continue;}
      if(userRecs[ds]){userReports[u.id].days.push({date:ds,type:'attendance',...userRecs[ds]});continue;}
      userReports[u.id].days.push({date:ds,type:'absent'});
    }
  }

  const[[totals]]=await pool.query(`SELECT COUNT(*) as total,SUM(clock_in_status='pending') as pending,SUM(clock_in_status='approved') as approved,SUM(clock_in_status='rejected') as rejected FROM attendance WHERE work_date BETWEEN ? AND ?`,[startDate,endDate]);
  res.json({records,holidays,userReports:Object.values(userReports),stats:totals,year:y,month:m});
}));

// Supervisors can approve/edit but NOT delete
app.put('/api/admin/attendance/:id', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_approve_attendance)
    return res.status(403).json({error:'Permission denied: cannot approve attendance'});

  const{clock_in_status,clock_out_status,approved_clock_in,approved_clock_out,admin_note}=req.body;
  const id=req.params.id;
  const[rows]=await pool.query('SELECT * FROM attendance WHERE id=?',[id]);
  if(!rows.length) return res.status(404).json({error:'Record not found'});
  const rec=rows[0];
  const u=[],v=[];
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
  v.push(id);
  await pool.query(`UPDATE attendance SET ${u.join(',')} WHERE id=?`,v);
  res.json({success:true});
}));

// Bulk approve — admin and supervisor with permission
app.post('/api/admin/attendance/bulk-approve', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_approve_attendance)
    return res.status(403).json({error:'Permission denied'});
  const{ids}=req.body;
  if(!Array.isArray(ids)||!ids.length) return res.status(400).json({error:'No IDs provided'});
  await pool.query(`UPDATE attendance SET clock_in_status='approved',approved_by=?,approved_at=NOW(),
    approved_clock_in=COALESCE(approved_clock_in,clock_in),
    approved_clock_out=COALESCE(approved_clock_out,clock_out)
    WHERE id IN (${ids.map(()=>'?').join(',')}) AND clock_in_status='pending'`,[req.user.id,...ids]);
  res.json({success:true});
}));

/* ── Admin attendance stats ── */
app.get('/api/admin/attendance/stats', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_view_all_attendance)
    return res.status(403).json({error:'Permission denied'});
  const{year,month}=req.query;
  const y=parseInt(year)||new Date().getFullYear();
  const m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`;
  const lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;
  await ensureSundaysHolidays(startDate,endDate);
  const[[overall]]=await pool.query(`SELECT COUNT(*) as total_checkins,SUM(clock_in_status='pending') as pending,SUM(clock_in_status='approved') as approved,SUM(clock_in_status='rejected') as rejected,COUNT(DISTINCT user_id) as unique_users FROM attendance WHERE work_date BETWEEN ? AND ?`,[startDate,endDate]);
  const[perUser]=await pool.query(`SELECT u.id,u.full_name,u.username,u.avatar_color,COUNT(a.id) as check_ins,SUM(a.clock_in_status='approved') as approved,SUM(a.clock_in_status='pending') as pending,SUM(a.clock_in_status='rejected') as rejected FROM users u LEFT JOIN attendance a ON u.id=a.user_id AND a.work_date BETWEEN ? AND ? WHERE u.is_active=1 AND u.role='member' GROUP BY u.id ORDER BY approved DESC`,[startDate,endDate]);
  const[daily]=await pool.query(`SELECT work_date as date,COUNT(*) as total,SUM(clock_in_status='approved') as approved,SUM(clock_in_status='pending') as pending FROM attendance WHERE work_date BETWEEN ? AND ? GROUP BY work_date ORDER BY work_date`,[startDate,endDate]);
  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ? ORDER BY holiday_date',[startDate,endDate]);
  const today=localDate(new Date());
  const holidayDates=new Set(holidays.map(h=>h.holiday_date));
  let workingDays=0;
  for(let d=1;d<=lastD;d++){const ds=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;if(ds<=today&&!holidayDates.has(ds))workingDays++;}
  res.json({overall,perUser,daily,holidays,workingDays,year:y,month:m});
}));

/* ── Holidays ── */
app.post('/api/admin/holidays', auth, adminOrSupervisor, wrap(async(req,res)=>{
  if(req.user.role==='supervisor'&&!req.user.permissions?.can_manage_holidays)
    return res.status(403).json({error:'Permission denied'});
  const{holiday_date,name}=req.body;
  if(!holiday_date||!name) return res.status(400).json({error:'Date and name required'});
  await pool.query('INSERT IGNORE INTO holidays(holiday_date,name,type) VALUES(?,?,?)',[holiday_date,name,'manual']);
  res.json({success:true});
}));
app.delete('/api/admin/holidays/:date', auth, adminOnly, wrap(async(req,res)=>{
  await pool.query('DELETE FROM holidays WHERE holiday_date=? AND type!=?',[req.params.date,'sunday']);
  res.json({success:true});
}));

/* ══════════════════════════════════════════════════
   ADMIN TASK DASHBOARD (comprehensive stats)
══════════════════════════════════════════════════ */
app.get('/api/admin/stats', auth, adminOnly, wrap(async(req,res)=>{
  // Overall task totals
  const[[totals]]=await pool.query(`SELECT
    COUNT(*) as total_tasks,
    SUM(status='todo') as todo,
    SUM(status='in_progress') as in_progress,
    SUM(status='review') as review,
    SUM(status='done') as done,
    SUM(priority='urgent') as urgent,
    SUM(priority='high') as high,
    SUM(priority='medium') as medium,
    SUM(priority='low') as low_p,
    SUM(due_date < CURDATE() AND status != 'done') as overdue,
    SUM(due_date >= CURDATE() AND due_date <= DATE_ADD(CURDATE(),INTERVAL 7 DAY) AND status != 'done') as due_this_week
    FROM tasks`);

  // Users overview
  const[[userStats]]=await pool.query(`SELECT
    COUNT(*) as total,
    SUM(role='admin') as admins,
    SUM(role='supervisor') as supervisors,
    SUM(role='member') as members,
    SUM(is_active=1) as active
    FROM users`);

  // Tasks per user (workload)
  const[perUser]=await pool.query(`SELECT u.id,u.full_name,u.avatar_color,u.username,u.role,
    COUNT(DISTINCT ta.task_id) as assigned,
    SUM(t.status='done') as completed,
    SUM(t.status='in_progress') as in_progress,
    SUM(t.status='todo') as todo,
    SUM(t.status='review') as review,
    SUM(t.due_date < CURDATE() AND t.status != 'done') as overdue
    FROM users u
    LEFT JOIN task_assignees ta ON u.id=ta.user_id
    LEFT JOIN tasks t ON ta.task_id=t.id
    WHERE u.is_active=1
    GROUP BY u.id ORDER BY assigned DESC`);

  // Task creation trend — last 30 days
  const[daily30]=await pool.query(`SELECT DATE(created_at) as date,status,COUNT(*) as count
    FROM tasks WHERE created_at >= DATE_SUB(CURDATE(),INTERVAL 30 DAY)
    GROUP BY DATE(created_at),status ORDER BY date`);

  // Task history / movements
  const[movements]=await pool.query(`SELECT th.*,t.title as task_title,
    u.full_name as changed_by_name,u.avatar_color,u.role as changed_by_role
    FROM task_history th
    JOIN tasks t ON th.task_id=t.id
    JOIN users u ON th.changed_by_id=u.id
    ORDER BY th.created_at DESC LIMIT 80`);

  // Priority distribution
  const[byPriority]=await pool.query(`SELECT priority,COUNT(*) as count,
    SUM(status='done') as done,SUM(status!='done') as open
    FROM tasks GROUP BY priority ORDER BY FIELD(priority,'urgent','high','medium','low')`);

  // Tag usage
  const[byTag]=await pool.query(`SELECT tg.name,tg.color,COUNT(tt.task_id) as count,
    SUM(t.status='done') as done
    FROM tags tg LEFT JOIN task_tags tt ON tg.id=tt.tag_id
    LEFT JOIN tasks t ON tt.task_id=t.id
    GROUP BY tg.id ORDER BY count DESC LIMIT 10`);

  // Status transition summary (how many moved each status)
  const[statusTransitions]=await pool.query(`SELECT old_value as from_status,new_value as to_status,
    COUNT(*) as count FROM task_history
    WHERE action='status_changed' AND created_at >= DATE_SUB(CURDATE(),INTERVAL 30 DAY)
    GROUP BY old_value,new_value ORDER BY count DESC`);

  // Completion velocity (tasks completed per week last 8 weeks)
  const[weeklyCompletion]=await pool.query(`SELECT
    YEAR(th.created_at) as year,
    WEEK(th.created_at,1) as week,
    MIN(DATE(th.created_at)) as week_start,
    COUNT(*) as completed
    FROM task_history th
    WHERE th.action='status_changed' AND th.new_value='done'
    AND th.created_at >= DATE_SUB(CURDATE(),INTERVAL 8 WEEK)
    GROUP BY YEAR(th.created_at),WEEK(th.created_at,1)
    ORDER BY year,week`);

  // Recent activity log
  const[activity]=await pool.query(`SELECT al.*,u.full_name,u.avatar_color,u.role
    FROM activity_log al LEFT JOIN users u ON al.user_id=u.id
    ORDER BY al.created_at DESC LIMIT 30`);

  // Tasks created vs completed this month
  const[[monthStats]]=await pool.query(`SELECT
    SUM(MONTH(created_at)=MONTH(CURDATE()) AND YEAR(created_at)=YEAR(CURDATE())) as created_this_month,
    SUM(status='done' AND MONTH(updated_at)=MONTH(CURDATE()) AND YEAR(updated_at)=YEAR(CURDATE())) as completed_this_month
    FROM tasks`);

  res.json({totals,userStats,perUser,daily30,movements,byPriority,byTag,statusTransitions,weeklyCompletion,activity,monthStats});
}));

/* ══════════════════════════════════════════════════
   SMTP
══════════════════════════════════════════════════ */
app.get('/api/admin/smtp', auth, adminOnly, wrap(async(req,res)=>{
  const[r]=await pool.query('SELECT id,host,port,username,encryption,from_email,from_name FROM smtp_config LIMIT 1');
  res.json(r[0]||{});
}));
app.put('/api/admin/smtp', auth, adminOnly, wrap(async(req,res)=>{
  const{host,port,username,password,encryption,from_email,from_name}=req.body;
  const[ex]=await pool.query('SELECT id FROM smtp_config LIMIT 1');
  if(ex.length){
    const s=['host=?','port=?','username=?','encryption=?','from_email=?','from_name=?'];
    const v=[host,port,username,encryption,from_email||'',from_name||'Task Manager'];
    if(password){s.push('password=?');v.push(password);}
    v.push(ex[0].id);
    await pool.query(`UPDATE smtp_config SET ${s.join(',')} WHERE id=?`,v);
  }else{
    await pool.query('INSERT INTO smtp_config(host,port,username,password,encryption,from_email,from_name) VALUES(?,?,?,?,?,?,?)',
      [host,port,username,password||'',encryption,from_email||'',from_name||'Task Manager']);
  }
  res.json({success:true});
}));
app.post('/api/admin/smtp/test', auth, adminOnly, wrap(async(req,res)=>{
  const[rows]=await pool.query('SELECT * FROM smtp_config LIMIT 1');
  if(!rows.length) return res.status(400).json({error:'SMTP not configured'});
  const cfg=rows[0];
  const t=nodemailer.createTransport({host:cfg.host,port:cfg.port,secure:cfg.encryption==='ssl',auth:{user:cfg.username,pass:cfg.password}});
  await t.verify();
  res.json({success:true,message:'SMTP connection verified!'});
}));

/* ══════════════════════════════════════════════════
   EMAIL HELPER
══════════════════════════════════════════════════ */
async function sendEmail(userId,by,title,type){
  const[sr]=await pool.query('SELECT * FROM smtp_config LIMIT 1');if(!sr.length)return;
  const[ur]=await pool.query('SELECT email,full_name FROM users WHERE id=?',[userId]);if(!ur.length)return;
  const cfg=sr[0],user=ur[0];
  const subs={assigned:`Assigned to: ${title}`,mentioned:`Mentioned in: ${title}`,reassigned:`Reassigned to you: ${title}`};
  const bods={
    assigned:`<p>Hi ${user.full_name},</p><p><b>@${by}</b> assigned you to <b>"${title}"</b>.</p>`,
    mentioned:`<p>Hi ${user.full_name},</p><p><b>@${by}</b> mentioned you in <b>"${title}"</b>.</p>`,
    reassigned:`<p>Hi ${user.full_name},</p><p><b>@${by}</b> reassigned <b>"${title}"</b> to you.</p>`,
  };
  const t=nodemailer.createTransport({host:cfg.host,port:cfg.port,secure:cfg.encryption==='ssl',auth:{user:cfg.username,pass:cfg.password}});
  await t.sendMail({from:`"${cfg.from_name}"<${cfg.from_email||cfg.username}>`,to:user.email,subject:subs[type]||subs.assigned,html:bods[type]||bods.assigned});
}

app.use((err,req,res,next)=>res.status(500).json({error:'Internal server error'}));

const PORT=process.env.PORT||3001;
setupDatabase().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`🚀 Synapse API on port ${PORT}`)));
