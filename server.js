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

/* ─── DB Setup ─────────────────────────────────────────── */
async function setupDatabase(){
  try{
    const c = await pool.getConnection(); console.log('MySQL connected');

    await c.query(`CREATE TABLE IF NOT EXISTS users(
      id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE,
      email VARCHAR(100) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL,
      full_name VARCHAR(100), role ENUM('admin','member') DEFAULT 'member',
      avatar_color VARCHAR(7) DEFAULT '#3B82F6', is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)`);

    await c.query(`CREATE TABLE IF NOT EXISTS tasks(
      id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(255) NOT NULL,
      description TEXT, status ENUM('todo','in_progress','review','done') DEFAULT 'todo',
      priority ENUM('low','medium','high','urgent') DEFAULT 'medium',
      creator_id INT NOT NULL, due_date DATE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS task_assignees(
      task_id INT NOT NULL, user_id INT NOT NULL, assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(task_id,user_id),
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS tags(
      id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(50) NOT NULL UNIQUE,
      color VARCHAR(7) DEFAULT '#6366F1')`);

    await c.query(`CREATE TABLE IF NOT EXISTS task_tags(
      task_id INT NOT NULL, tag_id INT NOT NULL, PRIMARY KEY(task_id,tag_id),
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY(tag_id)  REFERENCES tags(id)  ON DELETE CASCADE)`);

    await c.query(`CREATE TABLE IF NOT EXISTS notifications(
      id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL,
      task_id INT NOT NULL, triggered_by_id INT NOT NULL,
      type ENUM('assigned','mentioned','completed','reassigned') DEFAULT 'assigned',
      is_read BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
      id INT AUTO_INCREMENT PRIMARY KEY, host VARCHAR(255) NOT NULL,
      port INT NOT NULL DEFAULT 587, username VARCHAR(255) NOT NULL,
      password VARCHAR(255) NOT NULL, encryption ENUM('none','ssl','tls') DEFAULT 'tls',
      from_email VARCHAR(255), from_name VARCHAR(100),
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)`);

    await c.query(`CREATE TABLE IF NOT EXISTS activity_log(
      id INT AUTO_INCREMENT PRIMARY KEY, user_id INT,
      action VARCHAR(100) NOT NULL, entity_type VARCHAR(50), entity_id INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL)`);

    /* ── ATTENDANCE TABLES ── */
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
      UNIQUE KEY uniq_user_date(user_id, work_date),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(approved_by) REFERENCES users(id) ON DELETE SET NULL)`);

    await c.query(`CREATE TABLE IF NOT EXISTS holidays(
      id INT AUTO_INCREMENT PRIMARY KEY,
      holiday_date DATE NOT NULL UNIQUE,
      name VARCHAR(100) NOT NULL,
      type ENUM('sunday','public','manual') DEFAULT 'manual',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

    /* ── Seed default admin ── */
    const hash = await bcrypt.hash('Admin@1234',10);
    await c.query(`INSERT IGNORE INTO users(username,email,password_hash,full_name,role,avatar_color)
      VALUES('admin','admin@company.com',?,'System Admin','admin','#7C5CFC')`,[hash]);
    for(const[n,cl] of [['bug','#F87171'],['feature','#5B8AF0'],['design','#8B5CF6'],['backend','#FBBF24'],['frontend','#34D399'],['urgent','#F87171']])
      await c.query('INSERT IGNORE INTO tags(name,color) VALUES(?,?)',[n,cl]);

    c.release(); console.log('Database ready');
  }catch(e){ console.error('DB setup error:',e.message); }
}

/* ─── Helpers ──────────────────────────────────────────── */
const JWT_SECRET = process.env.JWT_SECRET||'synapse_secret';

const auth = async(req,res,next)=>{
  try{
    const t = req.headers.authorization?.split(' ')[1];
    if(!t) return res.status(401).json({error:'No token'});
    req.user = jwt.verify(t,JWT_SECRET); next();
  }catch{ res.status(401).json({error:'Invalid token'}); }
};
const adminOnly = (req,res,next)=>req.user?.role==='admin'?next():res.status(403).json({error:'Admin only'});
const wrap = fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(e=>{console.error(e.message);res.status(500).json({error:e.message||'Server error'});});

// Returns YYYY-MM-DD in local time
const localDate = (d=new Date())=>{
  const y=d.getFullYear(), m=String(d.getMonth()+1).padStart(2,'0'), dd=String(d.getDate()).padStart(2,'0');
  return `${y}-${m}-${dd}`;
};
const isSunday = dateStr => new Date(dateStr+'T12:00:00').getDay()===0;

/* ─── AUTH ─────────────────────────────────────────────── */
app.post('/api/auth/login', wrap(async(req,res)=>{
  const{username,password}=req.body;
  if(!username||!password) return res.status(400).json({error:'Username and password required'});
  const[rows]=await pool.query('SELECT * FROM users WHERE username=? AND is_active=1',[username]);
  if(!rows.length) return res.status(401).json({error:'Invalid credentials'});
  const u=rows[0];
  if(!await bcrypt.compare(password,u.password_hash)) return res.status(401).json({error:'Invalid credentials'});
  const token=jwt.sign({id:u.id,username:u.username,role:u.role},JWT_SECRET,{expiresIn:'8h'});
  pool.query('INSERT INTO activity_log(user_id,action,entity_type) VALUES(?,?,?)',[u.id,'login','user']).catch(()=>{});
  res.json({token,user:{id:u.id,username:u.username,email:u.email,full_name:u.full_name,role:u.role,avatar_color:u.avatar_color}});
}));

/* ─── USERS ─────────────────────────────────────────────── */
app.get('/api/users', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query('SELECT id,username,email,full_name,role,avatar_color,is_active,created_at FROM users ORDER BY full_name');
  res.json(rows);
}));
app.post('/api/users', auth, adminOnly, wrap(async(req,res)=>{
  const{username,email,password,full_name,role}=req.body;
  if(!username||!email||!password) return res.status(400).json({error:'Missing fields'});
  const hash=await bcrypt.hash(password,10);
  const colors=['#3B82F6','#10B981','#F59E0B','#8B5CF6','#EC4899','#06B6D4'];
  const color=colors[Math.floor(Math.random()*colors.length)];
  const[r]=await pool.query('INSERT INTO users(username,email,password_hash,full_name,role,avatar_color) VALUES(?,?,?,?,?,?)',[username,email,hash,full_name||username,role||'member',color]);
  res.json({id:r.insertId,username,email,full_name,role:role||'member',avatar_color:color});
}));
app.put('/api/users/:id', auth, adminOnly, wrap(async(req,res)=>{
  const{email,full_name,role,is_active,password}=req.body;
  const u=[],v=[];
  if(email!==undefined){u.push('email=?');v.push(email);}
  if(full_name!==undefined){u.push('full_name=?');v.push(full_name);}
  if(role!==undefined){u.push('role=?');v.push(role);}
  if(is_active!==undefined){u.push('is_active=?');v.push(is_active?1:0);}
  if(password){u.push('password_hash=?');v.push(await bcrypt.hash(password,10));}
  if(!u.length) return res.status(400).json({error:'Nothing to update'});
  v.push(req.params.id);
  await pool.query(`UPDATE users SET ${u.join(',')} WHERE id=?`,v);
  res.json({success:true});
}));
app.delete('/api/users/:id', auth, adminOnly, wrap(async(req,res)=>{
  if(parseInt(req.params.id)===req.user.id) return res.status(400).json({error:'Cannot deactivate yourself'});
  await pool.query('UPDATE users SET is_active=0 WHERE id=?',[req.params.id]);
  res.json({success:true});
}));

/* ─── TASKS ─────────────────────────────────────────────── */
const buildTaskQuery=(whereExtra,params,userId,isAdmin)=>{
  const vis=isAdmin?'1=1':'(t.creator_id=? OR t.id IN (SELECT task_id FROM task_assignees WHERE user_id=?))';
  if(!isAdmin) params.unshift(userId,userId);
  return `SELECT DISTINCT t.*,
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
  WHERE (${vis}) ${whereExtra}
  GROUP BY t.id ORDER BY t.created_at DESC`;
};
const parseTask=r=>({...r,
  tags:r.tags_raw?r.tags_raw.split('||').map(t=>{const[n,c]=t.split('::');return{name:n,color:c};}):[],
  assignees:r.assignees_raw?r.assignees_raw.split('||').map(a=>{const[id,fn,un,ac]=a.split('::');return{id:parseInt(id),full_name:fn,username:un,avatar_color:ac};}).filter(a=>!isNaN(a.id)):[]
});

app.get('/api/tasks', auth, wrap(async(req,res)=>{
  const{status,tag}=req.query; const params=[];let extra='';
  if(status){extra+=' AND t.status=?';params.push(status);}
  if(tag){extra+=' AND t.id IN (SELECT tt2.task_id FROM task_tags tt2 JOIN tags tg2 ON tt2.tag_id=tg2.id WHERE tg2.name=?)';params.push(tag);}
  const sql=buildTaskQuery(extra,params,req.user.id,req.user.role==='admin');
  const[rows]=await pool.query(sql,params); res.json(rows.map(parseTask));
}));
app.post('/api/tasks', auth, wrap(async(req,res)=>{
  const{title,description,status,priority,assignee_ids,due_date,tags,mentions}=req.body;
  if(!title) return res.status(400).json({error:'Title required'});
  const[r]=await pool.query('INSERT INTO tasks(title,description,status,priority,creator_id,due_date) VALUES(?,?,?,?,?,?)',
    [title,description||'',status||'todo',priority||'medium',req.user.id,due_date||null]);
  const taskId=r.insertId;
  const aList=Array.isArray(assignee_ids)?assignee_ids.map(Number):[];
  for(const uid of aList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}
  if(Array.isArray(tags)&&tags.length){
    for(const tn of tags){try{let[tr]=await pool.query('SELECT id FROM tags WHERE name=?',[tn]);const tid=tr.length?tr[0].id:(await pool.query('INSERT INTO tags(name) VALUES(?)',[tn]))[0].insertId;await pool.query('INSERT IGNORE INTO task_tags VALUES(?,?)',[taskId,tid]);}catch{}}
  }
  for(const uid of aList){if(uid!==req.user.id){try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'assigned']);sendEmail(uid,req.user.username,title,'assigned').catch(()=>{});}catch{}}}
  if(Array.isArray(mentions)&&mentions.length){for(const uid of mentions){if(uid!==req.user.id&&!aList.includes(uid)){try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'mentioned']);sendEmail(uid,req.user.username,title,'mentioned').catch(()=>{});}catch{}}}}
  await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,new_value) VALUES(?,?,?,?)',[taskId,req.user.id,'created',title]);
  res.json({id:taskId});
}));
app.put('/api/tasks/:id', auth, adminOnly, wrap(async(req,res)=>{
  const{title,description,status,priority,assignee_ids,due_date,mentions}=req.body;
  const taskId=req.params.id;
  const[old]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!old.length) return res.status(404).json({error:'Task not found'});
  const prev=old[0];
  await pool.query('UPDATE tasks SET title=?,description=?,status=?,priority=?,due_date=? WHERE id=?',[title,description||'',status,priority,due_date||null,taskId]);
  if(prev.status!==status) await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,field,old_value,new_value) VALUES(?,?,?,?,?,?)',[taskId,req.user.id,'status_changed','status',prev.status,status]);
  if(Array.isArray(assignee_ids)){
    const newList=assignee_ids.map(Number);
    const[oldRows]=await pool.query('SELECT user_id FROM task_assignees WHERE task_id=?',[taskId]);
    const oldList=oldRows.map(r=>r.user_id);
    const newlyAdded=newList.filter(id=>!oldList.includes(id));
    await pool.query('DELETE FROM task_assignees WHERE task_id=?',[taskId]);
    for(const uid of newList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}}
    for(const uid of newlyAdded){if(uid!==req.user.id){try{await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'assigned']);sendEmail(uid,req.user.username,title,'assigned').catch(()=>{});}catch{}}}
  }
  res.json({success:true});
}));
app.delete('/api/tasks/:id', auth, adminOnly, wrap(async(req,res)=>{
  await pool.query('DELETE FROM tasks WHERE id=?',[req.params.id]); res.json({success:true});
}));
app.post('/api/tasks/:id/complete-reassign', auth, wrap(async(req,res)=>{
  const{new_assignee_ids}=req.body; const taskId=req.params.id; const userId=req.user.id;
  const isAdmin=req.user.role==='admin';
  const[assigned]=await pool.query('SELECT * FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);
  if(!assigned.length&&!isAdmin) return res.status(403).json({error:'Not assigned to this task'});
  const[taskRows]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!taskRows.length) return res.status(404).json({error:'Task not found'});
  const task=taskRows[0];
  await pool.query('UPDATE tasks SET status=? WHERE id=?',['done',taskId]);
  await pool.query('DELETE FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);
  const newList=Array.isArray(new_assignee_ids)?new_assignee_ids.map(Number):[];
  for(const uid of newList){try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,userId,'reassigned']);sendEmail(uid,req.user.username,task.title,'reassigned').catch(()=>{});}catch{}}
  await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,new_value) VALUES(?,?,?,?)',[taskId,userId,'completed_and_reassigned',newList.join(',')]);
  res.json({success:true});
}));

/* ─── TAGS ──────────────────────────────────────────────── */
app.get('/api/tags', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query('SELECT * FROM tags ORDER BY name'); res.json(rows);
}));

/* ─── NOTIFICATIONS ──────────────────────────────────────── */
app.get('/api/notifications', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query(`SELECT n.*,t.title as task_title,u.username as triggered_by,u.full_name as triggered_by_name FROM notifications n JOIN tasks t ON n.task_id=t.id JOIN users u ON n.triggered_by_id=u.id WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 30`,[req.user.id]);
  res.json(rows);
}));
app.put('/api/notifications/:id/read', auth, wrap(async(req,res)=>{
  await pool.query('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?',[req.params.id,req.user.id]); res.json({success:true});
}));
app.put('/api/notifications/read-all', auth, wrap(async(req,res)=>{
  await pool.query('UPDATE notifications SET is_read=1 WHERE user_id=?',[req.user.id]); res.json({success:true});
}));

/* ═══════════════════════════════════════════════════════════
   ATTENDANCE MODULE
═══════════════════════════════════════════════════════════ */

/* Ensure Sundays are stored as holidays for a date range */
async function ensureSundaysHolidays(startDate, endDate){
  const start=new Date(startDate+'T12:00:00');
  const end=new Date(endDate+'T12:00:00');
  for(let d=new Date(start);d<=end;d.setDate(d.getDate()+1)){
    if(d.getDay()===0){
      const ds=localDate(d);
      await pool.query('INSERT IGNORE INTO holidays(holiday_date,name,type) VALUES(?,?,?)',[ds,'Sunday','sunday']).catch(()=>{});
    }
  }
}

/* ── Clock In ── */
app.post('/api/attendance/clock-in', auth, wrap(async(req,res)=>{
  const userId=req.user.id;
  const now=new Date();
  const today=localDate(now);

  // Check if Sunday/holiday
  const[hols]=await pool.query('SELECT * FROM holidays WHERE holiday_date=?',[today]);
  if(hols.length) return res.status(400).json({error:`Today is a holiday: ${hols[0].name}`});

  // Check already clocked in today
  const[existing]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  if(existing.length) return res.status(400).json({error:'Already clocked in today'});

  await pool.query(`INSERT INTO attendance(user_id,work_date,clock_in,clock_in_status) VALUES(?,?,?,?)`,[userId,today,now,'pending']);
  // Auto-seed Sunday holidays for this month
  const firstDay=today.slice(0,7)+'-01';
  const lastDay=new Date(now.getFullYear(),now.getMonth()+1,0);
  await ensureSundaysHolidays(firstDay,localDate(lastDay));
  res.json({success:true,message:'Clocked in successfully. Awaiting admin approval.',clock_in:now,status:'pending'});
}));

/* ── Clock Out ── */
app.post('/api/attendance/clock-out', auth, wrap(async(req,res)=>{
  const userId=req.user.id;
  const now=new Date();
  const today=localDate(now);
  const[rows]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  if(!rows.length) return res.status(400).json({error:'You have not clocked in today'});
  const rec=rows[0];
  if(rec.clock_out) return res.status(400).json({error:'Already clocked out today'});
  await pool.query('UPDATE attendance SET clock_out=?,clock_out_status=? WHERE id=?',[now,'pending',rec.id]);
  res.json({success:true,message:'Clocked out. Awaiting admin approval.',clock_out:now,status:'pending'});
}));

/* ── Get my attendance status today ── */
app.get('/api/attendance/today', auth, wrap(async(req,res)=>{
  const userId=req.user.id;
  const today=localDate(new Date());
  const[rows]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date=?',[userId,today]);
  const[hols]=await pool.query('SELECT * FROM holidays WHERE holiday_date=?',[today]);
  res.json({record:rows[0]||null, holiday:hols[0]||null, today});
}));

/* ── My attendance history ── */
app.get('/api/attendance/my', auth, wrap(async(req,res)=>{
  const userId=req.user.id;
  const{year,month}=req.query;
  const y=parseInt(year)||new Date().getFullYear();
  const m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`;
  const lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;

  // Ensure Sundays are stored
  await ensureSundaysHolidays(startDate,endDate);

  const[records]=await pool.query('SELECT * FROM attendance WHERE user_id=? AND work_date BETWEEN ? AND ? ORDER BY work_date',[userId,startDate,endDate]);
  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ? ORDER BY holiday_date',[startDate,endDate]);

  // Build full month report
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
    working_days:report.filter(d=>d.type==='attendance'&&(d.clock_in_status==='approved'||d.clock_in_status==='pending')).length,
    approved:report.filter(d=>d.type==='attendance'&&d.clock_in_status==='approved').length,
    pending:report.filter(d=>d.type==='attendance'&&d.clock_in_status==='pending').length,
    absent:report.filter(d=>d.type==='absent').length,
    holidays:report.filter(d=>d.type==='holiday').length,
    total_work_hours:records.filter(r=>r.approved_clock_in&&r.approved_clock_out).reduce((sum,r)=>{return sum+(new Date(r.approved_clock_out)-new Date(r.approved_clock_in))/3600000;},0).toFixed(1),
  };

  res.json({report,stats,year:y,month:m});
}));

/* ── Admin: All attendance ── */
app.get('/api/admin/attendance', auth, adminOnly, wrap(async(req,res)=>{
  const{year,month,user_id,status}=req.query;
  const y=parseInt(year)||new Date().getFullYear();
  const m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`;
  const lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;

  await ensureSundaysHolidays(startDate,endDate);

  let sql=`SELECT a.*,u.full_name,u.username,u.avatar_color,
    ab.full_name as approver_name
    FROM attendance a
    JOIN users u ON a.user_id=u.id
    LEFT JOIN users ab ON a.approved_by=ab.id
    WHERE a.work_date BETWEEN ? AND ?`;
  const params=[startDate,endDate];
  if(user_id){sql+=' AND a.user_id=?';params.push(user_id);}
  if(status){sql+=' AND a.clock_in_status=?';params.push(status);}
  sql+=' ORDER BY a.work_date DESC, u.full_name';

  const[records]=await pool.query(sql,params);
  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ?',[startDate,endDate]);
  const[users]=await pool.query('SELECT id,full_name,username,avatar_color FROM users WHERE is_active=1 AND role=\'member\' ORDER BY full_name');

  // Build per-user report
  const holidayMap={};holidays.forEach(h=>holidayMap[h.holiday_date]=h);
  const userReports={};

  for(const u of users){
    userReports[u.id]={user:u,days:[]};
    const userRecs={};records.filter(r=>r.user_id===u.id).forEach(r=>userRecs[r.work_date]=r);
    for(let d=1;d<=lastD;d++){
      const dateStr=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
      const today=localDate(new Date());
      if(dateStr>today) continue;
      if(holidayMap[dateStr]){userReports[u.id].days.push({date:dateStr,type:'holiday',name:holidayMap[dateStr].name});continue;}
      if(userRecs[dateStr]){userReports[u.id].days.push({date:dateStr,type:'attendance',...userRecs[dateStr]});continue;}
      userReports[u.id].days.push({date:dateStr,type:'absent'});
    }
  }

  /* Summary stats */
  const[totals]=await pool.query(`SELECT
    COUNT(*) as total,
    SUM(clock_in_status='pending') as pending,
    SUM(clock_in_status='approved') as approved,
    SUM(clock_in_status='rejected') as rejected
    FROM attendance WHERE work_date BETWEEN ? AND ?`,[startDate,endDate]);

  res.json({records,holidays,userReports:Object.values(userReports),stats:totals[0],year:y,month:m});
}));

/* ── Admin: Approve / Edit attendance ── */
app.put('/api/admin/attendance/:id', auth, adminOnly, wrap(async(req,res)=>{
  const{clock_in_status,approved_clock_in,approved_clock_out,admin_note}=req.body;
  const id=req.params.id;
  const u=[],v=[];
  if(clock_in_status!==undefined){u.push('clock_in_status=?');v.push(clock_in_status);}
  if(approved_clock_in!==undefined){u.push('approved_clock_in=?');v.push(approved_clock_in||null);}
  if(approved_clock_out!==undefined){u.push('approved_clock_out=?');v.push(approved_clock_out||null);}
  if(admin_note!==undefined){u.push('admin_note=?');v.push(admin_note);}
  // Set approver info when approving
  if(clock_in_status==='approved'||clock_in_status==='rejected'){
    u.push('approved_by=?');v.push(req.user.id);
    u.push('approved_at=NOW()');
  }
  if(!u.length) return res.status(400).json({error:'Nothing to update'});
  v.push(id);
  await pool.query(`UPDATE attendance SET ${u.join(',')} WHERE id=?`,v);
  res.json({success:true});
}));

/* ── Admin: Bulk approve pending ── */
app.post('/api/admin/attendance/bulk-approve', auth, adminOnly, wrap(async(req,res)=>{
  const{ids}=req.body;
  if(!Array.isArray(ids)||!ids.length) return res.status(400).json({error:'No IDs provided'});
  await pool.query(`UPDATE attendance SET clock_in_status='approved', approved_by=?, approved_at=NOW(),
    approved_clock_in=COALESCE(approved_clock_in,clock_in),
    approved_clock_out=COALESCE(approved_clock_out,clock_out)
    WHERE id IN (${ids.map(()=>'?').join(',')}) AND clock_in_status='pending'`,[req.user.id,...ids]);
  res.json({success:true});
}));

/* ── Admin: Attendance stats dashboard ── */
app.get('/api/admin/attendance/stats', auth, adminOnly, wrap(async(req,res)=>{
  const{year,month}=req.query;
  const y=parseInt(year)||new Date().getFullYear();
  const m=parseInt(month)||new Date().getMonth()+1;
  const startDate=`${y}-${String(m).padStart(2,'0')}-01`;
  const lastD=new Date(y,m,0).getDate();
  const endDate=`${y}-${String(m).padStart(2,'0')}-${String(lastD).padStart(2,'0')}`;

  await ensureSundaysHolidays(startDate,endDate);

  const[[overall]]=await pool.query(`SELECT
    COUNT(*) as total_checkins,
    SUM(clock_in_status='pending') as pending,
    SUM(clock_in_status='approved') as approved,
    SUM(clock_in_status='rejected') as rejected,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(DISTINCT work_date) as days_with_activity
    FROM attendance WHERE work_date BETWEEN ? AND ?`,[startDate,endDate]);

  // Per-user summary
  const[perUser]=await pool.query(`SELECT u.id,u.full_name,u.username,u.avatar_color,
    COUNT(a.id) as check_ins,
    SUM(a.clock_in_status='approved') as approved,
    SUM(a.clock_in_status='pending') as pending,
    SUM(a.clock_in_status='rejected') as rejected,
    SEC_TO_TIME(AVG(
      CASE WHEN a.approved_clock_in IS NOT NULL AND a.approved_clock_out IS NOT NULL
      THEN TIMESTAMPDIFF(SECOND,a.approved_clock_in,a.approved_clock_out) END
    )) as avg_hours
    FROM users u
    LEFT JOIN attendance a ON u.id=a.user_id AND a.work_date BETWEEN ? AND ?
    WHERE u.is_active=1 AND u.role='member'
    GROUP BY u.id ORDER BY approved DESC`,[startDate,endDate]);

  // Daily activity
  const[daily]=await pool.query(`SELECT work_date as date,
    COUNT(*) as total,
    SUM(clock_in_status='approved') as approved,
    SUM(clock_in_status='pending') as pending
    FROM attendance WHERE work_date BETWEEN ? AND ?
    GROUP BY work_date ORDER BY work_date`,[startDate,endDate]);

  // Holidays this month
  const[holidays]=await pool.query('SELECT * FROM holidays WHERE holiday_date BETWEEN ? AND ? ORDER BY holiday_date',[startDate,endDate]);

  // Total working days (non-holidays, non-future)
  const today=localDate(new Date());
  const holidayDates=new Set(holidays.map(h=>h.holiday_date));
  let workingDays=0;
  for(let d=1;d<=lastD;d++){
    const ds=`${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    if(ds<=today&&!holidayDates.has(ds)) workingDays++;
  }

  res.json({overall,perUser,daily,holidays,workingDays,year:y,month:m});
}));

/* ── Admin: Add manual holiday ── */
app.post('/api/admin/holidays', auth, adminOnly, wrap(async(req,res)=>{
  const{holiday_date,name}=req.body;
  if(!holiday_date||!name) return res.status(400).json({error:'Date and name required'});
  await pool.query('INSERT IGNORE INTO holidays(holiday_date,name,type) VALUES(?,?,?)',[holiday_date,name,'manual']);
  res.json({success:true});
}));
app.delete('/api/admin/holidays/:date', auth, adminOnly, wrap(async(req,res)=>{
  await pool.query('DELETE FROM holidays WHERE holiday_date=? AND type=?',[req.params.date,'manual']);
  res.json({success:true});
}));

/* ─── ADMIN STATS (Tasks) ────────────────────────────────── */
app.get('/api/admin/stats', auth, adminOnly, wrap(async(req,res)=>{
  const[[totals]]=await pool.query(`SELECT COUNT(*) as total_tasks,SUM(status='todo') as todo,SUM(status='in_progress') as in_progress,SUM(status='review') as review,SUM(status='done') as done,SUM(priority='urgent') as urgent,SUM(due_date < CURDATE() AND status != 'done') as overdue FROM tasks`);
  const[[users]]=await pool.query(`SELECT COUNT(*) as total,SUM(role='admin') as admins,SUM(is_active=1) as active FROM users`);
  const[perUser]=await pool.query(`SELECT u.id,u.full_name,u.avatar_color,u.username,COUNT(DISTINCT ta.task_id) as assigned,SUM(t.status='done') as completed,SUM(t.status='in_progress') as in_progress,SUM(t.status='todo') as todo FROM users u LEFT JOIN task_assignees ta ON u.id=ta.user_id LEFT JOIN tasks t ON ta.task_id=t.id WHERE u.is_active=1 GROUP BY u.id ORDER BY assigned DESC`);
  const[daily]=await pool.query(`SELECT DATE(created_at) as date,status,COUNT(*) as count FROM tasks WHERE created_at >= DATE_SUB(CURDATE(),INTERVAL 14 DAY) GROUP BY DATE(created_at),status ORDER BY date`);
  const[movements]=await pool.query(`SELECT th.*,t.title as task_title,u.full_name as changed_by_name,u.avatar_color FROM task_history th JOIN tasks t ON th.task_id=t.id JOIN users u ON th.changed_by_id=u.id ORDER BY th.created_at DESC LIMIT 50`);
  const[byPriority]=await pool.query(`SELECT priority,COUNT(*) as count FROM tasks GROUP BY priority`);
  const[byTag]=await pool.query(`SELECT tg.name,tg.color,COUNT(tt.task_id) as count FROM tags tg LEFT JOIN task_tags tt ON tg.id=tt.tag_id GROUP BY tg.id ORDER BY count DESC LIMIT 10`);
  const[activity]=await pool.query(`SELECT al.*,u.full_name,u.avatar_color FROM activity_log al LEFT JOIN users u ON al.user_id=u.id ORDER BY al.created_at DESC LIMIT 20`);
  res.json({totals,users,perUser,daily,movements,byPriority,byTag,activity});
}));

/* ─── SMTP ──────────────────────────────────────────────── */
app.get('/api/admin/smtp', auth, adminOnly, wrap(async(req,res)=>{
  const[r]=await pool.query('SELECT id,host,port,username,encryption,from_email,from_name FROM smtp_config LIMIT 1');
  res.json(r[0]||{});
}));
app.put('/api/admin/smtp', auth, adminOnly, wrap(async(req,res)=>{
  const{host,port,username,password,encryption,from_email,from_name}=req.body;
  const[ex]=await pool.query('SELECT id FROM smtp_config LIMIT 1');
  if(ex.length){const s=['host=?','port=?','username=?','encryption=?','from_email=?','from_name=?'];const v=[host,port,username,encryption,from_email||'',from_name||'Task Manager'];if(password){s.push('password=?');v.push(password);}v.push(ex[0].id);await pool.query(`UPDATE smtp_config SET ${s.join(',')} WHERE id=?`,v);}
  else await pool.query('INSERT INTO smtp_config(host,port,username,password,encryption,from_email,from_name) VALUES(?,?,?,?,?,?,?)',[host,port,username,password||'',encryption,from_email||'',from_name||'Task Manager']);
  res.json({success:true});
}));
app.post('/api/admin/smtp/test', auth, adminOnly, wrap(async(req,res)=>{
  const[rows]=await pool.query('SELECT * FROM smtp_config LIMIT 1');
  if(!rows.length) return res.status(400).json({error:'SMTP not configured'});
  const cfg=rows[0];
  const t=nodemailer.createTransport({host:cfg.host,port:cfg.port,secure:cfg.encryption==='ssl',auth:{user:cfg.username,pass:cfg.password}});
  await t.verify(); res.json({success:true,message:'SMTP connection verified!'});
}));

/* ─── EMAIL ─────────────────────────────────────────────── */
async function sendEmail(userId,triggeredBy,taskTitle,type){
  const[sr]=await pool.query('SELECT * FROM smtp_config LIMIT 1');if(!sr.length)return;
  const[ur]=await pool.query('SELECT email,full_name FROM users WHERE id=?',[userId]);if(!ur.length)return;
  const cfg=sr[0],user=ur[0];
  const subjects={assigned:`Assigned to: ${taskTitle}`,mentioned:`Mentioned in: ${taskTitle}`,reassigned:`Reassigned to you: ${taskTitle}`};
  const bodies={assigned:`<p>Hi ${user.full_name},</p><p><b>@${triggeredBy}</b> assigned you to <b>"${taskTitle}"</b>.</p>`,mentioned:`<p>Hi ${user.full_name},</p><p><b>@${triggeredBy}</b> mentioned you in <b>"${taskTitle}"</b>.</p>`,reassigned:`<p>Hi ${user.full_name},</p><p><b>@${triggeredBy}</b> reassigned <b>"${taskTitle}"</b> to you.</p>`};
  const t=nodemailer.createTransport({host:cfg.host,port:cfg.port,secure:cfg.encryption==='ssl',auth:{user:cfg.username,pass:cfg.password}});
  await t.sendMail({from:`"${cfg.from_name}"<${cfg.from_email||cfg.username}>`,to:user.email,subject:subjects[type]||subjects.assigned,html:bodies[type]||bodies.assigned});
}

app.use((err,req,res,next)=>res.status(500).json({error:'Internal server error'}));

const PORT=process.env.PORT||3001;
setupDatabase().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`Synapse API on port ${PORT}`)));
