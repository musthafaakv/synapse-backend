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

    const hash = await bcrypt.hash('Admin@1234',10);
    await c.query(`INSERT IGNORE INTO users(username,email,password_hash,full_name,role,avatar_color)
      VALUES('admin','admin@company.com',?,'System Admin','admin','#7C5CFC')`,[hash]);
    for(const[n,cl] of [['bug','#F87171'],['feature','#5B8AF0'],['design','#8B5CF6'],['backend','#FBBF24'],['frontend','#34D399'],['urgent','#F87171']])
      await c.query('INSERT IGNORE INTO tags(name,color) VALUES(?,?)',[n,cl]);

    c.release(); console.log('Database ready');
  }catch(e){ console.error('DB setup error:',e.message); }
}

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

// ── AUTH ──
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

// ── USERS ──
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

// ── TASKS ──
const buildTaskQuery = (whereExtra, params, userId, isAdmin) => {
  const visibilityClause = isAdmin ? '1=1'
    : '(t.creator_id=? OR t.id IN (SELECT task_id FROM task_assignees WHERE user_id=?))';
  if(!isAdmin){ params.unshift(userId,userId); }
  return `SELECT DISTINCT t.*,
    u1.username as creator_username, u1.full_name as creator_name, u1.avatar_color as creator_color,
    GROUP_CONCAT(DISTINCT CONCAT(tg.name,'::',tg.color) ORDER BY tg.name SEPARATOR '||') as tags_raw,
    GROUP_CONCAT(DISTINCT CONCAT(u2.id,'::',IFNULL(u2.full_name,''),'::',u2.username,'::',IFNULL(u2.avatar_color,'#3B82F6'))
      ORDER BY u2.full_name SEPARATOR '||') as assignees_raw
  FROM tasks t
  LEFT JOIN users u1 ON t.creator_id=u1.id
  LEFT JOIN task_assignees ta ON t.id=ta.task_id
  LEFT JOIN users u2 ON ta.user_id=u2.id
  LEFT JOIN task_tags tt ON t.id=tt.task_id
  LEFT JOIN tags tg ON tt.tag_id=tg.id
  WHERE (${visibilityClause}) ${whereExtra}
  GROUP BY t.id ORDER BY t.created_at DESC`;
};

const parseTask = r=>({...r,
  tags: r.tags_raw?r.tags_raw.split('||').map(t=>{const[name,color]=t.split('::');return{name,color};}):[],
  assignees: r.assignees_raw?r.assignees_raw.split('||').map(a=>{const[id,fn,un,ac]=a.split('::');return{id:parseInt(id),full_name:fn,username:un,avatar_color:ac};}).filter(a=>!isNaN(a.id)):[]
});

app.get('/api/tasks', auth, wrap(async(req,res)=>{
  const{status,tag}=req.query;
  const params=[];
  let extra='';
  if(status){extra+=' AND t.status=?';params.push(status);}
  if(tag){extra+=' AND t.id IN (SELECT tt2.task_id FROM task_tags tt2 JOIN tags tg2 ON tt2.tag_id=tg2.id WHERE tg2.name=?)';params.push(tag);}
  const sql=buildTaskQuery(extra,params,req.user.id,req.user.role==='admin');
  const[rows]=await pool.query(sql,params);
  res.json(rows.map(parseTask));
}));

app.post('/api/tasks', auth, wrap(async(req,res)=>{
  const{title,description,status,priority,assignee_ids,due_date,tags,mentions}=req.body;
  if(!title) return res.status(400).json({error:'Title required'});
  const[r]=await pool.query('INSERT INTO tasks(title,description,status,priority,creator_id,due_date) VALUES(?,?,?,?,?,?)',
    [title,description||'',status||'todo',priority||'medium',req.user.id,due_date||null]);
  const taskId=r.insertId;
  const aList=Array.isArray(assignee_ids)?assignee_ids.map(Number):[];
  for(const uid of aList){
    try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}
  }
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
  await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,new_value) VALUES(?,?,?,?)',
    [taskId,req.user.id,'created',title]);
  pool.query('INSERT INTO activity_log(user_id,action,entity_type,entity_id) VALUES(?,?,?,?)',[req.user.id,'create_task','task',taskId]).catch(()=>{});
  res.json({id:taskId});
}));

// Full edit — ADMIN ONLY
app.put('/api/tasks/:id', auth, adminOnly, wrap(async(req,res)=>{
  const{title,description,status,priority,assignee_ids,due_date,mentions}=req.body;
  const taskId=req.params.id;
  const[old]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!old.length) return res.status(404).json({error:'Task not found'});
  const prev=old[0];

  await pool.query('UPDATE tasks SET title=?,description=?,status=?,priority=?,due_date=? WHERE id=?',
    [title,description||'',status,priority,due_date||null,taskId]);

  // Log status change
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
    const[oldRows]=await pool.query('SELECT user_id FROM task_assignees WHERE task_id=?',[taskId]);
    const oldList=oldRows.map(r=>r.user_id);
    const newlyAdded=newList.filter(id=>!oldList.includes(id));
    await pool.query('DELETE FROM task_assignees WHERE task_id=?',[taskId]);
    for(const uid of newList){
      try{await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);}catch{}
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
  if(Array.isArray(mentions)&&mentions.length){
    for(const uid of mentions){
      if(uid!==req.user.id){
        try{
          await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,req.user.id,'mentioned']);
          sendEmail(uid,req.user.username,title,'mentioned').catch(()=>{});
        }catch{}
      }
    }
  }
  pool.query('INSERT INTO activity_log(user_id,action,entity_type,entity_id) VALUES(?,?,?,?)',[req.user.id,'update_task','task',taskId]).catch(()=>{});
  res.json({success:true});
}));

// Delete — ADMIN ONLY
app.delete('/api/tasks/:id', auth, adminOnly, wrap(async(req,res)=>{
  await pool.query('DELETE FROM tasks WHERE id=?',[req.params.id]);
  res.json({success:true});
}));

// Mark complete + reassign — available to assigned users
app.post('/api/tasks/:id/complete-reassign', auth, wrap(async(req,res)=>{
  const{new_assignee_ids}=req.body;
  const taskId=req.params.id;
  const userId=req.user.id;
  const isAdmin=req.user.role==='admin';

  // Check permission: must be assigned or admin
  const[assigned]=await pool.query('SELECT * FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);
  if(!assigned.length&&!isAdmin) return res.status(403).json({error:'You are not assigned to this task'});

  const[taskRows]=await pool.query('SELECT * FROM tasks WHERE id=?',[taskId]);
  if(!taskRows.length) return res.status(404).json({error:'Task not found'});
  const task=taskRows[0];

  // Mark task as done
  await pool.query('UPDATE tasks SET status=? WHERE id=?',['done',taskId]);
  await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,field,old_value,new_value) VALUES(?,?,?,?,?,?)',
    [taskId,userId,'status_changed','status',task.status,'done']);

  // Remove current user from assignees
  await pool.query('DELETE FROM task_assignees WHERE task_id=? AND user_id=?',[taskId,userId]);

  // Add new assignees if provided
  const newList=Array.isArray(new_assignee_ids)?new_assignee_ids.map(Number):[];
  for(const uid of newList){
    try{
      await pool.query('INSERT IGNORE INTO task_assignees(task_id,user_id) VALUES(?,?)',[taskId,uid]);
      // Notify new assignees
      await pool.query('INSERT INTO notifications(user_id,task_id,triggered_by_id,type) VALUES(?,?,?,?)',[uid,taskId,userId,'reassigned']);
      sendEmail(uid,req.user.username,task.title,'reassigned').catch(()=>{});
    }catch{}
  }

  await pool.query('INSERT INTO task_history(task_id,changed_by_id,action,new_value) VALUES(?,?,?,?)',
    [taskId,userId,'completed_and_reassigned',newList.join(',')]);
  pool.query('INSERT INTO activity_log(user_id,action,entity_type,entity_id) VALUES(?,?,?,?)',[userId,'complete_reassign','task',taskId]).catch(()=>{});
  res.json({success:true});
}));

// ── TAGS ──
app.get('/api/tags', auth, wrap(async(req,res)=>{
  const[rows]=await pool.query('SELECT * FROM tags ORDER BY name');
  res.json(rows);
}));

// ── NOTIFICATIONS ──
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

// ── ADMIN STATS ──
app.get('/api/admin/stats', auth, adminOnly, wrap(async(req,res)=>{
  const[[totals]]=await pool.query(`SELECT
    COUNT(*) as total_tasks,
    SUM(status='todo') as todo,
    SUM(status='in_progress') as in_progress,
    SUM(status='review') as review,
    SUM(status='done') as done,
    SUM(priority='urgent') as urgent,
    SUM(priority='high') as high,
    SUM(due_date < CURDATE() AND status != 'done') as overdue
    FROM tasks`);

  const[[users]]=await pool.query(`SELECT COUNT(*) as total,SUM(role='admin') as admins,SUM(is_active=1) as active FROM users`);

  // Tasks per user
  const[perUser]=await pool.query(`
    SELECT u.id,u.full_name,u.avatar_color,u.username,
      COUNT(DISTINCT ta.task_id) as assigned,
      SUM(t.status='done') as completed,
      SUM(t.status='in_progress') as in_progress,
      SUM(t.status='todo') as todo
    FROM users u
    LEFT JOIN task_assignees ta ON u.id=ta.user_id
    LEFT JOIN tasks t ON ta.task_id=t.id
    WHERE u.is_active=1
    GROUP BY u.id ORDER BY assigned DESC`);

  // Status over time (last 14 days)
  const[daily]=await pool.query(`
    SELECT DATE(created_at) as date, status, COUNT(*) as count
    FROM tasks WHERE created_at >= DATE_SUB(CURDATE(),INTERVAL 14 DAY)
    GROUP BY DATE(created_at),status ORDER BY date`);

  // Recent task history / movements
  const[movements]=await pool.query(`
    SELECT th.*,t.title as task_title,u.full_name as changed_by_name,u.avatar_color
    FROM task_history th
    JOIN tasks t ON th.task_id=t.id
    JOIN users u ON th.changed_by_id=u.id
    ORDER BY th.created_at DESC LIMIT 50`);

  // Tasks by priority
  const[byPriority]=await pool.query(`SELECT priority,COUNT(*) as count FROM tasks GROUP BY priority`);

  // Tasks by tag
  const[byTag]=await pool.query(`
    SELECT tg.name,tg.color,COUNT(tt.task_id) as count
    FROM tags tg LEFT JOIN task_tags tt ON tg.id=tt.tag_id
    GROUP BY tg.id ORDER BY count DESC LIMIT 10`);

  // Completion rate per user
  const[completionRate]=await pool.query(`
    SELECT u.full_name,u.avatar_color,
      COUNT(DISTINCT ta.task_id) as total,
      SUM(t.status='done') as done
    FROM users u
    JOIN task_assignees ta ON u.id=ta.user_id
    JOIN tasks t ON ta.task_id=t.id
    WHERE u.is_active=1 GROUP BY u.id HAVING total > 0 ORDER BY done DESC`);

  // Recent activity
  const[activity]=await pool.query(`
    SELECT al.*,u.full_name,u.avatar_color
    FROM activity_log al LEFT JOIN users u ON al.user_id=u.id
    ORDER BY al.created_at DESC LIMIT 20`);

  res.json({totals,users,perUser,daily,movements,byPriority,byTag,completionRate,activity});
}));

// ── SMTP ──
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

// ── EMAIL ──
async function sendEmail(userId,triggeredBy,taskTitle,type){
  const[sr]=await pool.query('SELECT * FROM smtp_config LIMIT 1');
  if(!sr.length)return;
  const[ur]=await pool.query('SELECT email,full_name FROM users WHERE id=?',[userId]);
  if(!ur.length)return;
  const cfg=sr[0],user=ur[0];
  const subjects={assigned:`You were assigned to: ${taskTitle}`,mentioned:`You were mentioned in: ${taskTitle}`,reassigned:`A task was reassigned to you: ${taskTitle}`,completed:`Task completed: ${taskTitle}`};
  const bodies={
    assigned:`<p>Hi ${user.full_name},</p><p><b>@${triggeredBy}</b> assigned you to the task <b>"${taskTitle}"</b>.</p>`,
    mentioned:`<p>Hi ${user.full_name},</p><p><b>@${triggeredBy}</b> mentioned you in <b>"${taskTitle}"</b>.</p>`,
    reassigned:`<p>Hi ${user.full_name},</p><p><b>@${triggeredBy}</b> completed a task and reassigned it to you: <b>"${taskTitle}"</b>.</p>`,
  };
  const t=nodemailer.createTransport({host:cfg.host,port:cfg.port,secure:cfg.encryption==='ssl',auth:{user:cfg.username,pass:cfg.password}});
  await t.sendMail({from:`"${cfg.from_name}"<${cfg.from_email||cfg.username}>`,to:user.email,subject:subjects[type]||subjects.assigned,html:bodies[type]||bodies.assigned});
}

app.use((err,req,res,next)=>res.status(500).json({error:'Internal server error'}));

const PORT=process.env.PORT||3001;
setupDatabase().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`Synapse API on port ${PORT}`)));
