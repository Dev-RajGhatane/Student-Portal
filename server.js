const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_IN_PRODUCTION";

const db = new Database("school_coding.db");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  language TEXT NOT NULL,
  code TEXT NOT NULL DEFAULT '',
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL DEFAULT '',
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

const adminEmail = process.env.ADMIN_EMAIL || "admin@school.local";
const adminPassword = process.env.ADMIN_PASSWORD || "Admin@12345";
const existingAdmin = db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
if (!existingAdmin) {
  db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)")
    .run("School Admin", adminEmail, bcrypt.hashSync(adminPassword, 12), "admin");
  console.log(`Admin created: ${adminEmail} / ${adminPassword}`);
}

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    if (!token) return res.status(401).json({ error: "Login required" });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired session" });
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  next();
}

app.post("/api/signup", (req,res)=>{
  const {name,email,password}=req.body;
  if(!name || !email || !password || password.length<6)
    return res.status(400).json({error:"Name, valid email and password (6+ characters) are required"});
  try {
    const hash=bcrypt.hashSync(password,12);
    const result=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name.trim(),email.trim().toLowerCase(),hash);
    const user={id:result.lastInsertRowid,name:name.trim(),email:email.trim().toLowerCase(),role:"student"};
    const token=jwt.sign(user,JWT_SECRET,{expiresIn:"7d"});
    res.json({token,user});
  } catch(e) {
    res.status(409).json({error:"Email is already registered"});
  }
});

app.post("/api/login",(req,res)=>{
  const {email,password}=req.body;
  const u=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").trim().toLowerCase());
  if(!u || !bcrypt.compareSync(password||"",u.password_hash))
    return res.status(401).json({error:"Incorrect email or password"});
  const user={id:u.id,name:u.name,email:u.email,role:u.role};
  const token=jwt.sign(user,JWT_SECRET,{expiresIn:"7d"});
  res.json({token,user});
});

app.get("/api/me",auth,(req,res)=>res.json(req.user));

app.get("/api/projects",auth,(req,res)=>{
  const rows=req.user.role==="admin"
    ? db.prepare(`SELECT p.*,u.name student_name,u.email student_email FROM projects p JOIN users u ON u.id=p.user_id ORDER BY p.updated_at DESC`).all()
    : db.prepare("SELECT * FROM projects WHERE user_id=? ORDER BY updated_at DESC").all(req.user.id);
  res.json(rows);
});

app.post("/api/projects",auth,(req,res)=>{
  const {title,language,code}=req.body;
  if(!title || !["html","css","javascript","python"].includes(language))
    return res.status(400).json({error:"Title and supported language are required"});
  const result=db.prepare("INSERT INTO projects(user_id,title,language,code,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)")
    .run(req.user.id,title,language,code||"");
  res.json({id:result.lastInsertRowid});
});

app.put("/api/projects/:id",auth,(req,res)=>{
  const p=db.prepare("SELECT * FROM projects WHERE id=?").get(req.params.id);
  if(!p) return res.status(404).json({error:"Project not found"});
  if(req.user.role!=="admin" && p.user_id!==req.user.id) return res.status(403).json({error:"Not allowed"});
  db.prepare("UPDATE projects SET title=?,language=?,code=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
    .run(req.body.title,p.language,req.body.code||"",p.id);
  res.json({ok:true});
});

app.delete("/api/projects/:id",auth,(req,res)=>{
  const p=db.prepare("SELECT * FROM projects WHERE id=?").get(req.params.id);
  if(!p) return res.status(404).json({error:"Project not found"});
  if(req.user.role!=="admin" && p.user_id!==req.user.id) return res.status(403).json({error:"Not allowed"});
  db.prepare("DELETE FROM projects WHERE id=?").run(p.id);
  res.json({ok:true});
});

app.get("/api/students",auth,adminOnly,(req,res)=>{
  res.json(db.prepare(`
    SELECT u.id,u.name,u.email,u.created_at,COUNT(p.id) project_count
    FROM users u LEFT JOIN projects p ON p.user_id=u.id
    WHERE u.role='student' GROUP BY u.id ORDER BY u.created_at DESC
  `).all());
});

app.get("/api/notes",auth,(req,res)=>{
  res.json(db.prepare("SELECT * FROM notes WHERE user_id=? ORDER BY updated_at DESC").all(req.user.id));
});
app.post("/api/notes",auth,(req,res)=>{
  const {title,content}=req.body;
  const r=db.prepare("INSERT INTO notes(user_id,title,content,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP)")
    .run(req.user.id,title||"My Note",content||"");
  res.json({id:r.lastInsertRowid});
});
app.put("/api/notes/:id",auth,(req,res)=>{
  db.prepare("UPDATE notes SET title=?,content=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?")
    .run(req.body.title,req.body.content,req.params.id,req.user.id);
  res.json({ok:true});
});
app.delete("/api/notes/:id",auth,(req,res)=>{
  db.prepare("DELETE FROM notes WHERE id=? AND user_id=?").run(req.params.id,req.user.id);
  res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Student Coding Portal: http://localhost:${PORT}`));