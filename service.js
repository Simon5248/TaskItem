// server.js

// --- 引入依賴 ---
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// --- 常數設定 ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-super-secret-key-that-should-be-in-env-vars'; // 在生產環境中，請務必使用環境變數
const DB_FILE = 'database.sqlite';

// --- 初始化 Express 應用 ---
const app = express();
app.use(cors()); // 允許跨來源請求 (CORS)
app.use(express.json()); // 解析 JSON 請求體

// --- 連接/初始化 SQLite 資料庫 ---
const db = new sqlite3.Database(DB_FILE, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // 建立資料表 (如果不存在)
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        `);
        db.run(`
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `);
    }
});

// --- 中介軟體：驗證 JWT ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // 未提供 token

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Token 無效或過期
        req.user = user;
        next();
    });
};

// --- API 路由 ---

// 1. 使用者認證路由 (Auth)
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password || password.length < 6) {
        return res.status(400).json({ message: '無效的 Email 或密碼 (密碼需至少6位數)。' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO users (email, password) VALUES (?, ?)';
    db.run(sql, [email, hashedPassword], function(err) {
        if (err) {
            // 檢查是否為 UNIQUE constraint 錯誤
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(409).json({ message: '此 Email 已被註冊。' });
            }
            return res.status(500).json({ message: '註冊失敗，請稍後再試。' });
        }
        res.status(201).json({ message: '註冊成功！', userId: this.lastID });
    });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.get(sql, [email], async (err, user) => {
        if (err) return res.status(500).json({ message: '伺服器錯誤。' });
        if (!user) return res.status(404).json({ message: '此 Email 尚未註冊。' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: '密碼錯誤。' });

        // 登入成功，產生 JWT
        const accessToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1d' }); // Token 有效期為 1 天
        res.json({ accessToken });
    });
});


// 2. 任務 CRUD 路由 (受保護的)
app.get('/api/tasks', authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC';
    db.all(sql, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ message: '無法獲取任務。' });
        res.json(rows);
    });
});

app.post('/api/tasks', authenticateToken, (req, res) => {
    const { title, description, status, priority } = req.body;
    if (!title) return res.status(400).json({ message: '標題為必填欄位。' });
    
    const sql = 'INSERT INTO tasks (title, description, status, priority, user_id) VALUES (?, ?, ?, ?, ?)';
    db.run(sql, [title, description, status, priority, req.user.id], function(err) {
        if (err) return res.status(500).json({ message: '新增任務失敗。' });
        res.status(201).json({ id: this.lastID, ...req.body });
    });
});

app.put('/api/tasks/:id', authenticateToken, (req, res) => {
    const { title, description, status, priority } = req.body;
    const { id } = req.params;

    const sql = `UPDATE tasks SET title = ?, description = ?, status = ?, priority = ?, updated_at = CURRENT_TIMESTAMP 
                 WHERE id = ? AND user_id = ?`;
    db.run(sql, [title, description, status, priority, id, req.user.id], function(err) {
        if (err) return res.status(500).json({ message: '更新任務失敗。' });
        if (this.changes === 0) return res.status(404).json({ message: '找不到任務或權限不足。' });
        res.json({ message: '任務更新成功。' });
    });
});

app.delete('/api/tasks/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const sql = 'DELETE FROM tasks WHERE id = ? AND user_id = ?';
    db.run(sql, [id, req.user.id], function(err) {
        if (err) return res.status(500).json({ message: '刪除任務失敗。' });
        if (this.changes === 0) return res.status(404).json({ message: '找不到任務或權限不足。' });
        res.status(204).send(); // No Content
    });
});

// --- 啟動伺服器 ---
app.listen(PORT, () => {
    console.log(`後端伺服器正在 http://localhost:${PORT} 上運行`);
});

/*
--- package.json 範例 ---
{
  "name": "task-app-backend",
  "version": "1.0.0",
  "description": "A simple backend for the tasks application.",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "sqlite3": "^5.1.6"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  }
}
*/
