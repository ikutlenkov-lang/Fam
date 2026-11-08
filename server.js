const express = require("express");
const http = require("http");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const helmet = require("helmet");
const multer = require("multer");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET || !DATABASE_URL) {
  console.error("Missing JWT_SECRET or DATABASE_URL environment variable");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));

// Главная страница и статические файлы
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", app: "Fam Messenger" });
});

// База данных
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(30) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS files (
      id BIGSERIAL PRIMARY KEY,
      sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size BIGINT NOT NULL,
      data BYTEA NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      content TEXT DEFAULT '',
      attachment_id BIGINT REFERENCES files(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Миграция для уже существующей таблицы messages
  await pool.query(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS attachment_id BIGINT
    REFERENCES files(id) ON DELETE SET NULL
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS messages_chat_idx
    ON messages(sender_id, receiver_id, created_at)
  `);
}

// Авторизация
function createToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: "Требуется вход" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Сессия истекла. Войдите снова." });
  }
}

// Регистрация
app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
      return res.status(400).json({
        error: "Логин: 3–30 символов, только буквы, цифры и _"
      });
    }

    if (password.length < 6 || password.length > 100) {
      return res.status(400).json({
        error: "Пароль должен содержать от 6 до 100 символов"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users(username, password)
       VALUES($1, $2)
       RETURNING id, username`,
      [username, hash]
    );

    const user = result.rows[0];

    res.json({
      token: createToken(user),
      user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Такой логин уже занят" });
    }

    console.error(error);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

// Вход
app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Неверный логин или пароль" });
    }

    res.json({
      token: createToken(user),
      user: { id: user.id, username: user.username }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

// Текущий пользователь
app.get("/api/me", auth, async (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username
  });
});

// Список пользователей
app.get("/api/users", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username
       FROM users
       WHERE id != $1
       ORDER BY username`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Не удалось загрузить пользователей" });
  }
});

// История переписки
app.get("/api/messages/:userId", auth, async (req, res) => {
  try {
    const otherId = Number(req.params.userId);

    if (!Number.isInteger(otherId) || otherId <= 0) {
      return res.status(400).json({ error: "Некорректный пользователь" });
    }

    const result = await pool.query(
      `SELECT
         m.id,
         m.sender_id,
         m.receiver_id,
         m.content,
         m.attachment_id,
         m.created_at,
         f.original_name,
         f.mime_type,
         f.file_size
       FROM messages m
       LEFT JOIN files f ON f.id = m.attachment_id
       WHERE
         (m.sender_id = $1 AND m.receiver_id = $2)
         OR
         (m.sender_id = $2 AND m.receiver_id = $1)
       ORDER BY m.created_at ASC
       LIMIT 500`,
      [req.user.id, otherId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Ошибка загрузки сообщений" });
  }
});

// Загрузка файлов
const allowedTypes = new Set([
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "image/heic",
  "application/pdf",
  "text/plain",
  "text/csv",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!allowedTypes.has(file.mimetype)) {
      return cb(new Error("Этот тип файла не поддерживается"));
    }
    cb(null, true);
  }
});

app.post("/api/upload", auth, (req, res) => {
  upload.single("file")(req, res, async (error) => {
    if (error) {
      return res.status(400).json({
        error: error.code === "LIMIT_FILE_SIZE"
          ? "Максимальный размер файла — 15 МБ"
          : error.message
      });
    }

    try {
      if (!req.file) {
        return res.status(400).json({ error: "Файл не выбран" });
      }

      const receiverId = Number(req.body.receiverId);

      if (!Number.isInteger(receiverId) || receiverId <= 0 ||
          receiverId === Number(req.user.id)) {
        return res.status(400).json({ error: "Некорректный получатель" });
      }

      const recipient = await pool.query(
        "SELECT id FROM users WHERE id = $1",
        [receiverId]
      );

      if (!recipient.rowCount) {
        return res.status(404).json({ error: "Пользователь не найден" });
      }

      const result = await pool.query(
        `INSERT INTO files
         (sender_id, receiver_id, original_name, mime_type, file_size, data)
         VALUES($1, $2, $3, $4, $5, $6)
         RETURNING id, original_name, mime_type, file_size`,
        [
          req.user.id,
          receiverId,
          req.file.originalname.slice(0, 255),
          req.file.mimetype,
          req.file.size,
          req.file.buffer
        ]
      );

      res.json(result.rows[0]);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Ошибка загрузки файла" });
    }
  });
});

// Получение файла
app.get("/api/files/:id", auth, async (req, res) => {
  try {
    const fileId = Number(req.params.id);

    if (!Number.isInteger(fileId) || fileId <= 0) {
      return res.status(400).json({ error: "Некорректный файл" });
    }

    const result = await pool.query(
      `SELECT original_name, mime_type, data
       FROM files
       WHERE id = $1
       AND (sender_id = $2 OR receiver_id = $2)`,
      [fileId, req.user.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Файл не найден" });
    }

    const file = result.rows[0];

    res.setHeader("Content-Type", file.mime_type);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Content-Disposition", "attachment");

    res.send(file.data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Ошибка получения файла" });
  }
});

// Socket.IO авторизация
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      return next(new Error("Требуется авторизация"));
    }

    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error("Недействительная сессия"));
  }
});

io.on("connection", (socket) => {
  const myId = Number(socket.user.id);

  socket.join(`user:${myId}`);

  socket.on("send_message", async (data, callback) => {
    try {
      const receiverId = Number(data?.receiverId);
      const content = String(data?.content || "").trim();
      const attachmentId = data?.attachmentId
        ? Number(data.attachmentId)
        : null;

      if (!Number.isInteger(receiverId) ||
          receiverId <= 0 ||
          receiverId === myId) {
        throw new Error("Некорректный получатель");
      }

      if (!content && !attachmentId) {
        throw new Error("Пустое сообщение");
      }

      if (content.length > 5000) {
        throw new Error("Сообщение слишком длинное");
      }

      const recipient = await pool.query(
        "SELECT id FROM users WHERE id = $1",
        [receiverId]
      );

      if (!recipient.rowCount) {
        throw new Error("Пользователь не найден");
      }

      if (attachmentId) {
        const file = await pool.query(
          `SELECT id FROM files
           WHERE id = $1
           AND sender_id = $2
           AND receiver_id = $3`,
          [attachmentId, myId, receiverId]
        );

        if (!file.rowCount) {
          throw new Error("Файл не найден или не принадлежит этой переписке");
        }
      }

      const result = await pool.query(
        `INSERT INTO messages
         (sender_id, receiver_id, content, attachment_id)
         VALUES($1, $2, $3, $4)
         RETURNING id, sender_id, receiver_id, content,
                   attachment_id, created_at`,
        [myId, receiverId, content, attachmentId]
      );

      const message = result.rows[0];

      if (attachmentId) {
        const file = await pool.query(
          `SELECT original_name, mime_type, file_size
           FROM files WHERE id = $1`,
          [attachmentId]
        );

        Object.assign(message, {
          original_name: file.rows[0].original_name,
          mime_type: file.rows[0].mime_type,
          file_size: file.rows[0].file_size
        });
      }

      io.to(`user:${receiverId}`).emit("new_message", message);
      io.to(`user:${myId}`).emit("new_message", message);

      if (typeof callback === "function") {
        callback({ ok: true, message });
      }
    } catch (error) {
      if (typeof callback === "function") {
        callback({ ok: false, error: error.message });
      }
    }
  });
});

// Ошибки
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Внутренняя ошибка сервера" });
});

async function start() {
  try {
    await initDatabase();

    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Fam Messenger started on port ${PORT}`);
    });
  } catch (error) {
    console.error("Database startup error:", error);
    process.exit(1);
  }
}

start();
