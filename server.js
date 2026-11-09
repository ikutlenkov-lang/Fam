
const express = require("express");
const http = require("http");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require("multer");
const helmet = require("helmet");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const TOKEN_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!TOKEN_SECRET || !DATABASE_URL) {
  console.error("Missing JWT_SECRET or DATABASE_URL");
  process.exit(1);
}

// PostgreSQL
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : undefined
});

// Разрешённые источники
const allowedOrigins = new Set([
  "null",
  "https://fam-4xqf.onrender.com",
  "https://appassets.androidplatform.net",
  "https://localhost",
  "http://localhost"
]);

function isAllowedOrigin(origin) {
  return !origin || allowedOrigins.has(origin);
}

// CORS для обычных HTTP-запросов
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && isAllowedOrigin(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  if (origin && !isAllowedOrigin(origin)) {
    return res.status(403).json({ error: "Origin not allowed" });
  }

  next();
});

// Настройки безопасности
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Статические файлы сайта
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Socket.IO
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      if (isAllowedOrigin(origin)) {
        return callback(null, true);
      }
      callback(new Error("Origin not allowed"));
    },
    methods: ["GET", "POST"]
  }
});

// Проверка JWT
function createToken(user) {
  return jwt.sign(
    { userId: user.id },
    TOKEN_SECRET,
    { expiresIn: "30d" }
  );
}

function verifyToken(token) {
  return jwt.verify(token, TOKEN_SECRET);
}

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({ error: "Authorization required" });
    }

    const decoded = verifyToken(token);

    const result = await pool.query(
      "SELECT id, username FROM users WHERE id = $1",
      [decoded.userId]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "User not found" });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Загрузка файлов
const allowedMimeTypes = new Set([
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
  limits: {
    fileSize: 15 * 1024 * 1024
  },
  fileFilter: (req, file, callback) => {
    if (!allowedMimeTypes.has(file.mimetype)) {
      return callback(new Error("File type not allowed"));
    }
    callback(null, true);
  }
});

// Проверка сервера
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// Регистрация
app.post("/api/register", async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({
        error: "Имя: 3-24 символа, только латиница, цифры и _"
      });
    }

    if (password.length < 6 || password.length > 128) {
      return res.status(400).json({
        error: "Пароль должен содержать от 6 до 128 символов"
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE LOWER(username) = LOWER($1)",
      [username]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        error: "Это имя пользователя уже занято"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, password)
       VALUES ($1, $2)
       RETURNING id, username`,
      [username, passwordHash]
    );

    const user = result.rows[0];

    res.status(201).json({
      token: createToken(user),
      user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Это имя пользователя уже занято"
      });
    }
    next(error);
  }
});

// Вход
app.post("/api/login", async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const result = await pool.query(
      `SELECT id, username, password
       FROM users
       WHERE LOWER(username) = LOWER($1)`,
      [username]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Неверное имя пользователя или пароль"
      });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({
        error: "Неверное имя пользователя или пароль"
      });
    }

    res.json({
      token: createToken(user),
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (error) {
    next(error);
  }
});

// Информация о текущем пользователе
app.get("/api/me", authenticate, (req, res) => {
  res.json(req.user);
});

// Список пользователей
app.get("/api/users", authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, username
       FROM users
       WHERE id <> $1
       ORDER BY username ASC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    next(error);
  }
});

// История переписки
app.get("/api/messages/:userId", authenticate, async (req, res, next) => {
  try {
    const otherId = Number(req.params.userId);

    if (!Number.isInteger(otherId) || otherId <= 0) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const result = await pool.query(
      `SELECT id, sender_id, receiver_id, content,
              attachment_id, created_at
       FROM messages
       WHERE
         (sender_id = $1 AND receiver_id = $2)
         OR
         (sender_id = $2 AND receiver_id = $1)
       ORDER BY created_at ASC
       LIMIT 1000`,
      [req.user.id, otherId]
    );

    res.json(result.rows);
  } catch (error) {
    next(error);
  }
});

// Загрузка вложения
app.post(
  "/api/upload",
  authenticate,
  upload.single("file"),
  async (req, res, next) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "File is required" });
      }

      const receiverId = Number(req.body.receiverId);

      if (!Number.isInteger(receiverId) || receiverId <= 0) {
        return res.status(400).json({ error: "Invalid receiver ID" });
      }

      const receiver = await pool.query(
        "SELECT id FROM users WHERE id = $1",
        [receiverId]
      );

      if (!receiver.rows.length) {
        return res.status(404).json({ error: "Receiver not found" });
      }

      const result = await pool.query(
        `INSERT INTO files
         (sender_id, receiver_id, original_name, mime_type, file_size, data)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id`,
        [
          req.user.id,
          receiverId,
          req.file.originalname,
          req.file.mimetype,
          req.file.size,
          req.file.buffer
        ]
      );

      res.status(201).json({
        id: result.rows[0].id
      });
    } catch (error) {
      next(error);
    }
  }
);

// Скачивание вложения
app.get("/api/files/:id", authenticate, async (req, res, next) => {
  try {
    const fileId = Number(req.params.id);

    if (!Number.isInteger(fileId) || fileId <= 0) {
      return res.status(400).json({ error: "Invalid file ID" });
    }

    const result = await pool.query(
      `SELECT original_name, mime_type, data, sender_id, receiver_id
       FROM files
       WHERE id = $1
       AND (sender_id = $2 OR receiver_id = $2)`,
      [fileId, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "File not found" });
    }

    const file = result.rows[0];

    res.setHeader("Content-Type", file.mime_type);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename*=UTF-8''${encodeURIComponent(file.original_name)}`
    );
    res.setHeader("Content-Length", file.data.length);

    res.send(file.data);
  } catch (error) {
    next(error);
  }
});

// Авторизация Socket.IO
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      return next(new Error("Authentication required"));
    }

    const decoded = verifyToken(token);

    const result = await pool.query(
      "SELECT id, username FROM users WHERE id = $1",
      [decoded.userId]
    );

    if (!result.rows.length) {
      return next(new Error("User not found"));
    }

    socket.user = result.rows[0];
    next();
  } catch (error) {
    next(new Error("Invalid or expired token"));
  }
});

// Соединение пользователя
io.on("connection", socket => {
  const userId = socket.user.id;

  socket.join(`user:${userId}`);

  console.log("User connected:", userId);

  // Отправка сообщения
  socket.on("send_message", async (payload, callback) => {
    try {
      const receiverId = Number(payload?.receiverId);
      const content = String(payload?.content || "").trim();
      const attachmentId = payload?.attachmentId
        ? Number(payload.attachmentId)
        : null;

      if (!Number.isInteger(receiverId) || receiverId <= 0) {
        throw new Error("Invalid receiver");
      }

      if (receiverId === Number(userId)) {
        throw new Error("Cannot message yourself");
      }

      if (!content && !attachmentId) {
        throw new Error("Message is empty");
      }

      if (content.length > 10000) {
        throw new Error("Message is too long");
      }

      const receiver = await pool.query(
        "SELECT id FROM users WHERE id = $1",
        [receiverId]
      );

      if (!receiver.rows.length) {
        throw new Error("Receiver not found");
      }

      if (attachmentId) {
        const file = await pool.query(
          `SELECT id FROM files
           WHERE id = $1
           AND sender_id = $2
           AND receiver_id = $3`,
          [attachmentId, userId, receiverId]
        );

        if (!file.rows.length) {
          throw new Error("Attachment not found");
        }
      }

      const result = await pool.query(
        `INSERT INTO messages
         (sender_id, receiver_id, content, attachment_id)
         VALUES ($1, $2, $3, $4)
         RETURNING id, sender_id, receiver_id, content,
                   attachment_id, created_at`,
        [userId, receiverId, content, attachmentId]
      );

      const message = result.rows[0];

      io.to(`user:${userId}`)
        .to(`user:${receiverId}`)
        .emit("new_message", message);

      if (typeof callback === "function") {
        callback({ ok: true, message });
      }
    } catch (error) {
      console.error("send_message error:", error.message);

      if (typeof callback === "function") {
        callback({ ok: false, error: error.message });
      }

      socket.emit("message_error", {
        error: error.message
      });
    }
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", userId);
  });
});

// Обработка ошибок загрузки и запросов
app.use((error, req, res, next) => {
  console.error("Server error:", error);

  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      error: error.code === "LIMIT_FILE_SIZE"
        ? "Максимальный размер файла 15 МБ"
        : "Ошибка загрузки файла"
    });
  }

  if (error.message === "File type not allowed") {
    return res.status(400).json({ error: error.message });
  }

  res.status(500).json({
    error: "Internal server error"
  });
});

// Создание таблиц и запуск
async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx
    ON users (LOWER(username))
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS files (
      id BIGSERIAL PRIMARY KEY,
      sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size BIGINT NOT NULL,
      data BYTEA NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL DEFAULT '',
      attachment_id BIGINT REFERENCES files(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS attachment_id BIGINT
    REFERENCES files(id) ON DELETE SET NULL
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS messages_conversation_idx
    ON messages (sender_id, receiver_id, created_at)
  `);

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Fam Messenger running on port ${PORT}`);
  });
}

start().catch(error => {
  console.error("Startup failed:", error);
  process.exit(1);
});
