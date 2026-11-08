
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const helmet = require("helmet");
const multer = require("multer");

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET || !DATABASE_URL) {
  console.error("Missing JWT_SECRET or DATABASE_URL");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : undefined
});

const io = new Server(server, {
  cors: { origin: true, credentials: true },
  maxHttpBufferSize: 1e6
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "2mb" }));

// ---------------- DATABASE ----------------

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(40) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS files (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size BIGINT NOT NULL,
      data BYTEA NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS attachment_id INTEGER
    REFERENCES files(id) ON DELETE SET NULL
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS messages_chat_idx
    ON messages(sender_id, receiver_id, created_at)
  `);

  console.log("Database initialized");
}

// ---------------- AUTH ----------------

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
    return res.status(401).json({ error: "Требуется авторизация" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Недействительный токен" });
  }
}

// ---------------- HEALTH ----------------

app.get("/health", (req, res) => {
  res.json({ status: "ok", app: "Fam Messenger" });
});

// ---------------- REGISTER ----------------

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_]{3,40}$/.test(username)) {
      return res.status(400).json({
        error: "Имя: 3–40 символов, латинские буквы, цифры и _"
      });
    }

    if (password.length < 8 || password.length > 100) {
      return res.status(400).json({
        error: "Пароль должен содержать от 8 до 100 символов"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, password)
       VALUES ($1, $2)
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
      return res.status(409).json({ error: "Имя уже занято" });
    }

    console.error(error);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

// ---------------- LOGIN ----------------

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
      return res.status(401).json({
        error: "Неверное имя пользователя или пароль"
      });
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

// ---------------- CURRENT USER ----------------

app.get("/api/me", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT id, username, created_at FROM users WHERE id = $1",
    [req.user.id]
  );

  if (!result.rows[0]) {
    return res.status(404).json({ error: "Пользователь не найден" });
  }

  res.json(result.rows[0]);
});

// ---------------- USERS ----------------

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
    res.status(500).json({ error: "Ошибка загрузки пользователей" });
  }
});

// ---------------- FILE UPLOAD ----------------

const allowedMimeTypes = new Set([
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "image/heic",
  "image/heif",
  "application/pdf",
  "text/plain",
  "text/csv",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.ms-powerpoint",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation"
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 15 * 1024 * 1024,
    files: 1
  },
  fileFilter: (req, file, callback) => {
    if (!allowedMimeTypes.has(file.mimetype)) {
      return callback(new Error("Этот тип файла не поддерживается"));
    }

    callback(null, true);
  }
});

app.post("/api/upload", auth, (req, res) => {
  upload.single("file")(req, res, async (uploadError) => {
    if (uploadError) {
      return res.status(400).json({
        error: uploadError.code === "LIMIT_FILE_SIZE"
          ? "Максимальный размер файла — 15 МБ"
          : uploadError.message
      });
    }

    try {
      const receiverId = Number(req.body.receiverId);

      if (!Number.isInteger(receiverId) || receiverId <= 0) {
        return res.status(400).json({ error: "Некорректный получатель" });
      }

      if (!req.file) {
        return res.status(400).json({ error: "Файл не выбран" });
      }

      const receiver = await pool.query(
        "SELECT id FROM users WHERE id = $1",
        [receiverId]
      );

      if (!receiver.rows.length) {
        return res.status(404).json({ error: "Получатель не найден" });
      }

      const safeName = req.file.originalname
        .replace(/[\\/\0]/g, "_")
        .slice(0, 200);

      const result = await pool.query(
        `INSERT INTO files
          (sender_id, receiver_id, original_name, mime_type, file_size, data)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, original_name, mime_type, file_size`,
        [
          req.user.id,
          receiverId,
          safeName,
          req.file.mimetype,
          req.file.size,
          req.file.buffer
        ]
      );

      const file = result.rows[0];

      res.json({
        success: true,
        file: {
          id: file.id,
          name: file.original_name,
          type: file.mime_type,
          size: Number(file.file_size),
          url: `/api/files/${file.id}`
        }
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Не удалось сохранить файл" });
    }
  });
});

// ---------------- FILE DOWNLOAD ----------------

app.get("/api/files/:id", auth, async (req, res) => {
  try {
    const fileId = Number(req.params.id);

    if (!Number.isInteger(fileId)) {
      return res.status(400).json({ error: "Некорректный ID файла" });
    }

    const result = await pool.query(
      `SELECT id, sender_id, receiver_id, original_name,
              mime_type, file_size, data
       FROM files
       WHERE id = $1`,
      [fileId]
    );

    const file = result.rows[0];

    if (!file) {
      return res.status(404).json({ error: "Файл не найден" });
    }

    if (
      file.sender_id !== req.user.id &&
      file.receiver_id !== req.user.id
    ) {
      return res.status(403).json({ error: "Нет доступа к файлу" });
    }

    const safeName = file.original_name.replace(/["\r\n]/g, "_");

    res.setHeader("Content-Type", file.mime_type);
    res.setHeader("Content-Length", file.file_size);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename*=UTF-8''${encodeURIComponent(safeName)}`
    );
    res.setHeader("X-Content-Type-Options", "nosniff");

    res.send(file.data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Ошибка скачивания" });
  }
});

// ---------------- CHAT HISTORY ----------------

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
         f.original_name AS attachment_name,
         f.mime_type AS attachment_type,
         f.file_size AS attachment_size
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

// ---------------- SOCKET AUTH ----------------

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      return next(new Error("Нет токена"));
    }

    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error("Недействительная авторизация"));
  }
});

// ---------------- SOCKET CONNECTION ----------------

io.on("connection", (socket) => {
  const userId = socket.user.id;

  socket.join(`user:${userId}`);

  console.log("Connected:", userId);

  socket.on("send_message", async (data = {}, callback) => {
    try {
      const receiverId = Number(data.receiverId ?? data.receiver_id);
      const content = String(data.content || "").slice(0, 5000);
      const attachmentId = data.attachmentId
        ? Number(data.attachmentId)
        : null;

      if (!Number.isInteger(receiverId) || receiverId <= 0) {
        throw new Error("Некорректный получатель");
      }

      if (!content.trim() && !attachmentId) {
        throw new Error("Пустое сообщение");
      }

      if (attachmentId) {
        const file = await pool.query(
          `SELECT id FROM files
           WHERE id = $1 AND sender_id = $2 AND receiver_id = $3`,
          [attachmentId, userId, receiverId]
        );

        if (!file.rows.length) {
          throw new Error("Вложение не найдено или недоступно");
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

      if (attachmentId) {
        const file = await pool.query(
          `SELECT original_name, mime_type, file_size
           FROM files WHERE id = $1`,
          [attachmentId]
        );

        const info = file.rows[0];

        message.attachment_name = info.original_name;
        message.attachment_type = info.mime_type;
        message.attachment_size = Number(info.file_size);
      }

      io.to(`user:${receiverId}`).emit("new_message", message);
      socket.emit("new_message", message);

      if (typeof callback === "function") {
        callback({ success: true, message });
      }
    } catch (error) {
      if (typeof callback === "function") {
        callback({ success: false, error: error.message });
      }
    }
  });

  socket.on("disconnect", () => {
    console.log("Disconnected:", userId);
  });
});

// ---------------- ERRORS ----------------

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Внутренняя ошибка сервера" });
});

// ---------------- START ----------------

initDatabase()
  .then(() => {
    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Fam Messenger running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database startup failed:", error);
    process.exit(1);
  });
