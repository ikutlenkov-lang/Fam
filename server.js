
const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1e6
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

const calls = new Map();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(24) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER REFERENCES users(id),
      receiver_id INTEGER REFERENCES users(id),
      content VARCHAR(4000) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS messages_pair_idx
    ON messages(sender_id, receiver_id, created_at);

    CREATE INDEX IF NOT EXISTS messages_reverse_idx
    ON messages(receiver_id, sender_id, created_at);
  `);
}

function getUser(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) {
    throw new Error("Unauthorized");
  }
  return jwt.verify(header.slice(7), JWT_SECRET);
}

function createToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function sendToUser(userId, event, data) {
  io.to(`user:${userId}`).emit(event, data);
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      status: "online",
      app: "Fam Messenger",
      database: "connected"
    });
  } catch {
    res.status(503).json({
      status: "offline",
      database: "disconnected"
    });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      !/^[a-zA-Z0-9_]{3,24}$/.test(username) ||
      typeof password !== "string" ||
      password.length < 10 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: "Имя: 3–24 символа. Пароль: 10–128 символов."
      });
    }

    const normalized = username.toLowerCase();
    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users(username, password)
       VALUES($1, $2)
       RETURNING id, username`,
      [normalized, hash]
    );

    const user = result.rows[0];

    res.status(201).json({
      token: createToken(user),
      user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Это имя пользователя уже занято."
      });
    }

    console.error("Registration error:", error.message);
    res.status(500).json({ error: "Ошибка регистрации." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      username.length > 24 ||
      password.length > 128
    ) {
      return res.status(400).json({ error: "Неверные данные." });
    }

    const result = await pool.query(
      "SELECT id, username, password FROM users WHERE username = $1",
      [username.toLowerCase()]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        error: "Неверный логин или пароль."
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
    console.error("Login error:", error.message);
    res.status(500).json({ error: "Ошибка входа." });
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const auth = getUser(req);
    const result = await pool.query(
      "SELECT id, username FROM users WHERE id = $1",
      [auth.id]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "Аккаунт не найден." });
    }

    res.json(result.rows[0]);
  } catch {
    res.status(401).json({ error: "Необходим вход." });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const auth = getUser(req);
    const result = await pool.query(
      `SELECT id, username
       FROM users
       WHERE id != $1
       ORDER BY username`,
      [auth.id]
    );

    res.json(result.rows);
  } catch {
    res.status(401).json({ error: "Необходим вход." });
  }
});

app.get("/api/messages/:userId", async (req, res) => {
  try {
    const auth = getUser(req);
    const otherId = Number(req.params.userId);

    if (
      !Number.isSafeInteger(otherId) ||
      otherId <= 0 ||
      otherId === auth.id
    ) {
      return res.status(400).json({
        error: "Неверный пользователь."
      });
    }

    const result = await pool.query(
      `SELECT id, sender_id, receiver_id, content, created_at
       FROM messages
       WHERE
         (sender_id = $1 AND receiver_id = $2)
         OR
         (sender_id = $2 AND receiver_id = $1)
       ORDER BY created_at DESC
       LIMIT 100`,
      [auth.id, otherId]
    );

    res.json(result.rows.reverse());
  } catch {
    res.status(401).json({ error: "Необходим вход." });
  }
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) throw new Error("No token");

    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

io.on("connection", (socket) => {
  const userId = socket.user.id;
  socket.join(`user:${userId}`);

  let lastMessageTime = 0;
  let lastCallTime = 0;

  socket.on("send_message", async (data, callback) => {
    const reply = typeof callback === "function"
      ? callback
      : () => {};

    try {
      const now = Date.now();

      if (now - lastMessageTime < 500) {
        return reply({ error: "Подожди немного." });
      }

      const receiverId = data?.receiverId;
      const content = data?.content;

      if (
        !Number.isSafeInteger(receiverId) ||
        receiverId <= 0 ||
        receiverId === userId ||
        typeof content !== "string" ||
        !content.trim() ||
        content.length > 4000
      ) {
        return reply({ error: "Некорректное сообщение." });
      }

      const receiver = await pool.query(
        "SELECT id FROM users WHERE id = $1",
        [receiverId]
      );

      if (!receiver.rows.length) {
        return reply({ error: "Пользователь не найден." });
      }

      lastMessageTime = now;

      const result = await pool.query(
        `INSERT INTO messages(sender_id, receiver_id, content)
         VALUES($1, $2, $3)
         RETURNING id, sender_id, receiver_id, content, created_at`,
        [userId, receiverId, content.trim()]
      );

      const message = result.rows[0];

      sendToUser(userId, "new_message", message);
      sendToUser(receiverId, "new_message", message);

      reply({ success: true });
    } catch (error) {
      console.error("Message error:", error.message);
      reply({ error: "Не удалось отправить сообщение." });
    }
  });

  // START CALL
  socket.on("call:invite", async (data, callback) => {
    const reply = typeof callback === "function"
      ? callback
      : () => {};

    try {
      if (Date.now() - lastCallTime < 2000) {
        return reply({ error: "Подожди немного." });
      }

      const receiverId = Number(data?.to);
      const mode = data?.mode;

      if (
        !Number.isSafeInteger(receiverId) ||
        receiverId <= 0 ||
        receiverId === userId ||
        !["audio", "video"].includes(mode)
      ) {
        return reply({ error: "Неверные параметры звонка." });
      }

      const receiver = await pool.query(
        "SELECT id, username FROM users WHERE id = $1",
        [receiverId]
      );

      if (!receiver.rows.length) {
        return reply({ error: "Пользователь не найден." });
      }

      const callId = crypto.randomUUID();

      const call = {
        id: callId,
        callerId: userId,
        receiverId,
        mode,
        status: "ringing"
      };

      calls.set(callId, call);
      lastCallTime = Date.now();

      sendToUser(receiverId, "call:incoming", {
        callId,
        callerId: userId,
        callerName: socket.user.username,
        mode
      });

      reply({ success: true, callId });

      // Remove unanswered calls after 45 seconds.
      setTimeout(() => {
        const current = calls.get(callId);

        if (current && current.status === "ringing") {
          sendToUser(current.callerId, "call:ended", {
            callId,
            reason: "no-answer"
          });

          sendToUser(current.receiverId, "call:ended", {
            callId,
            reason: "no-answer"
          });

          calls.delete(callId);
        }
      }, 45000);
    } catch (error) {
      console.error("Call invite error:", error.message);
      reply({ error: "Не удалось начать звонок." });
    }
  });

  // ACCEPT CALL
  socket.on("call:accept", (data, callback) => {
    const reply = typeof callback === "function"
      ? callback
      : () => {};

    const call = calls.get(data?.callId);

    if (
      !call ||
      call.receiverId !== userId ||
      call.status !== "ringing"
    ) {
      return reply({ error: "Звонок уже недоступен." });
    }

    call.status = "active";

    sendToUser(call.callerId, "call:accepted", {
      callId: call.id,
      receiverId: userId
    });

    reply({ success: true });
  });

  // REJECT CALL
  socket.on("call:reject", (data) => {
    const call = calls.get(data?.callId);

    if (!call || call.receiverId !== userId) return;

    sendToUser(call.callerId, "call:rejected", {
      callId: call.id
    });

    calls.delete(call.id);
  });

  // WEBRTC SIGNALING
  socket.on("call:signal", (data) => {
    const call = calls.get(data?.callId);
    const signal = data?.signal;

    if (
      !call ||
      call.status !== "active" ||
      !signal ||
      typeof signal !== "object" ||
      !["offer", "answer", "candidate"].includes(signal.type)
    ) {
      return;
    }

    const isParticipant =
      call.callerId === userId ||
      call.receiverId === userId;

    if (!isParticipant) return;

    const otherId = call.callerId === userId
      ? call.receiverId
      : call.callerId;

    sendToUser(otherId, "call:signal", {
      callId: call.id,
      signal
    });
  });

  // END CALL
  socket.on("call:end", (data) => {
    const call = calls.get(data?.callId);

    if (!call) return;

    if (
      call.callerId !== userId &&
      call.receiverId !== userId
    ) {
      return;
    }

    const otherId = call.callerId === userId
      ? call.receiverId
      : call.callerId;

    sendToUser(otherId, "call:ended", {
      callId: call.id,
      reason: "ended"
    });

    calls.delete(call.id);
  });
});

async function start() {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error("JWT_SECRET должен содержать минимум 32 символа.");
  }

  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL не настроен.");
  }

  await initializeDatabase();

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Fam Messenger running on port ${PORT}`);
  });
}

start().catch(error => {
  console.error("Startup error:", error);
  process.exit(1);
});
