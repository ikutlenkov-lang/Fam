const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(helmet());
app.use(express.json());
app.use(express.static("public"));

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
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
}

function authenticate(token) {
  if (!JWT_SECRET) throw new Error("Server not configured");
  return jwt.verify(token, JWT_SECRET);
}

app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (
      typeof username !== "string" ||
      !/^[a-zA-Z0-9_]{3,24}$/.test(username) ||
      typeof password !== "string" ||
      password.length < 10 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: "Invalid username or password"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, password)
       VALUES ($1, $2)
       RETURNING id, username`,
      [username.toLowerCase(), hash]
    );

    res.json({ user: result.rows[0] });
  } catch (error) {
    res.status(400).json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (typeof username !== "string" ||
        typeof password !== "string") {
      return res.status(400).json({ error: "Invalid login" });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username.toLowerCase()]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        error: "Wrong username or password"
      });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username }
    });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const user = authenticate(
      (req.headers.authorization || "").replace("Bearer ", "")
    );

    const result = await pool.query(
      "SELECT id, username FROM users WHERE id != $1",
      [user.id]
    );

    res.json(result.rows);
  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
});

io.use((socket, next) => {
  try {
    socket.user = authenticate(socket.handshake.auth.token);
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

io.on("connection", (socket) => {
  socket.join(`user:${socket.user.id}`);

  socket.on("send_message", async (data, callback) => {
    try {
      if (
        !Number.isInteger(data?.receiverId) ||
        typeof data?.content !== "string" ||
        !data.content.trim() ||
        data.content.length > 4000
      ) {
        return callback?.({ error: "Invalid message" });
      }

      const receiver = await pool.query(
        "SELECT id FROM users WHERE id = $1",
        [data.receiverId]
      );

      if (!receiver.rows.length) {
        return callback?.({ error: "User not found" });
      }

      const result = await pool.query(
        `INSERT INTO messages (sender_id, receiver_id, content)
         VALUES ($1, $2, $3)
         RETURNING *`,
        [socket.user.id, data.receiverId, data.content.trim()]
      );

      const message = result.rows[0];

      io.to(`user:${data.receiverId}`).emit(
        "new_message",
        message
      );

      socket.emit("new_message", message);
      callback?.({ success: true });
    } catch {
      callback?.({ error: "Message failed" });
    }
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "Fam Messenger online" });
});

async function start() {
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is missing");
  }

  await initializeDatabase();

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Fam Messenger running on ${PORT}`);
  });
}

start().catch(console.error);
