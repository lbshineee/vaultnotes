const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");

const { db } = require("./db");
const { requireAuth } = require("./auth");

const app = express();
app.use(express.json());

app.use(
  session({
    secret: "dev-insecure-secret", // v1 intentionally weak; fix later via env var
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // local dev only
    },
  })
);

app.get("/health", (req, res) => res.json({ ok: true }));

/**
 * AUTH
 */

// Register: { username, password }
app.post("/register", (req, res) => {
  const { username, password } = req.body ?? {};
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "username and password required" });
  }
  if (username.length < 3 || password.length < 8) {
    return res.status(400).json({ error: "weak username/password" });
  }

  const password_hash = bcrypt.hashSync(password, 12);

  try {
    const stmt = db.prepare(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    );
    const info = stmt.run(username, password_hash);

    // auto-login after register
    req.session.userId = info.lastInsertRowid;
    req.session.username = username;

    return res.status(201).json({ ok: true, userId: info.lastInsertRowid });
  } catch (e) {
    // UNIQUE constraint likely
    return res.status(409).json({ error: "username already exists" });
  }
});

// Login: { username, password }
app.post("/login", (req, res) => {
  const { username, password } = req.body ?? {};
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "username and password required" });
  }

  const row = db
    .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
    .get(username);

  if (!row) return res.status(401).json({ error: "invalid credentials" });

  const ok = bcrypt.compareSync(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });

  req.session.userId = row.id;
  req.session.username = row.username;

  return res.json({ ok: true });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

/**
 * NOTES (owner-scoped)
 */

// Create note: { title, content }
app.post("/notes", requireAuth, (req, res) => {
  const { title, content } = req.body ?? {};
  if (typeof title !== "string" || typeof content !== "string") {
    return res.status(400).json({ error: "title and content required" });
  }

  const stmt = db.prepare(
    "INSERT INTO notes (owner_user_id, title, content) VALUES (?, ?, ?)"
  );
  const info = stmt.run(req.session.userId, title, content);

  return res.status(201).json({ ok: true, noteId: info.lastInsertRowid });
});

// List my notes
app.get("/notes", requireAuth, (req, res) => {
  const rows = db
    .prepare(
      "SELECT id, title, content, created_at, updated_at FROM notes WHERE owner_user_id = ? ORDER BY id DESC"
    )
    .all(req.session.userId);

  return res.json({ ok: true, notes: rows });
});

// Get one note (owner-scoped)
app.get("/notes/:id", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "bad id" });

  const row = db
    .prepare(
      "SELECT id, title, content, owner_user_id FROM notes WHERE id = ?"
    )
    .get(id);

  if (!row) return res.status(404).json({ error: "not found" });
  if (row.owner_user_id !== req.session.userId)
    return res.status(403).json({ error: "forbidden" });

  return res.json({ ok: true, note: { id: row.id, title: row.title, content: row.content } });
});

// Update note (owner-scoped)
app.put("/notes/:id", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const { title, content } = req.body ?? {};
  if (!Number.isInteger(id)) return res.status(400).json({ error: "bad id" });
  if (typeof title !== "string" || typeof content !== "string") {
    return res.status(400).json({ error: "title and content required" });
  }

  const row = db
    .prepare("SELECT owner_user_id FROM notes WHERE id = ?")
    .get(id);

  if (!row) return res.status(404).json({ error: "not found" });
  if (row.owner_user_id !== req.session.userId)
    return res.status(403).json({ error: "forbidden" });

  db.prepare(
    "UPDATE notes SET title = ?, content = ?, updated_at = datetime('now') WHERE id = ?"
  ).run(title, content, id);

  return res.json({ ok: true });
});

// Delete note (owner-scoped)
app.delete("/notes/:id", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "bad id" });

  const row = db
    .prepare("SELECT owner_user_id FROM notes WHERE id = ?")
    .get(id);

  if (!row) return res.status(404).json({ error: "not found" });
  if (row.owner_user_id !== req.session.userId)
    return res.status(403).json({ error: "forbidden" });

  db.prepare("DELETE FROM notes WHERE id = ?").run(id);

  return res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API listening on http://localhost:${PORT}`));

