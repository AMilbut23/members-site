const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "change-this-secret", // use env variable in real apps
    resave: false,
    saveUninitialized: false,
  })
);

// Set EJS views
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Make user available in templates
app.use((req, res, next) => {
  res.locals.currentUser = req.session.username || null;
  res.locals.isAdmin = req.session.isAdmin || false;
  next();
});

// Auth guard
function requireLogin(req, res, next) {
  if (!req.session.username) {
    return res.redirect("/login");
  }
  next();
}

// Admin helper
function requireAdmin(req, res, next) {
  if (!req.session.username || !req.session.isAdmin) {
    return res.status(403).send("Access denied. Admins only.");
  }
  next();
}

// Routes
app.get("/", (req, res) => {
  res.render("index");
});

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render("register", { error: "Username and password required." });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)",
      [username, passwordHash],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE")) {
            return res.render("register", { error: "Username already taken." });
          }
          console.error(err);
          return res.render("register", { error: "Something went wrong." });
        }
        res.redirect("/login");
      }
    );
  } catch (e) {
    console.error(e);
    res.render("register", { error: "Something went wrong." });
  }
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err) {
        console.error(err);
        return res.render("login", { error: "Something went wrong." });
      }
      if (!user) {
        return res.render("login", { error: "Invalid username or password." });
      }

      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        return res.render("login", { error: "Invalid username or password." });
      }

      req.session.username = user.username;
      // NEW: store admin flag in session
      req.session.isAdmin = user.is_admin === 1;

      res.redirect("/member");
    }
  );
});

app.get("/member", requireLogin, (req, res) => {
  res.render("member");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

app.get("/admin", requireAdmin, (req, res) => {
  res.send(`
    <h1>Admin Area</h1>
    <p>Welcome, ${req.session.username}. You are an admin.</p>
    <p><a href="/member">Back to Members Area</a></p>
  `);
});

