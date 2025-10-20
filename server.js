const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const path = require("path");
const bodyParser = require("body-parser");
const flash = require("connect-flash");
const nodemailer = require("nodemailer");
require('dotenv').config();

function formatDateTime(timestamp) {
  const date = new Date(timestamp);
  const now = new Date();

  const isToday = date.toDateString() === now.toDateString();

  const yesterday = new Date();
  yesterday.setDate(now.getDate() - 1);
  const isYesterday = date.toDateString() === yesterday.toDateString();

  const hours = date.getHours() % 12 || 12;
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const ampm = date.getHours() >= 12 ? "PM" : "AM";
  const time = `${hours}:${minutes} ${ampm}`;

  if (isToday) return `Today ${time}`;
  if (isYesterday) return `Yesterday ${time}`;

  const options = { month: "short", day: "numeric" }; 
  return `${date.toLocaleDateString("en-US", options)} ${time}`;
}

function checkAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}


const app = express();
const port = 3000;

const MySQLStore = require('express-mysql-session')(session);

const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

app.use(session({
  key: 'chatapp_session',
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
}));


const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect((err) => {
  if (err) throw err;
  console.log("✅ MySQL Connected!");
});


app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(flash());

app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  next();
});


app.get("/", (req, res) => {
  if (req.session.user) {
    const sql = `
      SELECT messages.*, users.username AS sender
      FROM messages
      JOIN users ON messages.sender_id = users.id
      WHERE receiver_id IS NULL
      ORDER BY messages.created_at DESC
    `;
    db.query(sql, (err, results) => {
      if (err) throw err;
      const formattedMessages = results.map(m => ({
        ...m,
        formatted_time: formatDateTime(m.created_at)
      }));
      res.render("home", { user: req.session.user, messages: formattedMessages });
    });
  } else {
    db.query("SELECT COUNT(*) AS totalUsers FROM users", (err, results) => {
      if (err) throw err;
      const totalUsers = results[0].totalUsers;
      res.render("landing", { totalUsers });
    });
  }
});





app.get("/signup",  (req, res) => res.render("signup"));

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    req.flash("error_msg", "All fields are required");
    return res.redirect("/signup");
  }

  db.query("SELECT * FROM users WHERE username = ? OR email = ?", [username, email], async (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      req.flash("error_msg", "Username or email already exists");
      return res.redirect("/signup");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000);

    const sql = `
      INSERT INTO unauth_users (username, email, password, otp)
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE otp = VALUES(otp)
    `;
    db.query(sql, [username, email, hashedPassword, otp], async (err2) => {
      if (err2) {
        console.error(err2);
        req.flash("error_msg", "Something went wrong. Please try again.");
        return res.redirect("/signup");
      }

      const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "ChatApp OTP Verification",
        text: `Hello ${username},\n\nYour OTP is: ${otp}\n\nPlease enter this OTP to verify your account.`
      };

      try {
        await transporter.sendMail(mailOptions);
        req.flash("success_msg", "OTP sent! Please check your email to verify your account.");
        res.redirect(`/verify?email=${encodeURIComponent(email)}`);
      } catch (mailErr) {
        console.error(mailErr);
        req.flash("error_msg", "Failed to send OTP. Try again later.");
        return res.redirect("/signup");
      }
    });
  });
});



app.get("/verify", (req, res) => {
  const { email } = req.query;
  res.render("verify", { email, error_msg: req.flash("error_msg") });
});

app.post("/verify", (req, res) => {
  const { email, otp } = req.body;

  db.query("SELECT * FROM unauth_users WHERE email = ?", [email], (err, results) => {
    if (err) throw err;

    if (results.length === 0) {
      req.flash("error_msg", "No pending signup found. Please sign up first.");
      return res.redirect("/signup");
    }

    const tempUser = results[0];

    if (String(tempUser.otp) !== String(otp).trim()) {
      req.flash("error_msg", "Incorrect OTP. Please try again.");
      return res.redirect(`/verify?email=${encodeURIComponent(email)}`);
    }


    db.query(
      "INSERT INTO users (username, email, password, is_verified) VALUES (?, ?, ?, 1)",
      [tempUser.username, tempUser.email, tempUser.password],
      (err2, result) => {
        if (err2) {
          console.error(err2);
          req.flash("error_msg", "Something went wrong. Please try again.");
          return res.redirect("/signup");
        }


        db.query("DELETE FROM unauth_users WHERE email = ?", [email], (err3) => {
          if (err3) console.error("Failed to delete from unauth_users:", err3);


          db.query("SELECT * FROM users WHERE email = ?", [email], (err4, userResults) => {
            if (err4 || userResults.length === 0) {
              req.flash("success_msg", "Account verified! Please login.");
              return res.redirect("/login");
            }

            req.session.user = userResults[0]; // Set session
            req.flash("success_msg", `Welcome, ${userResults[0].username}!`);
            res.redirect("/"); // Redirect to home page directly
          });
        });
      }
    );
  });
});



app.post("/resend-otp", (req, res) => {
  const { email } = req.body;

  db.query("SELECT * FROM unauth_users WHERE email = ?", [email], async (err, results) => {
    if (err) throw err;

    if (results.length === 0) {
      req.flash("error_msg", "No pending signup found. Please sign up first.");
      return res.redirect("/signup");
    }

    const tempUser = results[0];
    const newOtp = Math.floor(100000 + Math.random() * 900000);


    db.query("UPDATE unauth_users SET otp = ? WHERE email = ?", [newOtp, email], async (err2) => {
      if (err2) throw err2;


      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
  user: process.env.EMAIL_USER,
  pass: process.env.EMAIL_PASS
}

      });

      const mailOptions = {
        from: "vijethdharmaprakash@gmail.com",
        to: email,
        subject: "ChatApp OTP Verification",
        text: `Hello ${tempUser.username},\n\nYour new OTP is: ${newOtp}\n\nPlease enter this OTP to verify your account.`
      };

      try {
        await transporter.sendMail(mailOptions);
        req.flash("success_msg", "OTP resent! Please check your email.");
        res.redirect(`/verify?email=${encodeURIComponent(email)}`);
      } catch (mailErr) {
        console.error(mailErr);
        req.flash("error_msg", "Failed to resend OTP. Try again later.");
        res.redirect("/signup");
      }
    });
  });
});






app.get("/login", (req, res) => res.render("login"));

app.post("/login", (req, res) => {
  const { username, password } = req.body;


  if (!username || !password) {
    req.flash("error_msg", "Both username and password are required.");
    return res.redirect("/login");
  }


  db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
    if (err) {
      console.error(err);
      req.flash("error_msg", "Something went wrong. Please try again.");
      return res.redirect("/login");
    }

    if (results.length === 0) {
      req.flash("error_msg", "User not found. Please create an account.");
      return res.redirect("/signup");
    }

    const user = results[0];


    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      req.flash("error_msg", "Invalid password. Please try again.");
      return res.redirect("/login");
    }


    if (!user.is_verified) {
      req.flash("error_msg", "Please verify your email before logging in.");
      return res.redirect("/login");
    }


    req.session.user = user;
    req.flash("success_msg", `Welcome back, ${user.username}!`);
    res.redirect("/");
  });
});




app.post("/send", checkAuth, (req, res) => {
  const { to, message } = req.body;


  if (!to || !message) return res.send("Recipient and message cannot be empty.");
  if (message.length > 500) return res.send("Message cannot exceed 500 characters.");

  db.query("SELECT id FROM users WHERE username = ?", [to], (err, result) => {
    if (err) throw err;
    if (result.length === 0) return res.send("Recipient not found");

    const receiverId = result[0].id;
    db.query(
      "INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
      [req.session.user.id, receiverId, message],
      (err) => {
        if (err) throw err;
        res.redirect("/");
      }
    );
  });
});



app.post("/post", checkAuth, (req, res) => {
  const { message } = req.body;

  if (!message || message.trim() === "") return res.send("Message cannot be empty.");
  if (message.length > 500) return res.send("Message cannot exceed 500 characters.");

  db.query("INSERT INTO messages (sender_id, message) VALUES (?, ?)", [req.session.user.id, message], (err) => {
    if (err) throw err;
    res.redirect("/");
  });
});



app.get("/mymessages", checkAuth, (req, res) => {
  const userId = req.session.user.id;


  const usersSql = `
    SELECT DISTINCT u.id, u.username
    FROM users u
    JOIN messages m ON (u.id = m.sender_id OR u.id = m.receiver_id)
    WHERE (m.sender_id = ? OR m.receiver_id = ?) AND u.id != ?
  `;
  
  db.query(usersSql, [userId, userId, userId], (err, users) => {
    if (err) throw err;


    res.render("mymessages", { user: req.session.user, users, messages: [], activeUser: null });
  });
});



app.get("/mymessages/:chatWithId", checkAuth, (req, res) => {
  const userId = req.session.user.id;
  const chatWithId = req.params.chatWithId;

  const usersSql = `
    SELECT DISTINCT u.id, u.username
    FROM users u
    JOIN messages m ON (u.id = m.sender_id OR u.id = m.receiver_id)
    WHERE (m.sender_id = ? OR m.receiver_id = ?) AND u.id != ?
  `;
  
  db.query(usersSql, [userId, userId, userId], (err, users) => {
    if (err) throw err;

    const messagesSql = `
      SELECT m.*, s.username AS senderName, r.username AS receiverName
      FROM messages m
      JOIN users s ON m.sender_id = s.id
      JOIN users r ON m.receiver_id = r.id
      WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
      ORDER BY m.created_at ASC
    `;

    db.query(messagesSql, [userId, chatWithId, chatWithId, userId], (err2, messages) => {
      if (err2) throw err2;

      const formattedMessages = messages.map(m => ({
        ...m,
        formatted_time: formatDateTime(m.created_at)
      }));

      const activeUser = users.find(u => u.id == chatWithId);

      res.render("mymessages", { user: req.session.user, users, messages: formattedMessages, activeUser });
    });
  });
});


app.post("/mymessages/:chatWithId/send", checkAuth, (req, res) => {
  const { chatWithId } = req.params;
  const { message } = req.body;
  const senderId = req.session.user.id;

  if (!message || message.trim() === "") return res.send("Message cannot be empty.");
  if (message.length > 500) return res.send("Message cannot exceed 500 characters.");

  db.query(
    "INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
    [senderId, chatWithId, message],
    (err) => {
      if (err) throw err;
      res.redirect(`/mymessages/${chatWithId}`);
    }
  );
});



app.get("/logout",checkAuth,  (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      return res.send("Error logging out");
    }
    res.redirect("/login");
  });
});


app.post("/mymessages/send", checkAuth, (req, res) => {
  const { toUsername, message } = req.body;
  const senderId = req.session.user.id;

  if (!toUsername || !message || message.trim() === "") {
    return res.send("Recipient and message are required.");
  }

  if (message.length > 500) return res.send("Message cannot exceed 500 characters.");


  db.query("SELECT id FROM users WHERE username = ?", [toUsername], (err, result) => {
    if (err) throw err;
    if (result.length === 0) return res.send("Recipient not found.");

    const receiverId = result[0].id;

    db.query(
      "INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
      [senderId, receiverId, message],
      (err2) => {
        if (err2) throw err2;

        res.redirect(`/mymessages/${receiverId}`);
      }
    );
  });
});



app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));
