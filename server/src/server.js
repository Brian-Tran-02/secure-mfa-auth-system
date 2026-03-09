const express = require("express");
const cors = require("cors");
const session = require("express-session");
require("dotenv").config();

require("./db");

const authRoutes = require("./routes/auth");

const app = express();

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  }),
);

app.use(express.json());

app.use(
  session({
    secret: "change_this_to_a_real_secret_later",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true,
      maxAge: 1000 * 60 * 60,
    },
  }),
);

app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
  res.send("Auth server is running");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
