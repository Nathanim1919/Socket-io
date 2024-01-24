const express = require("express");
const app = express();
const cors = require("cors");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const connectDB = require("./db/index");
const userRouter = require("./routes/auth/user.routes");
const passport = require("passport");
require("dotenv").config();

const startServer = () => {
  app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
  });
};

// Middlewares setup to parse incoming requests and cookies, and also to handle CORS
app.use(cookieParser());
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
    methods: ["GET,HEAD,PUT,PATCH,POST,DELETE"],
  })
);

// Move session middleware above passport middleware
app.use(
  session({
    secret: process.env.EXPRESS_SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use("/api/v1/users", userRouter);

// MongoDB connection
connectDB().then(startServer);