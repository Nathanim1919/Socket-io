const express = require("express");
const { cookie } = require("express-validator");
const app = express();
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const connectDB = require("./db/index");

require("dotenv").config();

const startServer = () => {
  app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
  });
};

// middlewares setup to parse incoming requests and cookies, and also to handle CORS
app.use(cookieParser());
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
    methods: ["GET,HEAD,PUT,PATCH,POST,DELETE"],
  })
);

// mongoDB connection
connectDB().then(startServer);