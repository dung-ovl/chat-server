const app = require("./app");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
dotenv.config({ path: "./config.env" });

// This is a global error handler middleware

process.on("uncaughtException", (err) => {
  console.log("UNCAUGHT EXCEPTION! 💥 Shutting down...");
  console.log(err.name, err.message);
  process.exit(1);
});
const http = require("http");

const server = http.createServer(app);

const DB = process.env.DBURI.replace("<PASSWORD>", process.env.DBPASSWORD);

mongoose
  .connect(DB, {})
  .then((con) => {
    console.log("DB connection successful");
  })
  .catch((err) => {
    console.log(err);
  });

const port = process.env.PORT || 3000;

server.listen(port, () => console.log(`Server is running on port ${port}`));

process.on("unhandledRejection", (err) => {
  console.log("UNHANDLED REJECTION! 💥 Shutting down...");
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});
