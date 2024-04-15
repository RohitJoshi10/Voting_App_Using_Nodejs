const mongoose = require("mongoose");
require("dotenv").config();

// Define the MongoDB connection URL
const mongoURL = process.env.MONGODB_URL_LOCAL; // "mongodb://localhost:27017/hotels"; // Replace 'mydatabase' with your database name. mongodb://localhost27017/mydatabase
// const mongoURL = process.env.MONGODB_URL;

// Set up MongoDB connection
mongoose.connect(mongoURL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
// mongoose.connect(mongoURL);

// Get the default connection
// Mongoose maintain a default connection object representing the MongoDB connection
const db = mongoose.connection;

// Define event listeners for database connection
db.on("connected", () => {
  console.log("Connected to MongoDB server");
});

db.on("error", (error) => {
  console.log("MongoDB connection error:", error);
});

// Export the database connection
module.exports = db;
