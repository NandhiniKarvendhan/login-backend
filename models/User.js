const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: false }, // Password optional for Google Sign-In
  name: { type: String },
});

module.exports = mongoose.model("User", userSchema);
