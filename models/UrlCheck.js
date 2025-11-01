const mongoose = require("mongoose");

const UrlCheckSchema = new mongoose.Schema({
  url: { type: String, required: true },
  prediction: { type: String, required: true },
  confidence: { type: Number, required: true },
  checkedAt: { type: Date, default: Date.now },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
});
module.exports = mongoose.models.UrlCheck || mongoose.model("UrlCheck", UrlCheckSchema);