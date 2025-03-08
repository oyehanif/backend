const mongoose = require("mongoose");
const crypto = require("crypto");
const uuidv1 = require("uuid/v1");

const userSchema = new mongoose.Schema(
  {
    Access: {
      type: String,
      default: "Active",
    },
    KycStatus: {
      type: String,
      default: "unVerified",
    },
    mobile: { type: Number },
    name: {
      type: String,
      required: true,
    },
    aadhar_number: {
      type: String,
      default:'NA',
      required: true,
    },
    remark: {
      type: String,
      required: true,
      default:"User"
    },
    email: {
      type: String,
      trim: true,
      required: true,
      unique: 32,
    },
    hashed_password: {
      type: String,
      required: true,
    },
    salt: String,
    role: {
      type: Number,
      default: 0,
    },
    brutecount: {
      type: Number,
      default: 0,
    },
    bruteblocktime: {
      type: Number,
      default: 0,
    },
    enabledtwofactorauth: { type: Boolean, default: false },
    secret: {
      type: String,
    },
    otpauth_url: {
      type: String,
    },
    ticket_history: [
      {
        ticket_id: { type: String },
        ticket_raised_by: { type: String },
        ticket_type: { type: String },
        ticket_query: { type: String },
        ticket_category: { type: String },
        ticket_subcategory: { type: String },
        
        flat: { type: String },
        area: { type: String },
        landmark: { type: String },
        pincode: { type: String },
        town: { type: String },
        ac_brand: { type: String },
        model_number: { type: String },
        date_of_purchase: { type: String },

        ticket_remark: { type: String },
        ticket_image_one:{ type: String },
        ticket_image_two:{ type: String },
        ticket_video_one:{ type: String },
        ticket_video_two:{ type: String },
        ticket_assigned_to: { type: String, default: 'NA' },
        timestamp: { type: Date, default: new Date().getTime() },
        status: { type: String, default: "Created" },
      },
    ],
  },
  { timestamps: true }
);

userSchema
  .virtual("password")
  .set(function (password) {
    this._password = password;
    this.salt = uuidv1();

    this.hashed_password = this.encryptPassword(password);
  })
  .get(function () {
    return this._password;
  });

userSchema.methods = {
  authenticate: function (plainText) {
    return this.encryptPassword(plainText) === this.hashed_password;
  },
  encryptPassword: function (password) {
    if (!password) return "";
    try {
      return crypto
        .createHmac("sha1", this.salt)
        .update(password)
        .digest("hex");
    } catch (err) {
      return "";
    }
  },
};

module.exports = mongoose.model("userpool", userSchema);
