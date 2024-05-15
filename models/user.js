const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = new mongoose.Schema({
  fisrtName: {
    type: String,
    required: [true, "Please enter your first name"],
  },
  lastName: {
    type: String,
    required: [true, "Please enter your last name"],
  },
  avatar: {
    type: String,
    default: "default.jpg",
  },
  email: {
    type: String,
    required: [true, "Please enter your email"],
    validate: {
      validator: function (email) {
        return String(email)
          .toLowerCase()
          .match(/^[a-zA-Z0-9_.+]+(?<!^[0-9]*)@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/);
      },
      message: (props) => `${props.value} is not a valid email address!`,
    },
    unique: true,
  },
  password: {
    type: String,
    required: [true, "Please enter your password"],
    minlength: 8,
    select: false,
  },

  passwordConfirm: {
    type: String,
  },
  passwordChangedAt: {
    type: Date,
  },
  passwordResetToken: {
    type: String,
  },

  passwordResetExpires: {
    type: Date,
  },

  createAt: {
    type: Date,
  },

  updatedAt: {
    type: Date,
  },
  verified: {
    type: Boolean,
    default: false,
  },

  otp: {
    type: Number,
  },

  otpExpires: {
    type: Date,
  },
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("otp")) return next();
  this.otp = await bcrypt.hash(this.otp, 12);
  next();
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

userSchema.methods.correctPassword = async function (
  candiatePassword,
  userPassword
) {
  return await bcrypt.compare(candiatePassword, userPassword);
};

userSchema.methods.correctOTP = async function (candiateOTP, userOTP) {
  return await bcrypt.compare(candiateOTP, userOTP);
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp;
  }

  return false;
};

const User = mongoose.model("User", userSchema);
module.exports = User;
