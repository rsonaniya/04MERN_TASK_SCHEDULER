import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please tell us your name"],
    minLength: [3, "A name must be at least 3 characters long"],
  },
  email: {
    type: String,
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, "email must be in xyz@company format"],
  },
  photoUrl: String,
  password: {
    type: String,
    minLength: [8, "Password must be at least characters long"],
    required: [true, "Password is required"],
  },
  resetTokenExpiresIn: Date,
  passwordResetToken: String,
});

userSchema.pre("save", async function (next) {
  this.password = await bcrypt.hash(this.password, 12);
});

userSchema.methods.isCorrectPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.generateResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.resetTokenExpiresIn = Date.now() + 60 * 60 * 1000;

  return resetToken;
};

const User = new mongoose.model("User", userSchema);

export default User;
