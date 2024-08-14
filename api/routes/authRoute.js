import express from "express";
import {
  authenticate,
  changePassword,
  forgotPassword,
  login,
  resetPassword,
  signup,
} from "../controller/authController.js";

const router = express.Router();

router.post("/sign-up", signup);
router.post("/login", login);
router.post("/change-password", authenticate, changePassword);
router.post("/forgot-password", forgotPassword);
router.patch("/reset-password/:resetToken", resetPassword);

export default router;
