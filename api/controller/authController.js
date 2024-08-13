import { errorHandler } from "../utils/errorHandler.js";
import User from "../model/UserModel.js";
import jwt from "jsonwebtoken";
import sendEmail from "../utils/mail.js";

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
};

const sendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  res.cookie("jwt", token, {
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    httpOnly: true,
  });

  user.password = undefined;
  console.log(token, user);
  res.status(statusCode).json({
    status: "success",
    token,
    data: { user },
  });
};

export const authenticate = async (req, res, next) => {
  let token;
  try {
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    } else if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return next(
        errorHandler(
          404,
          "You are not logged in or you do not have a valid token to procceed further"
        )
      );
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const currentUser = await User.findById(decoded.id);

    if (!currentUser) {
      return next(
        errorHandler(401, "The user belonging to this token no longer exists")
      );
    }
    req.user = currentUser;
    next();
  } catch (error) {
    console.log(error);
    return next(error);
  }
};
export const signup = async (req, res, next) => {
  try {
    const { name, email, password, imageUrl } = req.body;

    if (!name || !email || !password) {
      return next(
        errorHandler("404", "Email, Password and Name are required fields ")
      );
    }

    const user = await User.findOne({ email });
    if (user) {
      return next(errorHandler(404, "User already exists with the same email"));
    }

    const newUser = await User.create({
      name,
      email,
      password,
      imageUrl,
    });

    sendToken(newUser, 201, res);
  } catch (error) {
    console.log(error);
    return next(error);
  }
};

export const login = async (req, res, next) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return next(errorHandler(404, "Email and password are required field"));
    }

    const foundUser = await User.findOne({ email });

    if (
      !foundUser ||
      !(await foundUser.isCorrectPassword(password, foundUser.password))
    ) {
      return next(
        errorHandler(
          404,
          "Either no user is available for given email or password is invalid"
        )
      );
    }
    sendToken(foundUser, 200, res);
  } catch (error) {
    return next(error);
  }
};

export const changePassword = async (req, res, next) => {
  try {
    const { email, password, newPassword } = req.body;
    if (!email || !password || !newPassword) {
      return next(
        errorHandler(
          404,
          "Email, current password and new password are required fields "
        )
      );
    }

    if (email !== req.user.email) {
      return next(
        errorHandler(
          401,
          "You are not authorized to change someone else's password"
        )
      );
    }

    if (!(await req.user.isCorrectPassword(password, req.user.password))) {
      return next(errorHandler(401, "Entered current password is invalid"));
    }
    const currentUser = req.user;
    currentUser.password = newPassword;
    const modifiedUser = await currentUser.save();
    sendToken(modifiedUser, 200, res);
  } catch (error) {}
};

export const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      return next(
        errorHandler(
          404,
          "A valid email is required to send the reset password link"
        )
      );
    }
    const foundUser = await User.findOne({ email });

    if (!foundUser) {
      return next(errorHandler(404, "No user found with the entered email "));
    }

    const resetToken = foundUser.generateResetPasswordToken();

    const modifiedUser = await foundUser.save();

    const resetUrl = `${req.protocol}://${req.get(
      "host"
    )}/api/v1/auth/reset-password/${resetToken}`;

    const message = `Forgot your password? Submit a reset password request to the link: ${resetUrl}`;

    await sendEmail({
      email: foundUser.email,
      subject: "Your password reset token (valid for 10 min)",
      message,
    });
  } catch (error) {
    console.log(error);
    return next(error);
  }
};
