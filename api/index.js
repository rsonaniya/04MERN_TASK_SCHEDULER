import express from "express";
import { config } from "dotenv";
import connectToMongo from "./utils/connectToMongo.js";
import authRouter from "./routes/authRoute.js";
import cookieParser from "cookie-parser";

config();
const app = express();

const PORT = process.env.PORT || 5000;
connectToMongo();

app.use(express.json());

app.use(cookieParser());

app.use("/api/v1/auth", authRouter);

app.use((err, req, res, next) => {
  const errorCode = err.statusCode || 500;
  const errorMessage = err.errorMessage || "Something went wrong";
  if (err) {
    return res.status(errorCode).json({
      message: errorMessage,
    });
  }
});

app.listen(PORT, () => console.log(`app started at port ${PORT}`));
