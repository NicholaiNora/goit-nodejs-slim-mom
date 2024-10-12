import express from "express";
import {
  loginUser,
  logoutUser,
  registerUser,
  tokenUser,
} from "../../controllers/usersControllers.js";
import { authenticateToken } from "../../middlewares/authenticateToken.js";

const router = express.Router();

router.post("/register", async (req, res, next) => {
  try {
    const result = await registerUser(req, res, next);
    return result;
  } catch (error) {
    next(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const result = await loginUser(req, res, next);
    return result;
  } catch (error) {
    next(error);
  }
});

router.post("/token", async (req, res, next) => {
  try {
    const result = tokenUser(req, res, next);
    return result;
  } catch (error) {
    next(error);
  }
});

router.get("/", authenticateToken, async (req, res, next) => {
  try {
    const { _id, email } = req.user;
    res.json({ _id, email });
  } catch (error) {
    next(error);
  }
});

router.get("/logout", authenticateToken, async (req, res, next) => {
  try {
    const result = await logoutUser(req, res, next);
    return result;
  } catch (error) {
    next(error);
  }
});

export { router };
