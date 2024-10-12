import express from "express";
//prettier-ignore
import { loginUser, logoutUser, registerUser, tokenUser } from "../../controllers/usersControllers.js";
//prettier-ignore
import { authenticateAccessToken, authenticateRefreshToken } from "../../middlewares/authenticateToken.js";

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

router.post("/token", authenticateRefreshToken, async (req, res, next) => {
  try {
    const result = tokenUser(req, res, next);
    return result;
  } catch (error) {
    next(error);
  }
});

router.get("/", authenticateAccessToken, async (req, res, next) => {
  try {
    const { _id, email, token} = req.user;
    if (!token) {
      return res.status(401).send();
    }
    res.json({ _id, email });
  } catch (error) {
    next(error);
  }
});

router.get("/logout", authenticateAccessToken, async (req, res, next) => {
  try {
    const result = await logoutUser(req, res, next);
    return result;
  } catch (error) {
    next(error);
  }
});

export { router };
