import jwt from "jsonwebtoken";
import { User } from "../models/usersModel.js";
import { Session } from "../models/sessionModel.js";
import "dotenv/config";

const { ACCESS_SECRET_KEY, REFRESH_SECRET_KEY } = process.env;

const authenticateAccessToken = async (req, res, next) => {
  const { authorization = "" } = req.headers;
  const [bearer, token] = authorization.split(" ");

  if (bearer !== "Bearer") {
    next(res.status(401).json({ message: "Not authorized1" }));
  }

  try {
    const { uid, sid } = jwt.verify(token, ACCESS_SECRET_KEY);
    console.log(sid, uid);
    const session = await Session.findById(sid);
    if (!session) {
      next(res.status(404).json({ message: "Invalid session" }));
    }

    const user = await User.findById(uid);
    if (!user) {
      next(res.status(404).json({ message: "Invalid user" }));
    }

    // if (!user || user.token !== token || !user.token) {
    //   next(res.status(401).json({ message: "Not authorized2" }));
    // }

    req.user = user;
    req.session = session;
    next();
  } catch (error) {
    console.log(error);
    next(res.status(401).json({ message: "Not authorized3" }));
  }
};

const authenticateRefreshToken = async (req, res, next) => {
  const { authorization = "" } = req.headers;
  const [bearer, token] = authorization.split(" ");

  if (bearer !== "Bearer") {
    next(res.status(401).json({ message: "Not authorized1" }));
  }

  try {
    const { sid, uid } = jwt.verify(token, REFRESH_SECRET_KEY);
    console.log(sid, uid);
    const session = await Session.findById(sid);
    if (!session) {
      next(res.status(404).json({ message: "Invalid session" }));
    }

    const user = await User.findById(uid);
    if (!user) {
      next(res.status(404).json({ message: "Invalid user" }));
    }

    // if (!user || user.token !== token || !user.token) {
    //   next(res.status(401).json({ message: "Not authorized2" }));
    // }

    req.session = session;
    next();
  } catch (error) {
    console.log(error);
    next(res.status(401).json({ message: "Not authorized3" }));
  }
};

export { authenticateAccessToken, authenticateRefreshToken };
