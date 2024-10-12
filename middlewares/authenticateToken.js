import jwt from "jsonwebtoken";
import { User } from "../models/usersModel.js";
import "dotenv/config";

const { ACCESS_SECRET_KEY } = process.env;

const authenticateToken = async (req, res, next) => {
  const { authorization = "" } = req.headers;
  const [bearer, token] = authorization.split(" ");

  if (bearer !== "Bearer") {
    next(res.status(401).json({ message: "Not authorized" }));
  }

  try {
    const { id } = jwt.verify(token, ACCESS_SECRET_KEY);
    const user = await User.findById(id);
    console.log(user);
    if (!user) {
      next(res.status(401).json({ message: "Not authorized" }));
    }

    // if (!user || user.token !== token || !user.token) {
    //   next(res.status(401).json({ message: "Not authorized2" }));
    // }

    req.user = user;
    next();
  } catch (error) {
    next(res.status(401).json({ message: "Not authorized" }));
  }
};

export { authenticateToken };
