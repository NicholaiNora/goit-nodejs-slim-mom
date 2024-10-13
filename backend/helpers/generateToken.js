import jwt from "jsonwebtoken";
const { ACCESS_SECRET_KEY } = process.env;

const generateAccessToken = (user) => {
  return jwt.sign(user, ACCESS_SECRET_KEY, { expiresIn: "30s" });
};

export { generateAccessToken };
