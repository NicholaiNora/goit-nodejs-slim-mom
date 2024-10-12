import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import "dotenv/config";
import { User } from "../models/usersModel.js";
//prettier-ignore
import { signinValidation, signupValidation } from "../validation/validation.js";
import { generateAccessToken } from "../helpers/generateToken.js";

const { REFRESH_SECRET_KEY } = process.env;

const registerUser = async (req, res) => {
  const { name, email, password } = req.body;

  const { error } = signupValidation.validate(req.body);
  if (error) {
    res.status(400).json({ message: error.message });
  }

  //if email is already in the database
  const user = await User.findOne({ email });
  if (user) {
    res.status(409).json({ message: "Email in use" });
  }

  const hashPassword = await bcrypt.hash(password, 10);

  await User.create({
    name,
    email,
    password: hashPassword,
  });

  res.status(201).json({ message: "Successfully registered!" });
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;

  const { error } = signinValidation.validate(req.body);
  if (error) {
    res.status(400).json({ message: error.message });
  }

  const user = await User.findOne({ email });
  if (!user) {
    res.status(409).json({ message: "Email or password is wrong" });
  }

  //bcrypt returns boolean
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    res.status(409).json({ message: "Email or password is wrong" });
  }

  const payload = { id: user._id, email: user.email };
  const accessToken = generateAccessToken(payload);
  const refreshToken = jwt.sign(payload, REFRESH_SECRET_KEY);
  console.log(refreshToken);

  await User.findByIdAndUpdate(user._id, { token: refreshToken });

  res.status(200).json({
    user: {
      email: user.email,
    },
    accessToken,
    refreshToken,
  });
};

const tokenUser = async (req, res) => {
  const { token } = req.body;
  if (!token)
    return res.status(401).json({ message: "Refresh token required" });

  // Check if the refresh token is valid and still exists
  const refreshToken = await User.findOne({ token });
  if (!refreshToken) {
    return res.status(403).json({ message: "Invalid refresh token" });
  }

  // Verify the refresh token
  jwt.verify(token, REFRESH_SECRET_KEY, (err, user) => {
    if (err)
      return res.status(403).json({ message: "Token verification failed" });

    // Generate a new access token
    console.log(user);
    const accessToken = generateAccessToken({
      id: user.id,
      email: user.email,
    });
    res.json({ accessToken });
  });
};

const logoutUser = async (req, res) => {
  const { _id } = req.user; //coming from validation next()

  await User.findByIdAndUpdate(_id, { token: null });

  res.status(204).send();
};

//prettier-ignore
export { registerUser, loginUser, logoutUser, tokenUser };
