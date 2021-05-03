const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { transformUser } = require("./merge");

const User = require("../../models/user");

module.exports = {
  createUser: async (args) => {
    try {
      const existingUser = await User.findOne({ email: args.userInput.email });
      if (existingUser) {
        throw new Error("User exists already.");
      }
      const hashedPassword = await bcrypt.hash(args.userInput.password, 12);

      const user = new User({
        username: args.userInput.username,
        firstName: args.userInput.firstName,
        lastName: args.userInput.lastName,
        email: args.userInput.email,
        avatar: args.userInput.avatar,
        password: hashedPassword,
        type: args.userInput.type,
        phone: args.userInput.phone,
        address: args.userInput.address,
      });

      const result = await user.save();

      return {
        ...result._doc,
        password: null,
        _id: result.id,
        type: result.type,
      };
    } catch (err) {
      throw err;
    }
  },
  getUser: async (args, req) => {
    try {
      if (!req.isAuth) {
        throw new Error("Unauthenticated!");
      }
      const user = await User.findById(req.userId);
      // console.log(user);
      return transformUser(user);
    } catch (err) {
      throw err;
    }
  },
  updateUserById: async ({ userId, updateUserInput }) => {
    try {
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        updateUserInput,
        (err, data) => {
          if (err) {
            console.log(err);
          } else {
            return data;
          }
        }
      );
      return transformUser(updatedUser);
    } catch (error) {
      throw new Error(error);
    }
  },
  getAllUsers: async (args, req, res) => {
    try {
      if (!req.isAuth) {
        throw new Error("Unauthenticated!");
      }
      if (!req.isAdmin) {
        throw new Error("You're not an admin");
      }

      const users = await User.find();
      return users;
    } catch (error) {
      throw error;
    }
  },
  login: async ({ email, password }, res) => {
    const user = await User.findOne({ email: email });
    if (!user) {
      throw new Error("User does not exist!");
    }
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      throw new Error("Password is incorrect");
    }
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      "somesupersecretkey",
      {
        expiresIn: "1h",
      }
    );

    return {
      userId: user.id,
      token: token,
      tokenExpiration: 60 * 60 * 1000,
      type: user.type,
    };
  },
};
