const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrpyt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator");

const User = require("../../models/User");

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post(
  "/",
  [
    check("name", "Name is required")
      .not()
      .isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({ min: 6 })
  ],
  async (req, res) => {
    // async because User.findOne() returns a promise
    // Show errors if something goes wrong
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body; // destructure the data sent with the request

    try {
      // See if user exists
      let user = await User.findOne({ email }); // grab the user

      if (user) {
        // match the same type of error as errors: errors.array()
        return res
          .status(400)
          .json({ errors: [{ msg: "User already exists" }] });
      }
      // Get users gravatar
      const avatar = gravatar.url(email, {
        s: "200", // size
        r: "pg", // rating
        d: "mm" // default
      });
      // Create an instance of User
      user = new User({
        name,
        email,
        avatar,
        password
      });
      // Encrypt password:
      // Create a salt to do the hashing with
      // bcrpyt.genSalt() returns a promise
      const salt = await bcrpyt.genSalt(10);

      user.password = await bcrpyt.hash(password, salt);

      await user.save(); // save the user to database

      // Return jsonwebtoken
      const payload = {
        user: {
          id: user.id
        }
      };

      jwt.sign(
        payload,
        config.get("jwtSecret"),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err; // err is potential error
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server error");
    }
  }
);

module.exports = router;
