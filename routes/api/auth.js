const express = require("express");
const auth = require("../../middleware/auth");
const router = express.Router();

const User = require("../../models/User");

// @route   GET api/auth
// @desc    Test route
// @access  Public
// 'auth' is the middleware, adding it here makes the route protected
router.get("/", auth, async (req, res) => {
  try {
    // -password removes the password from data
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

module.exports = router;
