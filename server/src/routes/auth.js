const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  getProfile,
  logoutUser,
  setupMFA,
  verifyMFASetup,
} = require("../controllers/authController");

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/profile", getProfile);
router.post("/logout", logoutUser);

router.post("/mfa/setup", setupMFA);
router.post("/mfa/verify", verifyMFASetup);

module.exports = router;
