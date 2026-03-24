const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  getProfile,
  logoutUser,
  setupMFA,
  verifyMFASetup,
  loginWithMFA,
  debugSession,
} = require("../controllers/authController");

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/profile", getProfile);
router.post("/logout", logoutUser);

router.post("/mfa/setup", setupMFA);
router.post("/mfa/verify", verifyMFASetup);
router.post("/mfa/login", loginWithMFA);
router.get("/debug-session", debugSession);

module.exports = router;
