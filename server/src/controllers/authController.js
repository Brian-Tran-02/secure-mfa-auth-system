const bcrypt = require("bcrypt");
const pool = require("../db");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");

const SALT_ROUNDS = 10;

const registerUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email],
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        message: "User already exists.",
      });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    const newUser = await pool.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email, created_at`,
      [email, passwordHash],
    );

    return res.status(201).json({
      message: "User registered successfully.",
      user: newUser.rows[0],
    });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({
      message: "Server error.",
    });
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email],
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        message: "Invalid credentials.",
      });
    }

    const user = userResult.rows[0];

    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({
        message: "Invalid credentials.",
      });
    }

    if (user.mfa_enabled) {
      req.session.mfa_pending = true;
      req.session.mfa_user = {
        id: user.id,
        email: user.email,
      };

      return req.session.save((err) => {
        if (err) {
          console.error("Session save error during MFA step:", err);
          return res.status(500).json({
            message: "Server error.",
          });
        }

        return res.status(200).json({
          message: "MFA required.",
          mfaRequired: true,
        });
      });
    }

    req.session.user = {
      id: user.id,
      email: user.email,
      mfa_enabled: user.mfa_enabled,
    };

    return req.session.save((err) => {
      if (err) {
        console.error("Session save error during login:", err);
        return res.status(500).json({
          message: "Server error.",
        });
      }

      return res.status(200).json({
        message: "Login successful.",
        mfaRequired: false,
        user: req.session.user,
      });
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      message: "Server error.",
    });
  }
};

const getProfile = (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      message: "Not authenticated.",
    });
  }

  return res.status(200).json({
    message: "Profile retrieved successfully.",
    user: req.session.user,
  });
};

const logoutUser = (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        message: "Logout failed.",
      });
    }

    res.clearCookie("connect.sid");
    return res.status(200).json({
      message: "Logout successful.",
    });
  });
};

const setupMFA = async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({
        message: "Not authenticated.",
      });
    }

    const secret = speakeasy.generateSecret({
      name: `Secure MFA Auth System (${req.session.user.email})`,
    });

    req.session.temp_mfa_secret = secret.base32;

    return req.session.save(async (err) => {
      if (err) {
        console.error("Session save error during MFA setup:", err);
        return res.status(500).json({
          message: "Server error.",
        });
      }

      try {
        const qrCodeDataURL = await qrcode.toDataURL(secret.otpauth_url);

        return res.status(200).json({
          message: "MFA setup initiated.",
          qrCode: qrCodeDataURL,
          secret: secret.base32,
        });
      } catch (qrError) {
        console.error("QR code generation error:", qrError);
        return res.status(500).json({
          message: "Server error.",
        });
      }
    });
  } catch (error) {
    console.error("MFA setup error:", error);
    return res.status(500).json({
      message: "Server error.",
    });
  }
};

const verifyMFASetup = async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({
        message: "Not authenticated.",
      });
    }

    const { token } = req.body;
    const tempSecret = req.session.temp_mfa_secret;

    if (!token) {
      return res.status(400).json({
        message: "Verification code is required.",
      });
    }

    if (!tempSecret) {
      return res.status(400).json({
        message: "No MFA setup in progress.",
      });
    }

    const verified = speakeasy.totp.verify({
      secret: tempSecret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(401).json({
        message: "Invalid verification code.",
      });
    }

    await pool.query(
      `UPDATE users
       SET totp_secret = $1, mfa_enabled = TRUE
       WHERE id = $2`,
      [tempSecret, req.session.user.id],
    );

    req.session.user.mfa_enabled = true;
    delete req.session.temp_mfa_secret;

    return req.session.save((err) => {
      if (err) {
        console.error("Session save error after MFA verify:", err);
        return res.status(500).json({
          message: "Server error.",
        });
      }

      return res.status(200).json({
        message: "MFA enabled successfully.",
      });
    });
  } catch (error) {
    console.error("MFA verification error:", error);
    return res.status(500).json({
      message: "Server error.",
    });
  }
};

const loginWithMFA = async (req, res) => {
  try {
    const { token } = req.body;

    if (!req.session.mfa_pending || !req.session.mfa_user) {
      return res.status(401).json({
        message: "No MFA login in progress.",
      });
    }

    if (!token) {
      return res.status(400).json({
        message: "OTP token is required.",
      });
    }

    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [
      req.session.mfa_user.id,
    ]);

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        message: "User not found.",
      });
    }

    const user = userResult.rows[0];

    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(401).json({
        message: "Invalid OTP code.",
      });
    }

    req.session.user = {
      id: user.id,
      email: user.email,
      mfa_enabled: user.mfa_enabled,
    };

    delete req.session.mfa_pending;
    delete req.session.mfa_user;

    return req.session.save((err) => {
      if (err) {
        console.error("Session save error during MFA login:", err);
        return res.status(500).json({
          message: "Server error.",
        });
      }

      return res.status(200).json({
        message: "MFA login successful.",
        user: req.session.user,
      });
    });
  } catch (error) {
    console.error("MFA login error:", error);
    return res.status(500).json({
      message: "Server error.",
    });
  }
};

const debugSession = (req, res) => {
  return res.status(200).json(req.session);
};

module.exports = {
  registerUser,
  loginUser,
  getProfile,
  logoutUser,
  setupMFA,
  verifyMFASetup,
  loginWithMFA,
  debugSession,
};
