const express = require('express');
const router = express.Router();
const { check } = require('express-validator');
const { login, changePassword, verifySession } = require('../controllers/authController');

// -----------------------------
// @route   POST /api/auth/login
// @desc    Student login and get token
// @access  Public
// -----------------------------
router.post(
  '/login',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').not().isEmpty(),
  ],
  login
);

// -----------------------------
// @route   POST /api/auth/change-password
// @desc    Change student password
// @access  Private
// -----------------------------
router.post(
  '/change-password',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('oldPassword', 'Old password is required').isLength({ min: 6 }),
    check('newPassword', 'New password must be at least 6 characters').isLength({ min: 6 }),
  ],
  changePassword
);

// -----------------------------
// @route   POST /api/auth/verifysession
// @desc    Verify student session token
// @access  Public
// -----------------------------
router.post(
  '/verifysession',
  [check('token', 'Token is required').not().isEmpty()],
  verifySession
);

module.exports = router;
