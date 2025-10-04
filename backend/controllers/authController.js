const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const { generateToken, verifyToken } = require('../utils/auth');
const Student = require('../models/Student');

// ---------- Student Login ----------
exports.login = async (req, res, next) => {
  let success = false;
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success, errors: errors.array() });
    }

    const { email, password } = req.body;

    const student = await Student.findOne({ email });
    if (!student) {
      return res
        .status(400)
        .json({ success, errors: [{ msg: 'Invalid email or password' }] });
    }

    const isMatch = await bcrypt.compare(password, student.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ success, errors: [{ msg: 'Invalid email or password' }] });
    }

    const token = generateToken(student.id, false);
    success = true;
    res.status(200).json({
      success,
      data: {
        token,
        student: {
          id: student.id,
          email: student.email,
          name: student.name,
        },
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
};

// ---------- Student Change Password ----------
exports.changePassword = async (req, res, next) => {
  let success = false;
  try {
    const { email, oldPassword, newPassword } = req.body;
    const student = await Student.findOne({ email });
    if (!student) {
      return res.status(400).json({ success, msg: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(oldPassword, student.password);
    if (!isMatch) {
      return res.status(400).json({ success, msg: 'Invalid credentials' });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    student.password = hashed;
    await student.save();

    success = true;
    res.status(200).json({ success, msg: 'Password changed successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
};

// ---------- Verify Token ----------
exports.verifySession = async (req, res, next) => {
  let success = false;
  try {
    const { token } = req.body;
    const decoded = verifyToken(token);
    if (decoded) {
      success = true;
      return res.status(200).json({ success, data: decoded });
    }
    res.status(400).json({ success, msg: 'Invalid token' });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success, msg: 'Server error' });
  }
};
