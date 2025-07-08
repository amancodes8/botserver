const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/auth');
const User = require('../models/User');
const Assessment = require('../models/Assessment');

// @route   GET api/users/dashboard
// @desc    Get user dashboard data
router.get('/dashboard', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    const assessments = await Assessment.find({ user: req.user.id })
      .sort({ dateTaken: -1 })
      .populate('answers.question');
    
    res.json({ user, assessments });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   PUT api/users/update
// @desc    Update user profile
router.put('/update', authMiddleware, async (req, res) => {
  const { name, dateOfBirth, gender } = req.body;

  try {
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: { name, dateOfBirth, gender } },
      { new: true }
    ).select('-password');
    
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;