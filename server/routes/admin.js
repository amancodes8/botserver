const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const authMiddleware = require('../middleware/auth');
const adminMiddleware = require('../middleware/admin');
const User = require('../models/User');
const Question = require('../models/Question');
const Assessment = require('../models/Assessment');

// @route   GET api/admin/stats
// @desc    Get admin dashboard stats
router.get('/stats', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const questionCount = await Question.countDocuments();
    const assessmentCount = await Assessment.countDocuments();
    
    res.json({ userCount, questionCount, assessmentCount });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   GET api/admin/users
// @desc    Get all users
router.get('/users', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   GET api/admin/users/:id
// @desc    Get user by ID
router.get('/users/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }
    
    const assessments = await Assessment.find({ user: req.params.id })
      .sort({ dateTaken: -1 });
    
    res.json({ user, assessments });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   PUT api/admin/users/:id
// @desc    Update user
router.put('/users/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  const { name, email, role, dateOfBirth, gender } = req.body;

  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { name, email, role, dateOfBirth, gender } },
      { new: true }
    ).select('-password');
    
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   DELETE api/admin/users/:id
// @desc    Delete user
router.delete('/users/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Assessment.deleteMany({ user: req.params.id });
    
    res.json({ msg: 'User deleted' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   POST api/admin/questions
// @desc    Add new question
router.post('/questions', [authMiddleware, adminMiddleware], [
  check('questionText', 'Question text is required').not().isEmpty(),
  check('options', 'Options are required').isArray({ min: 2 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { questionText, category, options } = req.body;

  try {
    const question = new Question({
      questionText,
      category: category || 'autism',
      options,
      createdBy: req.user.id
    });

    await question.save();
    res.json(question);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   PUT api/admin/questions/:id
// @desc    Update question
router.put('/questions/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  const { questionText, options } = req.body;

  try {
    const question = await Question.findByIdAndUpdate(
      req.params.id,
      { $set: { questionText, options } },
      { new: true }
    );
    
    res.json(question);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   DELETE api/admin/questions/:id
// @desc    Delete question
router.delete('/questions/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    await Question.findByIdAndDelete(req.params.id);
    res.json({ msg: 'Question deleted' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;