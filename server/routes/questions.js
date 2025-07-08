const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const authMiddleware = require('../middleware/auth');
const Question = require('../models/Question');

// @route   GET api/questions
// @desc    Get all autism questions
router.get('/', authMiddleware, async (req, res) => {
  try {
    const questions = await Question.find({ category: 'autism' });
    res.json(questions);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   POST api/questions
// @desc    Submit assessment answers
router.post('/assess', authMiddleware, [
  check('answers', 'Answers are required').isArray({ min: 1 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { answers } = req.body;

  try {
    // Calculate total score
    let totalScore = 0;
    const answerDocs = [];
    
    for (const answer of answers) {
      const question = await Question.findById(answer.questionId);
      if (!question) continue;
      
      const selectedOption = question.options.find(opt => opt._id.toString() === answer.optionId);
      if (!selectedOption) continue;
      
      totalScore += selectedOption.score;
      answerDocs.push({
        question: answer.questionId,
        selectedOption: answer.optionId,
        score: selectedOption.score
      });
    }

    // Save assessment
    const assessment = new Assessment({
      user: req.user.id,
      answers: answerDocs,
      totalScore
    });

    await assessment.save();
    res.json(assessment);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;