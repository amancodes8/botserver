const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const authMiddleware = require('../middleware/auth');
const Assessment = require('../models/Assessment');
const Question = require('../models/Question');
const User = require('../models/User');

// @route   POST api/assessments
// @desc    Submit a new autism assessment
// @access  Private
router.post('/', [
  authMiddleware,
  [
    check('answers', 'Answers are required').isArray({ min: 1 }),
    check('answers.*.questionId', 'Question ID is required').not().isEmpty(),
    check('answers.*.optionId', 'Option ID is required').not().isEmpty()
  ]
], async (req, res) => {
  // Validate request
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { answers, notes } = req.body;
    const userId = req.user.id;
    
    // Calculate total score and prepare answer documents
    let totalScore = 0;
    const answerDocs = [];
    
    // Process each answer
    for (const answer of answers) {
      const question = await Question.findById(answer.questionId);
      if (!question) {
        return res.status(400).json({ msg: `Question not found: ${answer.questionId}` });
      }
      
      const selectedOption = question.options.find(
        opt => opt._id.toString() === answer.optionId
      );
      
      if (!selectedOption) {
        return res.status(400).json({ msg: `Invalid option for question: ${answer.questionId}` });
      }
      
      totalScore += selectedOption.score;
      answerDocs.push({
        question: answer.questionId,
        selectedOption: answer.optionId,
        score: selectedOption.score
      });
    }

    // Create assessment record
    const assessment = new Assessment({
      user: userId,
      answers: answerDocs,
      totalScore,
      notes: notes || ''
    });

    await assessment.save();
    
    // Populate question details in the response
    const populatedAssessment = await Assessment.populate(assessment, {
      path: 'answers.question',
      select: 'questionText category'
    });

    res.json(populatedAssessment);

  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   GET api/assessments
// @desc    Get all assessments for current user
// @access  Private
router.get('/', authMiddleware, async (req, res) => {
  try {
    const assessments = await Assessment.find({ user: req.user.id })
      .sort({ dateTaken: -1 })
      .populate({
        path: 'answers.question',
        select: 'questionText category'
      });
      
    res.json(assessments);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   GET api/assessments/:id
// @desc    Get single assessment by ID
// @access  Private
router.get('/:id', authMiddleware, async (req, res) => {
  try {
    const assessment = await Assessment.findOne({
      _id: req.params.id,
      user: req.user.id
    }).populate({
      path: 'answers.question',
      select: 'questionText options category'
    });

    if (!assessment) {
      return res.status(404).json({ msg: 'Assessment not found' });
    }

    res.json(assessment);
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ msg: 'Assessment not found' });
    }
    res.status(500).send('Server error');
  }
});

// @route   DELETE api/assessments/:id
// @desc    Delete an assessment
// @access  Private
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const assessment = await Assessment.findOneAndRemove({
      _id: req.params.id,
      user: req.user.id
    });

    if (!assessment) {
      return res.status(404).json({ msg: 'Assessment not found' });
    }

    res.json({ msg: 'Assessment removed' });
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ msg: 'Assessment not found' });
    }
    res.status(500).send('Server error');
  }
});

module.exports = router;