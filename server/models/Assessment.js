const mongoose = require('mongoose');

const AnswerSchema = new mongoose.Schema({
  question: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Question'
  },
  selectedOption: Number,
  score: Number
});

const AssessmentSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  answers: [AnswerSchema],
  totalScore: {
    type: Number,
    required: true
  },
  dateTaken: {
    type: Date,
    default: Date.now
  },
  notes: String
});

module.exports = mongoose.model('Assessment', AssessmentSchema);