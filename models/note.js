const mongoose = require('mongoose');
 


const noteSchema = new mongoose.Schema({
  title: String,
  body: String,
  hmos: String,
  billedMonth: String,
  billedAmount: Number,
  paidAmount: Number,
  paymentDate: String,
  diffrencies: Number,
  scannedCopies: String,
  remarks: String
  });



  const Note = mongoose.model('Note', noteSchema);


  module.exports = Note;