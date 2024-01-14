const Note = require('../models/note');

const fetchNotes = async (req, res) => {
    // find the notes
   const notes = await Note.find();
    // respond with 
    res.json({notes: notes})
  }

  const fetchNote = async (req, res) => {
    //get id of the url 
   const noteId = req.params.id
    //find the note using the  
    const note = await Note.findById(noteId)
    //respond to the note  
    res.json({note})
  }

  const createNote = async (req, res) => {
    const {title, body, hmos, billedMonth, billedAmount, paidAmount, scannedCopies, remarks} = req.body

  
    // Create a note with the provided data
    const note = await Note.create({
      title,
      body,
      hmos,
      billedMonth,
      billedAmount,
      paidAmount,
      diffrencies :paidAmount - billedAmount,
      scannedCopies,
      remarks
    });

      

        // Respond with the new note
        res.json({note});
      }



      const updateNote = async (req, res) => {
        // get the id off the url
        const noteId = req.params.id;
        // get the data fof the req body
        const {title, body, hmos, billedMonth, billedAmount, paymentDate, diffrencies, scannedCopies, remarks} = req.body

        // find and update the record
    await Note.findByIdAndUpdate(noteId, {
            title,
            body,
            hmos,
            billedMonth,
            billedAmount,
            paymentDate,
            diffrencies,
            scannedCopies,
            remarks
        })

        // find updated note
        const note = await Note.findById(noteId)
        // respond with it
        res.json({note})
      }


      const deleteNote = async (req,res) => {

        // get the id off the url
        const noteId = req.params.id;

        //delete the record
      const note =  await Note.deleteOne({id: noteId})

        // respond with it
        res.json({note})
  }




  
  module.exports = {
    fetchNotes,   
    fetchNote,
    createNote,
    updateNote,
    deleteNote
  }