// Load env variables
if (process.env.NODE_ENV !== "production") {
    require("dotenv").config();
  }
  
  // Import dependencies
  const express = require('express');
  const cors = require("cors")
  const connectToDb = require('./config/connectToDb');
  const cookieParser = require("cookie-parser")
  const Note = require('./models/note');
  const notesController = require ("./controllers/notesController");
  const usersController = require("./controllers/usersController");
  const requireAuth = require("./middleware/requireAuth");
  
  // Create an express app
  const app = express();
  
  // Configure express app
  app.use(express.json());
  app.use(cookieParser());
  app.use(cors({
    origin: true,
    credentials: true,
  }));
  
  // Connect to database
  connectToDb()
    .then(() => {
      // Routing
      app.get('/', (req, res) => {
        res.json({ hello: 'World' });
      });
      app.post("/signup", usersController.signup)
      
      app.post("/login", usersController.login)

      app.get("/logout", usersController.logout)

      app.get("/check-auth", requireAuth, usersController.checkAuth)

      app.get("/notes", notesController.fetchNotes)

      app.get("/notes/:id", notesController.fetchNote)
  
      app.post('/notes', notesController.createNote);

      app.put("/notes/:id", notesController.updateNote)
  
      app.delete("/notes/:id", notesController.deleteNote)

      // Start the server
      app.listen(5000, () => {
        console.log('Server started on port 5000');
      });
    })
    .catch((error) => { 
      console.error('Error starting server:', error);
    });