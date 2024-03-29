const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require("./routes/authRoutes")
require("dotenv").config()
const cookieParser = require('cookie-parser');
const { requireAuth, checkUser } = require('./middleware/authMiddleware');
const app = express();

// middleware
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

// view engine
app.set('view engine', 'ejs');
const port = process.env.PORT || 3000;
// database connection
const dbURI = process.env.DBURI;
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex:true })
  .then((result) => app.listen(port))
  .catch((err) => console.log(err));

// routes
app.get('*', checkUser)
app.get('/', (req, res) => res.render('home'));
app.get('/smoothies', requireAuth, (req, res) => res.render('smoothies'));

// cookies
// app.get('/set-cookies', (req, res) => {
//   // res.setHeader('Set-Cookie', 'newUser=true');

//   res.cookie('newUser', false, {maxAge: 1000 * 60 * 60 * 24, httpOnly: true });
//   res.send("you got the cookies");
// })
// app.get('/read-cookies', (req, res) => {
//   const cookies = req.cookies;
  
// })
app.use(authRoutes);