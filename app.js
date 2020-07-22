/*
 *  Date Created: July 12, 2020
 *  Author: Justin Deng, Yuxuan Zou, Darren Wang but mostly Darren
 *  Description: Login Page powered by MongoDB and incorporates password encryption
 */

const express = require('express');                         // returns a method using express
const app = express();                                      // gets an express object from the mthod
const expressSession = require('express-session');          // allows create sessions, cookies
const bodyParser = require('body-parser');                  // allows to retrieve information from html items

app.use(bodyParser.urlencoded({ extended: true })); 
// Set dashboard to only be accessed if authorized
app.use(expressSession({secret : '/dashboard', 
                        saveUninitialized: true, 
                        resave : false})); 
port = process.env.PORT || 3000
app.listen(port);       // hosted on port 3000

// combine backend for account setup information with app.js
const account_router = require('./account.js'); 
app.use(account_router);