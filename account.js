const express = require('express');
const router = express.Router();                            // used for refactoring code 
const path = require('path');                               // provides path functions
const MongoClient = require('mongodb').MongoClient;         // returns a MongoDB client
const bcrypt = require('bcrypt');                           // module for encrypting strings (for password)
const validator = require("email-validator");               // validate whether an email is real
const nodemailer = require('nodemailer');                   // send email from server
const checkAuth = require('./authentication.js').checkAuth; // custom method from authentication.js for authentication

const saltRounds = 10;                                      // for encryption (the higher the better the security is)

/**
 * 
 * force user to put in stronger password
 * remove from database when reset password
 * include link in email
 * host website
 l*/

// Login information for MongoDB
const MONGOD_USER = "xxxxxx";
const MONGOD_PWD = "xxxxxx";
var DB_NAME_LOGIN = "login"; // database name
var uri = "mongodb+srv://"+MONGOD_USER+":"+MONGOD_PWD+
            "@cluster0.jd51y.mongodb.net/"+DB_NAME_LOGIN+"?retryWrites=true&w=majority";
  
 const SERVER_EMAIL = 'xxxxxx';
 const SERVER_EMAIL_PWD = 'xxxxxx';

// GET REQUESTS, Linking html to pages ====================================================================
router.get('/', function(req,res){ 
    if (!req.session.user_id) res.sendFile(path.join(__dirname+'/login.html'));
    else res.redirect('/dashboard');
});

router.get('/dashboard', checkAuth,function(req,res){ 
    res.sendFile(path.join(__dirname+'/dashboard.html'));
});

router.get('/register', function(req,res){ 
    res.sendFile(path.join(__dirname+'/register.html'));
});

router.get('/forgot', function(req,res){
    res.sendFile(path.join(__dirname+'/forgot.html'));
});

router.get('/reset', function(req,res){
    res.sendFile(path.join(__dirname+'/reset.html'))
})


// POST REQUESTS ===========================================================================================
router.post('/login_form', function(req,res){
    var username = req.body.log_user;
    var pwd = req.body.log_pwd;
    const client = new MongoClient(uri, { useNewUrlParser: true , useUnifiedTopology: true});
    console.log("Connecting...");
    client.connect(err => {
        if(err) throw err;
        console.log("Connected to mongo");
        const collection = client.db(DB_NAME_LOGIN).collection("login_information"); // db is databse, collection is table
        collection.findOne({username : username}, function(err, item){
            console.log("Found someone who is " + username);
            if(item){
                var db_pwd = item.password;
                bcrypt.hash(pwd, saltRounds, function(err, hash){
                    pwd = hash;
                });
                bcrypt.compare(pwd, db_pwd, function(err, isMatch){ //checks if password is correct
                    if(err) throw err;
                    if(isMatch){
                        req.session.user_id = "username";              // create a session with the user's username
                        req.session.cookie.maxAge = 36000000 * 6;      // session expires in 6 hours
                        req.session.save();
                        res.redirect('/dashboard');
                        console.log("Information is correct");
                    }else{
                        console.log("Wrong password");
                        res.redirect('/');
                    }
                });
            }else{
                console.log("Username is not registered.");
                res.redirect('/');
            }
        });
    });
});

router.post('/register_form', function(req,res){
    const inp_email = req.body.reg_email;
    const inp_user = req.body.reg_user;

    var user_data = {email : inp_email,
                     username : inp_user, 
                     password : ""}; // object information for the user

    bcrypt.hash(req.body.reg_pwd, saltRounds, function(err, hash){
        user_data.password = hash;
    });
    
    // creating the MongoDB
    const client = new MongoClient(uri, { useNewUrlParser: true , useUnifiedTopology: true});

    client.connect(err => {
        if(err) throw err;
        const collection = client.db(DB_NAME_LOGIN).collection("login_information"); // db is databse, collection is table
        if (validator.validate(inp_email)){
            collection.findOne({email: inp_email}, function(err, result){
                if(result){ // there is a duplicate
                    console.log("Duplicate email found");
                }else{ // does not exist
                    collection.findOne({username: inp_user}, function(err, result){
                        if(result){ // if it exits
                            console.log("Duplicate user found");
                        }else{
                            collection.insertOne(user_data, function(err, res) {
                                if(err) throw err;
                                console.log("User has successfully registered.");
                            }); 
                        }
                    });
                }
            });
        }
    });
    client.close();
    res.redirect('/');
});

router.post('/forgot_form',function(req,res){
    const inp_email = req.body.forgot_email;
    console.log(inp_email);
    const client = new MongoClient(uri, { useNewUrlParser: true , useUnifiedTopology: true});
    
    client.connect(err => {
        if(err) throw err;
        const collection = client.db(DB_NAME_LOGIN).collection("login_information"); // db is databse, collection is table
        collection.findOne({email : inp_email}, function(err, result){
            console.log("Finding " + inp_email);
            if(result){
                sendPWDMail(inp_email);
            }else{
                console.log(inp_email + " is not a valid email");
            }
        });
    });
    client.close();
    res.redirect('/');
});

router.post('/forgot_button_form', function(req,res){
    res.redirect('/forgot');
});

router.post('/reset_password',function(req,res){
    var inp_temp_pass = req.body.temporary_password;
    var inp_new_pass = req.body.new_password;
    var inp_confirm_pass = req.body.confirm_new_password;
    console.log(inp_new_pass + " vs " + inp_confirm_pass);
    if (!(inp_new_pass == inp_confirm_pass)){
        console.log("the password are not the same");
    }else{
        const client = new MongoClient(uri, { useNewUrlParser: true , useUnifiedTopology: true});
        client.connect(err => {
            if(err) throw err;
            const collection = client.db(DB_NAME_LOGIN).collection("login_information");
            const temporary_collection = client.db(DB_NAME_LOGIN).collection("reset_information"); 
            temporary_collection.findOne({temporary_password: inp_temp_pass}, function(err, result){
                if (result){
                    bcrypt.hash(inp_new_pass, saltRounds, function(err, hash){
                        collection.replaceOne({email : result.email}, {$set:{password: hash}}, function(err, result){
                            if(err) throw err;
                            if(result){
                                temporary_collection.deleteOne({temporary_password: inp_temp_pass}, function(err,result){
                                    if(err) throw err;
                                    if(result) console.log("Removed from temporary database");
                                    else console.log("Did not remove from temporary database");
                                });
                            }
                        });
                        console.log("Password updated");
                        
                    });
                } else {
                    console.log("This user was not found in the temporary database");
                }
            });
        });
        client.close()
    }
    res.redirect('/');
})

router.post('/back_login', function(req,res){
    res.redirect('/');
});

// External METHODS ====================================================================================
// Returns a random generated temporary password 
function generateTempPWD(){
    var tempPas = "";
    for (let i = 0; i < 4; i++){
        tempPas += Math.random().toString(36).slice(-8);
    }
    return tempPas;
}

// Sends the temporary email to the requested email
async function sendPWDMail(inp_email){
    const GMAIL_INFO = {
        service: 'Gmail',
        auth: {
            user: SERVER_EMAIL,
            pass: SERVER_EMAIL_PWD,
        }
    };
    const serverEmail = nodemailer.createTransport(GMAIL_INFO);
    const temp_pwd = generateTempPWD();
    const clientEmail = {
        from : GMAIL_INFO.auth.user,
        to : inp_email,                    
        subject : 'Temporary code to reset password',
        html: `<p> <a href="localhost:3000/reset"> Click on this link to reset your password. </a> </p> 
                    <br> <p> Your temporary password is ` + temp_pwd + ' </p>',
    }
    let info = await serverEmail.sendMail(clientEmail);
    if(info){
        console.log('Email sent!');
        // server end 
        const client = new MongoClient(uri, { useNewUrlParser: true , useUnifiedTopology: true});
        client.connect(err => {
            if (err) throw err;
            nested_sendPWD(client, temp_pwd, inp_email);
        });
        client.close();
    }
    else console.log('Email failed to send');
}

async function nested_sendPWD(client, temp_pwd, inp_email){
    const temp_collection = client.db(DB_NAME_LOGIN).collection("reset_information");
    let find_status = await temp_collection.findOne({email: inp_email});
    let insert_status;
    if(find_status){
        insert_status = await temp_collection.replaceOne({email : inp_email}, {$set:{temporary_password: temp_pwd}});
        return;
    }else{
        insert_status = await temp_collection.insertOne({email: inp_email, temporary_password: temp_pwd});
    }
    if(insert_status){
        console.log("Temp password updated in temp database");
        setTimeout(function(){
            // remove from database
            temp_collection.deleteOne({temporary_password: temp_pwd}, function(err,isDeleted){
                if(err) throw err;
                if(isDeleted) console.log("Temporary password is deleted");
                else console.log("Error on deleting/Has been already deleted");
            });
        }, 1800000); // 30 minutes
    }else{
        console.log("Error in adding temp password in the database");
    }
}

module.exports = router