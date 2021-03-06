require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth2').Strategy;
var findOrCreate = require('mongoose-findorcreate');


const app = express();

app.use(express.static("public"));

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb+srv://"+ process.env.DB, {useNewUrlparser: true, useUnifiedTopology: true});

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password'] });
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username });
  });
});


passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://rugged-cuyahoga-valley-99210.herokuapp.com/auth/google/secrets",
    passReqToCallback: true
  },
  function(request, accessToken, refreshToken, profile, done) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));



app.get("/", function(req, res){
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'profile', 'email' ] }
));

app.get('/auth/google/secrets',
  passport.authenticate('google', {
    failureRedirect: '/login',
    successRedirect: '/secrets'
}));


app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    } else {
      if(foundUsers) {
        res.render("secrets", {userWithSecrets: foundUsers});
      }
    }
  });
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // } else {
  //   res.redirect("/login");
  // }
});


app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("login");
  }
});


app.get('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});


app.post("/register", function(req, res){

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash){
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //
  //   newUser.save(function(err){
  //     if(err){
  //       console.log(err);
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res){
  // const username = req.body.username;
  // const password = req.body.password;
  //
  //
  // User.findOne({email: username}, function(err, foundUser){
  //   if(err){
  //     console.log(err);
  //   } else {
  //     if(foundUser){
  //       bcrypt.compare(password, foundUser.password, function(err, result){
  //         if(result === true){
  //           res.render("secrets");
  //         }
  //       });
  //     }
  //   }
  // });

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});


app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err, founduser){
    if(err){
      console.log(err);
    } else {
      if(founduser){
        founduser.secret = submittedSecret;
        founduser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });


});



let port = process.env.PORT;
if(port == null || port ==""){
  port = 3000;
}


app.listen(port, function(){
  console.log("Server is Started Successfully");
});
