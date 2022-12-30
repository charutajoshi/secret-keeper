require("dotenv").config();
const express = require("express");
const bodyParser = require("body-Parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const saltRounds = 10;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const secretSchema = new mongoose.Schema ({
  secret: String
});

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secrets: [secretSchema]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
const Secret = new mongoose.model("Secret", secretSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) { res.render("home"); });

app.get("/auth/google", passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/facebook', passport.authenticate('facebook'));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  if (req.isAuthenticated()) {
    User.find({"_id": req.user.id}, function(err, foundUsers) {
      if (err) {
        console.log(err);
      } else {
        if (foundUsers) {
          res.render("secrets", {usersWithSecrets: foundUsers});
        }
      }
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;
  const secret = new Secret({
    secret: submittedSecret
  });

  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
          foundUser.secrets.push(secret);
          foundUser.save(function() {
            res.redirect("/secrets");
        });
      }
    }
  });
});

app.post("/register", function(req, res) {
  // Validate the user isn't alread registered

  // try {
  //   User.register({username: req.body.username}, req.body.password);
  //   passport.authenticate("local")(req, res, function() {
  //         res.redirect("/secrets")
  //       });
  // } catch (e) {
  //   if (e instanceof UserExistsError) {
  //     console.log("whooooops UserExistsError");
  //     res.redirect("/register");
  //   } else {
  //     console.log("some error");
  //     res.redirect("/register");
  //   }
  // }

  // If already registered, give option to change password
  // If not registered, create account

  // User.register({username: req.body.username}, req.body.password, function(err, user) {
  //   if (err) {
  //     console.log(err.constructor);
  //     if (err.constructor === err.errorMessages) {
  //       console.log("User exists!");
  //       res.redirect("/register");
  //     } else {
  //       // console.log(err);
  //     }
  //   } else {
  //     passport.authenticate("local")(req, res, function() {
  //       res.redirect("/secrets")
  //     })
  //   }
  // })

  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets")
      })
    }
  })

});

app.post("/login", function(req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/logout", function(req, res, next) {
  req.logout(function(err) {
    if (err) {
      return next(err);
    }
      res.redirect("/");
  });
});

app.listen(3000, function() {
  console.log("Server started on port 3000.");
})
