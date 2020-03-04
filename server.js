if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');
const writeFileAtomic = require('write-file-atomic');
const path = require('path');

// Add some body parser middleware
app.use(express.json());

app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    saveUninitialized: false,
    resave: false,
  })
);
app.use(methodOverride('_method'));
app.use(express.static(__dirname + '/views'));

/* MONGOOSE SETUP */

const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/drugdecider');

const Schema = mongoose.Schema;
const UserDetail = new Schema({
  username: String,
  password: String,
});
const UserDetails = mongoose.model('user', UserDetail, 'users');

/*  PASSPORT SETUP  */

const passport = require('passport');
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, cb) {
  cb(null, user);
});

passport.deserializeUser(function(id, cb) {
  UserDetails.findById(id, function(err, user) {
    cb(err, user);
  });
});

/* PASSPORT LOCAL AUTHENTICATION */

const LocalStrategy = require('passport-local').Strategy;

passport.use(
  'local',
  new LocalStrategy((username, password, done) => {
    UserDetails.findOne(
      {
        username: username,
      },
      async (err, user) => {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false, { message: 'Invalid Username or Password' });
        }
        if (await bcrypt.compare(password, user.password)) {
          return done(null, user);
        }
        return done(null, false, { message: 'Invalid Username or Password' });
      }
    );
  })
);

app.get('/', checkAuthenticated, (req, res) => {
  req.flash('info_i', req.session.messagei);
  req.session.messagei = '';
  res.render('index.ejs', { name: req.user.username });
});

app.post(
  '/login',
  checkNotAuthenticated,
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true,
  })
);

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs');
});

app.get('/changePassword', checkAuthenticated, (req, res) => {
  res.render('change-password.ejs', { message: req.session.message });
});

app.post('/updatedata', checkAuthenticated, (req, res) => {
  update_drug_data(req.body);
});

app.post('/changePassword', checkAuthenticated, async (req, res) => {
  try {
    if (await bcrypt.compare(req.body.oldPassword, req.user.password)) {
      //check if new passwords are the same
      if (req.body.newPassword.localeCompare(req.body.confirmPassword) == 0) {
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        UserDetails.update(
          { _id: req.user._id },
          { $set: { password: hashedPassword } },
          function(err) {
            if (err) {
              req.session.message = 'could not update password';
              throw 'could not update password';
            }
          }
        );
        req.session.messagei = 'Password successfully updated.';
      } else {
        req.session.message = 'New passwords do not match.';
        throw 'bad new password';
      }
      res.redirect('/');
    } else {
      req.session.message = 'Old password does not match.';
      throw "old password doesn't match";
    }
  } catch (e) {
    req.flash('info_c', req.session.message);
    req.session.message = '';
    res.redirect('/changePassword');
  }
});

app.delete('/logout', (req, res) => {
  req.logOut();
  res.redirect('/login');
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
}

function update_drug_data(data) {
  writeFileAtomic(
    path.join(__dirname, '..', 'api.drugdecider.com', 'data', 'data.json'),
    JSON.stringify(data),
    err => {
      if (err) throw err;
    }
  );
}

app.listen(3000);
