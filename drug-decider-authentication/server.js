if(process.env.NODE_ENV !== 'production'){
    require('dotenv').config();
}

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');

const initializePassport = require('./passport-config');

initializePassport(
    passport, 
    username => {
        return users.find(user => user.username === username); //need to be replace by accessing mongodb
    },
    id => {
        return users.find(user => user.id === id);
    }
);

const users = [];

app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));


app.get('/', checkAuthenticated, (req, res) => {
    req.flash('info_i', req.session.messagei);
    req.session.messagei = "";
    res.render('index.ejs', { name: req.user.username })
});

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs');
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try{
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        users.push({
            id: Date.now().toString(),
            username: req.body.username,
            password: hashedPassword
        });
        res.redirect('/login');
    } catch {
        res.redirect('/register');
    }
});

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
});

app.get('/changePassword', checkAuthenticated, (req, res) => {
    res.render('change-password.ejs', { message: req.session.message });
});

app.post('/changePassword', checkAuthenticated, async (req, res) => {
    try{
        if(await bcrypt.compare(req.body.oldPassword, req.user.password)){
            //check if new passwords are the same
            if(req.body.newPassword.localeCompare(req.body.confirmPassword) == 0){
                const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
                req.user.password = hashedPassword; //need to update pswd in db
                req.session.messagei = "Password successfully updated.";
                
            }else{
                req.session.message = "New passwords do not match.";
                throw "bad new password";
            }
            res.redirect('/');
        }else{
            req.session.message = "Old password does not match.";
            throw "old password doesn't match";
        }
    }catch(e){
        req.flash('info_c', req.session.message);
        req.session.message = "";
        res.redirect('/changePassword');
    }
});

app.delete('/logout', (req, res) => {
    req.logOut();
    res.redirect('/login');
})

function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect('/login');
}

function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect('/');
    }
    next();
}

app.listen(3000);