// config/passport.js

// load all the things we need
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;

var nodemailer = require('nodemailer');
var randomstring = require('randomstring');
var fs = require('fs');
var request = require('request');

// load up the user model
var User = require('../app/models/user');
var credentials = require('../credentials');

var smtpTransport = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    secure: true,
    port: 465,
    auth: {
        user: credentials.gmail.user,
        pass: credentials.gmail.pass,
    },
});

var download = function(uri, filename, callback){
  request.head(uri, function(err, res, body){
    console.log('content-type:', res.headers['content-type']);
    console.log('content-length:', res.headers['content-length']);

    request(uri).pipe(fs.createWriteStream(filename)).on('close', callback);
  });
};

// expose this function to our app using module.exports
module.exports = function(passport) {

    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) {

        // asynchronous
        // User.findOne wont fire unless data is sent back
        process.nextTick(function() {

        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'local.email' :  email }, function(err, user) {
            // if there are any errors, return the error
            if (err)
                return done(err);

            // check to see if theres already a user with that email
            if (user) {
                return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
            } else {

                // if there is no user with that email
                // create the user
                var newUser = new User();

                // set the user's local credentials
                newUser.local.email    = email;
                newUser.local.password = newUser.generateHash(password);
                newUser.local.isVerified = false;
                newUser.local.verifyId = randomstring.generate(15);

                let link = 'http://' + req.get('host') + '/verify?id=' + newUser.local.verifyId;
                let mailOptions = {
                    from: 'INFOR-Online-test <do-not-reply@infor.org>',
                    to: newUser.local.email,
                    subject: 'Confirm your email account',
                    html: 'Click this link to verify your email account.<br><a href="'+link+'">Click here to verify</a>'
                }

                console.log(mailOptions);

                smtpTransport.sendMail(mailOptions, function(err, res) {
                    if(err){
                        return console.error('Cannot send email: ' + err);
                    }
                    console.log('Mail sent: ' + newUser.local.email);
                });

                // save the user
                newUser.save(function(err) {
                    if (err)
                        throw err;
                    return done(null, newUser);
                });

            }

        });    

        });

    }));

    passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) { // callback with email and password from our form

        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'local.email' :  email }, function(err, user) {
            // if there are any errors, return the error before anything else
            if (err)
                return done(err);

            // if no user is found, return the message
            if (!user)
                return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user
            
            return done(null, user);
        });

    }));

    passport.use('facebook-login', new FacebookStrategy({

        // pull in our app id and secret from our auth.js file
        clientID            : credentials.facebookAuth.ID,
        clientSecret        : credentials.facebookAuth.Secret,
        callbackURL         : credentials.facebookAuth.callbackURL,
        // passReqToCallback   : true, 
        profileFields       : ['id', 'name', 'gender', 'email', 'photos'],

    },

    // facebook will send back the token and profile
    function(token, refreshToken, profile, done) {

        // console.log('call facebook-login');
        console.log('token: ', token);
        console.log('refreshToken: ', refreshToken);
        console.log('profile: ', profile);
        // asynchronous
        process.nextTick(function() {

            // find the user in the database based on their facebook id
            User.findOne({ 'facebook.id' : profile.id }, function(err, user) {

                // if there is an error, stop everything and return that
                // ie an error connecting to the database
                if (err)
                    return done(err);

                // if the user is found, then log them in
                if (user) {
                    return done(null, user); // user found, return that user
                } else {
                    // if there is no user found with that facebook id, create them
                    var newUser = new User();

                    // set all of the facebook information in our user model
                    newUser.facebook.id    = profile.id; // set the users facebook id                   
                    newUser.facebook.token = token; // we will save the token that facebook provides to the user                    
                    newUser.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName; // look at the passport user profile to see how names are returned
                    newUser.facebook.email = profile.emails[0].value; // facebook can return multiple emails so we'll take the first
                    newUser.facebook.gender = profile.gender;

                    // var profile_pic_link = "graph.facebook.com/"; + profile.id + "/picture" + "?width=200&height=200" + "&access_token=" + token;
                    // console.log('pic_link: ' + profile_pic_link);

                    // download(profile_pic_link, profile.username + '.png', function(){
                    //   console.log('save profile picture done: ' + profile.username);
                    // });

                    // save our user to the database
                    newUser.save(function(err) {
                        if (err)
                            throw err;

                        // if successful, return the new user
                        return done(null, newUser);
                    });
                }

            });
        });

    }));

};