const passport = require('passport');
const LocaStrategy = require('passport-local').Strategy;

const User = require('../models/user');

passport.serializeUser((user, done) => {
    done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

passport.use('local-signup', new LocaStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, email, password, done) => {

    const user = await User.findOne({ email: email });
    if(user){
        return done(null, false, req.flash('signupMessage','The email is alredy taken'));
    } else {
        const userUser = new User();
        userUser.email = email;
        userUser.password = userUser.encryptPassword(password);
        await userUser.save();
        done(null, userUser);
    }
}));

passport.use('local-signin', new LocaStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
}, async(req, email, password, done) => {
    const user = await User.findOne({ email: email });
    if(!user){
        return done(null, false, req.flash('signinMessage', 'No user found'));
    }
    if(!user.comparePassword(password)){
        return done(null, false, req.flash('signinMessage', 'Incorrect password'));
    }
    done(null, user);
}));