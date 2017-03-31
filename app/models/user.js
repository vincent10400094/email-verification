// app/models/user.js
// load the things we need
var mongoose = require('mongoose');
var bcrypt   = require('bcrypt-nodejs');

// define the schema for our user model
var userSchema = mongoose.Schema({

<<<<<<< HEAD
    local: {

        email		: String,
        password 	: String,
        verifyId	: String,
        isVerified	: Boolean,

=======
    local            : {
        email        : String,
        password     : String,
        verifyId     : String,
        isVerified   : { type: Boolean, default: false},
>>>>>>> a2fa4d277f242f8eac4125de7d087e6655529e81
    },

    facebook: {

    	id		: String,
    	token	: String,
    	name	: String,
    	email	: String,

    }

});

// methods ======================
// generating a hash
userSchema.methods.generateHash = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// checking if password is valid
userSchema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.local.password);
};

// create the model for users and expose it to our app
module.exports = mongoose.model('User', userSchema);