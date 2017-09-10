const mongoose = require('mongoose');
mongoose.Promise = global.Promise;
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');


//EMAIL-------------------------------------------------------------------------------------------------------------------
let emailLengthChecker = (email) => {
    if (!email) {
        return false;
    } else {
        if (email.length < 11 || email.length > 30) {
            return false;
        } else {
            return true;
        }
    }
};

let validEmailChecker = (email) => {
    if (!email) {
        return false;
    } else {
        const regExp = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);
        return regExp.test(email);
    }
}


const emailValidators = [{
    validator: emailLengthChecker,
    message: 'Email has to contain at least 11 and no more than 30 characters'
}, {
    validator: validEmailChecker,
    message: 'Must be valid email!'
}]

//USERNAME-------------------------------------------------------------------------------------------------------------------

let usernameLengthChecker = (username) => {
    if (!username) {
        return false;
    } else {
        if (username.length < 5 || username.length > 20) {
            return false;
        } else {
            return true;
        }
    }
};

let validUsernameChecker = (username) => {
    if (!username) {
        return false;
    } else {
        const regExp = new RegExp(/^[a-zA-Z0-9]+$/);
        return regExp.test(username);
    }
};

const usernameValidators = [{
        validator: validUsernameChecker,
        message: "Must be valid username!"
    },
    {
        validator: usernameLengthChecker,
        message: "Username has to contain at least 5 and no more than 20 characters"
    }
];

//PASSWORD-------------------------------------------------------------------------------------------------------------------

let passwordLengthChecker = (password) => {
    if (!password) {
        return false;
    } else {
        if (password.length < 8 || password.length > 20) {
            return false;
        } else {
            return true;
        }
    }
};

let validPasswordChecker = (password) => {
    if (!password) {
        return false;
    } else {
        const regExp = new RegExp(/^(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[\d])(?=.*?[\W]).{8,20}$/);
        return regExp.test(password);
    }
};

const passwordValidators = [{
        validator: passwordLengthChecker,
        message: 'Password has to contain at least 8 and no more than 20 characters'
    },
    {
        validator: validPasswordChecker,
        message: 'Must be valid password'
    }
];

//SCHEMA-------------------------------------------------------------------------------------------------------------------


const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        validate: emailValidators
    },
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        validate: usernameValidators
    },
    password: {
        type: String,
        required: true,
        validate: passwordValidators
    },

});



userSchema.pre('save', function (next) {
    if (!this.isModified('password'))
        return next();

    bcrypt.hash(this.password, null, null, (err, hash) => {
        if (err)
            return next(err);
        this.password = hash;
        next();

    });

});


userSchema.methods.comparePassword = (password) => {
    return bcrypt.compareSync(password, this.password);
};

module.exports = mongoose.model('User', userSchema);