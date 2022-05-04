const mongoose = require("mongoose");
const { isEmail } = require('validator');
const bycrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, "Please enter an email"],
        unique: true,
        lowercase: true,
        validate: [isEmail, "Please enter a valid email"]
    },
    password: {
        type: String,
        required: [true, "Please enter a password"],
        minlength: [6, "Minimum password length is 6 characters"],
    }
})

userSchema.statics.login = async function(email, password) {
    const user = await this.findOne({ email });
    if(user) {
       const auth = bycrypt.compare(password, user.password);
       if (auth) {
        return user;
       } else {
        throw Error('incorrect password')
       }
    }
    throw Error('incorrect email')
}

// fire a function before saving
userSchema.pre("save", async function (next) {
    const salt = await bycrypt.genSalt();
    this.password = await bycrypt.hash(this.password, salt);  
    next();
})

const User = mongoose.model('user', userSchema);
module.exports = User;