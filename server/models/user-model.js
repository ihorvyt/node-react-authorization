const {Schema, model} = require('mongoose');

const UserSchema = new Schema({
    username: {type: String, unique: true, required: true},
    email: {type: String, unique: true, required: true},
    password: {type: String, required: true},
    isActivated: {type: Boolean},
    activationLink: {type: String},
    forgotPasswordLink: {type: String},
    randomPasswordIsSet: {type: Boolean, default: false},
    picture: {type: String, default: null},
})

module.exports = model("User", UserSchema);