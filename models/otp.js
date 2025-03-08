const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
email: {
type: String,
},
otp: {
type:String
}
});

module.exports = mongoose.model("login_otp", userSchema);