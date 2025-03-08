const User = require('../models/user')
const ForgotPassOTP = require('../models/FogotPassOTP'); 
const Userotp = require('../models/otp')
const jwt = require('jsonwebtoken'); //to generate signed token
const expressJwt = require('express-jwt');
const JWT_ACC_KEY = 'jwtaccountactivatekey321'
const crypto = require('crypto')
const uuidv1 = require('uuid/v1')
const nodemailer = require("nodemailer");
var CryptoJS = require("crypto-js");
const speakeasy = require('speakeasy')
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
var ObjectID = require("mongodb").ObjectID


exports.signup = async (req, res) => {
  try {
    // Validate required fields
    const { encryptedemail, encryptedpass, phone, referred_by_id } = req.body;
    if (!encryptedemail || !encryptedpass || !phone) {
      return res.send('Missing required fields: email, password, or phone.');
    }

    // Decrypt email and password
    const decryptemail = CryptoJS.AES.decrypt(encryptedemail, 'key');
    const email = decryptemail.toString(CryptoJS.enc.Utf8).toLowerCase();
    const decryptpass = CryptoJS.AES.decrypt(encryptedpass, 'key');
    const password = decryptpass.toString(CryptoJS.enc.Utf8);

    // Validate email format
    const emailRegex = /\S+@\S+\.\S+/;
    if (!emailRegex.test(email)) {
      return res.send('Invalid email format.');
    }

    // Generate OTP secret and token
    const temp_secret = speakeasy.generateSecret({ name: "Service" });
    const secret = temp_secret.ascii;
    const otpauth_url = temp_secret.otpauth_url;
    const tokenData = { email, password, phone, name: 'NA', secret, otpauth_url };

    // Sign JWT token
    const token = jwt.sign(tokenData, JWT_ACC_KEY, { expiresIn: '20m' });

    // Verify and save user
    jwt.verify(token, JWT_ACC_KEY, async (err, decodedToken) => {
      if (err) {
        return res.send('Incorrect or Expired link.');
      }
      const user = new User(decodedToken);
      try {
        await user.save();
        user.salt = undefined;
        user.hashed_password = undefined;

        return res.send("Signup Complete");
      } catch (err) {
        return res.send("User Already Exists.");
      }
    });

  } catch (error) {
    return res.send("Something went wrong.");
  }
};

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  // Generate 4-digit OTP
  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  const expirationTime = Date.now() + 10 * 60 * 1000; // 10 minutes from now

  try {
    // Check if the user exists in the userpool collection
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User with this email does not exist." });
    }

    // Check if there's already an OTP for this email, update it if exists
    const existingOTP = await ForgotPassOTP.findOne({ email });
    if (existingOTP) {
      existingOTP.otp = otp;
      existingOTP.otpExpiry = expirationTime;
      await existingOTP.save();
    } else {
      // Create a new OTP entry for the email
      await ForgotPassOTP.create({
        email,
        otp,
        otpExpiry: expirationTime,
      });
    }

    // Send OTP via email
    var transporter = nodemailer.createTransport({
      host: "smtp.hostinger.com",
      port: 465,
      secure: true,
      auth: {
        user: "support@aitradeandstake.com",
        pass: "Peter@1137",
      },
      tls: {
        ciphers: "SSLv3",
      },
    });

    await transporter.sendMail({
      from: '"AITRADEANDSTAKE Team" <support@aitradeandstake.com>',
      to: email,
      subject: "Reset Password OTP",
      html: `
        <p>Hello,</p>
        <p>Your OTP to reset your password is: <b>${otp}</b></p>
        <p>The OTP is valid for 10 minutes.</p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Regards,</p>
        <p>AITRADEANDSTAKE Team</p>
      `,
    });

    res.json({ message: "OTP sent to your email." });
  } catch (error) {
    console.log('error: ', error);
    res.status(500).json({ message: "Failed to send OTP. Please try again." });
  }
};

exports.resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    // Find the OTP entry in the forgot_pass_otp collection
    const otpRecord = await ForgotPassOTP.findOne({ email });

    if (!otpRecord) {
      return res.status(404).send("OTP not found for this email.");
    }

    // Check if OTP is correct and not expired
    if (otpRecord.otp !== otp || Date.now() > otpRecord.otpExpiry) {
      return res.status(400).send("Invalid or expired OTP.");
    }

    // Encrypt the new password
    const salt = uuidv1();
    const hashedPassword = crypto
      .createHmac('sha1', salt)
      .update(newPassword)
      .digest("hex");

    // Update user's password in the User collection
    const updatedUser = await User.findOneAndUpdate(
      { email },
      { $set: { hashed_password: hashedPassword, salt } },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).send("User not found.");
    }

    // Remove OTP record from forgot_pass_otp collection after successful password reset
    await ForgotPassOTP.deleteOne({ email });

    res.send("Password reset successfully.");
  } catch (error) {
    res.status(500).send("Error resetting password, please try again.");
  }
};

exports.getUser = (req, res) => {
    var decrypt  = CryptoJS.AES.decrypt(req.body.encrypt, 'key');
    var email = decrypt.toString(CryptoJS.enc.Utf8)
    // var decrypt1  = CryptoJS.AES.decrypt(req.body.encrypt2, 'key');
    // var password = decrypt1.toString(CryptoJS.enc.Utf8)
    var userEmail = req.body.useremail
    User.findOne({ email }, async(err, user) => {
        if(user){
            if(req.body.role==1){
                User.findOne({ email:userEmail }, async(err, userD) => {
                    if(userD){
                            res.send(userD)
                    }
                    else{
                        res.send("User not found")
                    }
                })
            }
            else{
                res.send("You dont have permission for this operation")
            }
        }
        else{
            res.send("You dont have permission for this operation")
        }
    })
  
}

exports.blockUser = (req, res) => {
    var decrypt  = CryptoJS.AES.decrypt(req.body.encrypt, 'key');
    var email = decrypt.toString(CryptoJS.enc.Utf8)
    // var decrypt1  = CryptoJS.AES.decrypt(req.body.encrypt2, 'key');
    // var password = decrypt1.toString(CryptoJS.enc.Utf8)
    User.findOne({ email }, async(err, user) => {
        if(user){
            if(user.role===1){
                let userE = req.body.useremail
                User.findOneAndUpdate({email:userE} , {$set: {brutecount:200}} , {new:true})
                .then(ress=>{
                    res.send("Successfully blocked user")
                })
            }
        }
    })
}

exports.unBlockUser = (req, res) => {
    var decrypt  = CryptoJS.AES.decrypt(req.body.encrypt, 'key');
    var email = decrypt.toString(CryptoJS.enc.Utf8)
    User.findOne({ email }, async(err, user) => {
        if(user){
            if(user.role===1){
                let userE = req.body.useremail
                User.findOneAndUpdate({email:userE} , {$set: {brutecount:0}} , {new:true})
                .then(ress=>{
                    res.send("Successfully unblocked user")
                })
            }
        }
    })
}

exports.signin = (req, res) => {

var decrypt  = CryptoJS.AES.decrypt(req.body.encrypt1, 'key');
var localVar =  decrypt.toString(CryptoJS.enc.Utf8)
var email = localVar.toLowerCase()
var decrypt1  = CryptoJS.AES.decrypt(req.body.encrypt2, 'key');
var password = decrypt1.toString(CryptoJS.enc.Utf8)
User.findOne({ email }, async(err, user) => {
if(user){
  var now = new Date().getMinutes();
  var dbTime = user.bruteblocktime
  var t = dbTime - now

  if(t<=0){
  if(user.brutecount==5){
      if(user.bruteblocktime==0){
        var deadline = new Date(new Date().getMinutes()+5).getTime();
        // var current = new Date();
        // console.log(deadline,new Date().getHours());
        User.findOneAndUpdate({email:user.email} , {$set: {bruteblocktime:deadline}} , {new:true})
        .then(resp=>console.log("Success"))
        res.send("You have exceeded the maximum try")
      }
      else{
        User.findOneAndUpdate({email:user.email} , {$set: {bruteblocktime:0,brutecount:0}} , {new:true})
        .then(resp=>{
        res.send("Your account has been successfully unblocked")
        })
      }
  }

  else if(user.brutecount==200){
    res.send("Admin has blocked you , kindly contact to support")
  }

  else if(user.brutecount<=5){
    var count = user.brutecount
    User.findOneAndUpdate({email:user.email} , {$set: {bruteblocktime:0}} , {new:true})
    .then(resp=>console.log("WORKED FOR BRUTE 0"))
    User.findOneAndUpdate({email:user.email} , {$set: {brutecount:count+1}} , {new:true})
    .then(t=>{console.log("WORKED FOR BRUTE +1")})
    .catch(e=>{console.log("ERROR")})
  
if (err || !user) {
    res.send("User doesn't exist ? Please Sign Up")
}
if (!user.authenticate(password)) {
    res.send(`Invalid credentials. You are left with ${5-(count+1)} more attempts`)
}
else{
//Setting Brute to zero
User.findOneAndUpdate({email:user.email} , {$set: {brutecount:0}} , {new:true})
.then(t=>{console.log("SUCCSESS")})
.catch(e=>{console.log("ERROR")})
//generate A SIGNED token with user id and secret
QRCode.toDataURL(user.otpauth_url , async function(err,data){
const token = jwt.sign({ _id: user._id,email:user.email,hash:user.hashed_password,role:user.role,enabledtwofactorauth:user.enabledtwofactorauth }, process.env.JWT_SECRET,{expiresIn:'360m'})
//persist the token as 't' in cookie with expire date
res.cookie('t', token, { expire: new Date() + 9999 })

const { _id, name, email, role } = user

return res.json({ token:token,email:user.email })
})
  }
}

}
else{
  res.send("You are tempororily blocked")
  console.log("YOU ARE TEMPORORILY BLOCKED")
}
}
else{
    res.send("User doesnt exist , Please Sign Up")
}
})
}

exports.confirmotp = (req, res) => {
  const { email , _id} =req.body

  var decryptotp  = CryptoJS.AES.decrypt(req.body.otp, 'key');
  var otp = decryptotp.toString(CryptoJS.enc.Utf8)
  var decrypttokenotp  = CryptoJS.AES.decrypt(req.body.tokenotp, 'key');
  var tokenotp = decrypttokenotp.toString(CryptoJS.enc.Utf8)

	jwt.verify(tokenotp , process.env.JWT_SECRET , async function(err , decodedToken){
    Userotp.findOne({email:decodedToken.email})
    .then(ress=>{
      if(otp==ress.otp){
        res.send(decodedToken)
      }
      else{
        res.send("Invalid OTP")
      }
    })
    .catch(err=>console.log(err))
	})
}

exports.AccChangePass = (req,res)=>{
    //find the user based on email
// const { email, password } = req.body

var decrypt  = CryptoJS.AES.decrypt(req.body.encrypt1, 'key');
var email = decrypt.toString(CryptoJS.enc.Utf8)
var decrypt1  = CryptoJS.AES.decrypt(req.body.encrypt2, 'key');
var password = decrypt1.toString(CryptoJS.enc.Utf8)
User.findOne({ email }, async(err, user) => {
  
if (err || !user) {
return res.status(400).json({
err: "User doesn't exist ? Please Sign Up"
})
}
//if user found make sure th email and password match
// create authenticate method in user model
if (!user.authenticate(password)) {
return res.status(401).json({
error: "email and password don't match"
})
}
//generate A SIGNED token with user id and secret
const token = jwt.sign({ _id: user._id,email:user.email,name:user.name,phone:user.phone,role:user.role }, process.env.JWT_SECRET)
//persist the token as 't' in cookie with expire date

res.cookie('t', token, { expire: new Date() + 9999 })
//return response with user and token to frontend clint
const { _id, name, email, role } = user

jwt.verify(token , process.env.JWT_SECRET , async function(err , decodedToken){
      if(decodedToken){
        var salt = uuidv1()
        var x = crypto
        .createHmac('sha1', salt)
        .update(req.body.newPass)
        .digest("hex");
        
        User.findOneAndUpdate({email:decodedToken.email } , {$set:{hashed_password:x , salt:salt}} , {new: true})
        .then(response=>res.send(response))
        .catch(err=>res.send(err))
      }
      else{
        res.send("SOMETHING WENT WRONG")
      }
	})

// return res.json({ token, user: { email, name, role } })
})
}

exports.enableTwoFA = (req,res)=>{
    var decrypt  = CryptoJS.AES.decrypt(req.body.encrypt1, 'key');
    var email = decrypt.toString(CryptoJS.enc.Utf8)
    User.findOneAndUpdate({email:email } , {$set:{enabledtwofactorauth:true}} , {new: true})
    .then(response=>{
        QRCode.toDataURL(response.otpauth_url , function(err,data){
            res.send(data)
        })
    })
    .catch(err=>res.send(err))
}
exports.disableTwoFA = (req,res)=>{
    var decrypt  = CryptoJS.AES.decrypt(req.body.encrypt1, 'key');
    var email = decrypt.toString(CryptoJS.enc.Utf8)
    User.findOneAndUpdate({email:email } , {$set:{enabledtwofactorauth:false}} , {new: true})
    .then(response=>{
      res.send({enabledtwofactorauth:response.enabledtwofactorauth})
    })
    .catch(err=>res.send(err))
}

exports.verifyTwoFA = (req,res)=>{
   var verified = speakeasy.totp.verify({
       secret:req.body.secret,
       encoding:'ascii',
       token:req.body.token
   })
 res.send({verified:verified})
}

exports.signout=(req,res)=>{
res.clearCookie('t')
res.json({message: "Signout success"})
}


exports.requireSignin = expressJwt({
secret: process.env.JWT_SECRET,
userProperty: "auth"
});


exports.isAuth = (req,res,next)=>{
let user = req.profile && req.auth && req.profile._id == req.auth._id
if(!user){
return res.status(403).json({
error:"Access Denied"
});
}
next();
}

exports.isAdmin =(req,res,next)=>{
if(req.profile.role === 0){
return res.status(403).json({
error:"Admin Resource Access Denied"
})
}
next();
}



//BACKEND FUNCTIONS START
exports.validateToken = (req, res)=>{   
  const token = req.headers.authorization.split(' ')[1];  
  if(!token)
  {
      res.status(200).json({success:false, message: "Error! Token was not provided."});
  }
  try{
    const decodedToken = jwt.verify(token,process.env.JWT_SECRET );
    res.status(200).json(
      {
        success:true, 
        data:
        {
          email:decodedToken.email,
          _id:decodedToken._id,
          role:decodedToken.role
        }
      }); 
  }
  catch{
    res.send("User validation failed")
  } 
}

 
exports.create_dealer = async (req, res) => {
  try {
    // Extract and verify token
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.send({ success: false, message: "Token not provided" });
    }
    
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const adminUser = await User.findOne({ email: decodedToken.email });

    if (!adminUser || adminUser.role !== 1) {
      return res.send({ success: false, message: "Unauthorized access" });
    }

    // Validate input
    const { name, mobile, email, password } = req.body;
    if (!name || !mobile || !email || !password) {
      return res.send({ success: false, message: "All fields are required" });
    }

    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.send({ success: false, message: "Email already registered" });
    }

    const temp_secret = speakeasy.generateSecret({ name: "Service" });
    const secret = temp_secret.ascii;
    const otpauth_url = temp_secret.otpauth_url;
    const tokenData = { email, password, mobile, name,remark:"Dealer",role:2, secret, otpauth_url };

    // Sign JWT token
    const tokenJWT = jwt.sign(tokenData, JWT_ACC_KEY, { expiresIn: '20m' });

    // Verify and save user
    jwt.verify(tokenJWT, JWT_ACC_KEY, async (err, decodedToken) => {
      if (err) {
        return res.send('Incorrect or Expired link.');
      }
      const user = new User(decodedToken);
      try {
        await user.save();
        user.salt = undefined;
        user.hashed_password = undefined;

        return res.send({
          success: true,
          message: "Dealer created successfully",
          dealer: { name, mobile, email  },
        });
      } catch (err) {
        console.log(err)
          res.send({
          success: false,
          message: "Dealer already exists"
        });      
      }
    });
  } catch (error) {
    console.error(error);
    res.send({ success: false, message: "Internal server error" });
  }
};

exports.get_all_users = async (req, res) => {
  try {
    // Extract and verify token
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.send({ success: false, message: "Token not provided" });
    }

    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const adminUser = await User.findOne({ email: decodedToken.email });

    if (!adminUser || adminUser.role !== 1) {
      return res.send({ success: false, message: "Unauthorized access" });
    }

    // Fetch all users except admin
    const users = await User.find({ role: { $ne: 1 } }).select("-salt -hashed_password");

    res.send({ success: true, users });
  } catch (error) {
    console.error(error);
    res.send({ success: false, message: "Internal server error" });
  }
};

exports.get_all_tickets = async (req, res) => {
  try {
    // Extract token from headers
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.send({ success: false, message: "Unauthorized: Token not provided" });
    }

    // Verify token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const adminUser = await User.findOne({ email: decodedToken.email });

    // Ensure user exists and has admin privileges
    if (!adminUser || adminUser.role !== 1) {
      return res.send({ success: false, message: "Forbidden: Access denied" });
    }

    // Fetch users with tickets
    const usersWithTickets = await User.find(
      { "ticket_history.0": { $exists: true } }, // Ensure at least one ticket exists
      { name: 1, email: 1, mobile: 1, ticket_history: 1 } // Return only relevant fields
    );

    // Transform data for structured response
    const allTickets = usersWithTickets.flatMap(user =>
      user.ticket_history.map(ticket => ({
        ticket_id: ticket.ticket_id,
        ticket_raised_by: ticket.ticket_raised_by || user.name,
        ticket_type: ticket.ticket_type,
        ticket_query: ticket.ticket_query,
        ticket_category: ticket.ticket_category,
        ticket_subcategory: ticket.ticket_subcategory,
        ticket_remark: ticket.ticket_remark,
        ticket_image_one: ticket.ticket_image_one,
        ticket_image_two: ticket.ticket_image_two,
        ticket_video_one: ticket.ticket_video_one,
        ticket_video_two: ticket.ticket_video_two,
        ticket_assigned_to: ticket.ticket_assigned_to,
        timestamp: ticket.timestamp,
        status: ticket.status,
        user_email: user.email,
        user_mobile: user.mobile,
      }))
    );

    res.send({ success: true, tickets: allTickets });
  } catch (error) {
    console.error("Error fetching tickets:", error);
    res.send({ success: false, message: "Internal server error" });
  }
};

exports.get_user_tickets = async (req, res) => {
  try {
    // Extract token from headers
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.send({ success: false, message: "Unauthorized: Token not provided" });
    }

    // Verify token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userEmail = decodedToken.email;

    // Fetch user by email
    const user = await User.findOne({ email: userEmail }, { ticket_history: 1, email: 1, mobile: 1 });

    // Ensure user exists
    if (!user) {
      return res.send({ success: false, message: "User not found" });
    }

    // Transform data for structured response
    const userTickets = user.ticket_history.map(ticket => ({
      ticket_id: ticket.ticket_id,
      ticket_raised_by: ticket.ticket_raised_by || user.name,
      ticket_type: ticket.ticket_type,
      ticket_query: ticket.ticket_query,
      ticket_category: ticket.ticket_category,
      ticket_subcategory: ticket.ticket_subcategory,
      flat: ticket.flat,
      area: ticket.area,
      landmark: ticket.landmark,
      pincode: ticket.pincode,
      town: ticket.town,
      ac_brand: ticket.ac_brand,
      model_number: ticket.model_number,
      date_of_purchase: ticket.date_of_purchase,
      ticket_remark: ticket.ticket_remark,
      ticket_image_one: ticket.ticket_image_one,
      ticket_image_two: ticket.ticket_image_two,
      ticket_video_one: ticket.ticket_video_one,
      ticket_video_two: ticket.ticket_video_two,
      ticket_assigned_to: ticket.ticket_assigned_to,
      timestamp: ticket.timestamp,
      status: ticket.status,
      user_email: user.email,
      user_mobile: user.mobile,
    }));

    res.send({ success: true, tickets: userTickets });
  } catch (error) {
    console.error("Error fetching user tickets:", error);
    res.send({ success: false, message: "Internal server error" });
  }
};


exports.create_ticket = async (req, res) => {
  try {
    // Extract and verify token
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.send({ success: false, message: "Token not provided" });
    }

    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ email: decodedToken.email });

    if (!user) {
      return res.send({ success: false, message: "Unauthorized access" });
    }

    if(user.role==3){
      return res.send({ success: false, message: "Unauthorized access" });
    }

    // Validate input
    const {
      query,
      category,
      subcategory,
      ticket_remark,
      ticket_image_one,
      ticket_image_two,
      ticket_video_one,
      ticket_video_two,
      flat,
      area,
      landmark,
      pincode,
      town,
      ac_brand,
      model_number,
      date_of_purchase
    } = req.body;
// console.log(req.body)
      if ( !query || !category || !subcategory || !flat || !area || !landmark || !pincode || !town || !ac_brand || !model_number ||
        !date_of_purchase) {
        return res.send({ success: false, message: "All required fields must be provided" });
      }

    // Generate a unique ticket ID
    const ticket_id = `TICKET-${Date.now()}`;

      var newTicket = ''
    if(user.role==1){
     newTicket = {
      ticket_id,
      ticket_raised_by: user.email,
      ticket_type:"By Admin",
      ticket_query:query,
      ticket_category:category,
      ticket_subcategory:subcategory,

      flat,
      area,
      landmark,
      pincode,
      town,
      ac_brand,
      model_number,
      date_of_purchase,

      ticket_remark: ticket_remark || "No remarks",
      ticket_image_one: ticket_image_one || null,
      ticket_image_two: ticket_image_two || null,
      ticket_video_one: ticket_video_one || null,
      ticket_video_two: ticket_video_two || null,
      ticket_assigned_to: "NA",
      timestamp: new Date(),
      status: "Created",
    };
  }
  else if(user.role==2){
     newTicket = {
      ticket_id,
      ticket_raised_by: user.email,
      ticket_type:"By Dealer",
      ticket_query,
      ticket_category,
      ticket_subcategory,

      flat,
      area,
      landmark,
      pincode,
      town,
      ac_brand,
      model_number,
      date_of_purchase,

      ticket_remark: ticket_remark || "No remarks",
      ticket_image_one: ticket_image_one || null,
      ticket_image_two: ticket_image_two || null,
      ticket_video_one: ticket_video_one || null,
      ticket_video_two: ticket_video_two || null,
      ticket_assigned_to: "NA",
      timestamp: new Date(),
      status: "Created",
    };
  }
  else{
     newTicket = {
      ticket_id,
      ticket_raised_by: user.email,
      ticket_type:"By User",
      ticket_query,
      ticket_category,
      ticket_subcategory,

      flat,
      area,
      landmark,
      pincode,
      town,
      ac_brand,
      model_number,
      date_of_purchase,

      ticket_remark: ticket_remark || "No remarks",
      ticket_image_one: ticket_image_one || null,
      ticket_image_two: ticket_image_two || null,
      ticket_video_one: ticket_video_one || null,
      ticket_video_two: ticket_video_two || null,
      ticket_assigned_to: "NA",
      timestamp: new Date(),
      status: "Created",
    };
  }

    // Push the ticket into the user's history
    user.ticket_history.push(newTicket);
    await user.save();

    res.send({
      success: true,
      message: "Ticket created successfully",
      ticket: newTicket,
    });
  } catch (error) {
    console.error("Error creating ticket:", error);
    res.send({ success: false, message: "Internal server error" });
  }
};

exports.create_technician = async (req, res) => {
  try {
    // Extract and verify token
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.send({ success: false, message: "Token not provided" });
    }
    
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const adminUser = await User.findOne({ email: decodedToken.email });

    if (!adminUser || adminUser.role !== 1) {
      return res.send({ success: false, message: "Unauthorized access" });
    }

    // Validate input
    const { name, mobile, email, password ,aadhar_number} = req.body;
    if (!name || !mobile || !email || !password || !aadhar_number) {
      return res.send({ success: false, message: "All fields are required" });
    }

    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.send({ success: false, message: "Email already registered" });
    }

    const temp_secret = speakeasy.generateSecret({ name: "Service" });
    const secret = temp_secret.ascii;
    const otpauth_url = temp_secret.otpauth_url;
    const tokenData = { email, password, mobile,remark:"Technician",role:3, name, aadhar_number, secret, otpauth_url };

    // Sign JWT token
    const tokenJWT = jwt.sign(tokenData, JWT_ACC_KEY, { expiresIn: '20m' });

    // Verify and save user
    jwt.verify(tokenJWT, JWT_ACC_KEY, async (err, decodedToken) => {
      if (err) {
        return res.send('Incorrect or Expired link.');
      }
      const user = new User(decodedToken);
      try {
        await user.save();
        user.salt = undefined;
        user.hashed_password = undefined;

        return res.send({
          success: true,
          message: "Technician created successfully",
          dealer: { name, mobile, email  },
        });
      } catch (err) {
        console.log(err)
          res.send({
          success: false,
          message: "Technician already exists"
        });      
      }
    });
  } catch (error) {
    console.error(error);
    res.send({ success: false, message: "Internal server error" });
  }
};


const verifyAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.send({ success: false, message: "Token not provided" });
    }
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const adminUser = await User.findOne({ email: decodedToken.email });
    if (!adminUser || adminUser.role !== 1) {
      return res.send({ success: false, message: "Unauthorized access" });
    }
    req.adminUser = adminUser;
    next();
  } catch (error) {
    res.send({ success: false, message: "Invalid token" });
  }
};

// API to list all available technicians
exports.get_all_technicians = [verifyAdmin, async (req, res) => {
  try {
    const technicians = await User.find({ role: 3 }, "name email mobile");
    res.send({ success: true, technicians });
  } catch (error) {
    res.send({ success: false, message: "Internal server error" });
  }
}];

// API to assign a ticket to a technician
exports.assign_ticket = [verifyAdmin, async (req, res) => {
  try {
    const { ticket_id, technician_email } = req.body;
    if (!ticket_id || !technician_email) {
      return res.send({ success: false, message: "Ticket ID and technician email are required" });
    }
    const technician = await User.findOne({ email: technician_email, role: 3 });
    if (!technician) {
      return res.send({ success: false, message: "Technician not found" });
    }
    const userWithTicket = await User.findOne({ "ticket_history.ticket_id": ticket_id });
    if (!userWithTicket) {
      return res.send({ success: false, message: "Ticket not found" });
    }
    await User.updateOne(
      { "ticket_history.ticket_id": ticket_id },
      { $set: { "ticket_history.$.ticket_assigned_to": technician_email, "ticket_history.$.status": "Assigned" } }
    );
    res.send({ success: true, message: "Ticket assigned successfully" });
  } catch (error) {
    res.send({ success: false, message: "Internal server error" });
  }
}];

// API to view assigned tickets
exports.get_assigned_tickets = [verifyAdmin, async (req, res) => {
  try {
    const assignedTickets = await User.aggregate([
      { $unwind: "$ticket_history" },
      { $match: { "ticket_history.ticket_assigned_to": { $ne: "NA" } } },
      {
        $project: {
          _id: 0,
          ticket_id: "$ticket_history.ticket_id",
          ticket_assigned_to: "$ticket_history.ticket_assigned_to",
          status: "$ticket_history.status",
          user_email: "$email",
          user_mobile: "$mobile",
        },
      },
    ]);
    res.send({ success: true, tickets: assignedTickets });
  } catch (error) {
    res.send({ success: false, message: "Internal server error" });
  }
}];
