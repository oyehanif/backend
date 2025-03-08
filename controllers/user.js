const User = require('../models/user')
const _ = require('lodash');
const axios = require('axios')
const nodemailer = require("nodemailer");

exports.userById=(req,res,next,id)=>{
    User.findById(id).exec((err,user)=>{
        if(err || !user){
            return res.status(400).json({
                error:"user not found"
            })
        }
        req.profile = user;
        next();
    });
}

exports.allUsers = (req,res)=>{
    User.find((err,users)=>{
        if(err){
            return res.status(400).json({
                error:err
            })
        }  
            res.json({users})
    })
};


exports.updateUser = (req, res) => { 
    let user = req.profile
    user = _.extend(user, req.body)
    user.updated = Date.now()
    user.save((err) => {
        if(err) {
            return res.status(400).json({
                error : "not authorized to perform this action"
            })
        }
        user.hashed_password = undefined;
        user.salt = undefined;
        res.json({user})
    })
}
