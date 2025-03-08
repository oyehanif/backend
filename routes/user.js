const express = require('express');
const router = express.Router();
const {requireSignin,isAuth,isAdmin} = require('../controllers/auth')


const {userById, allUsers , updateUser } = require('../controllers/user')

//admin can see all users data but needs to be signed in 
router.get("/userDataAll/:userId",requireSignin,isAuth,isAdmin, allUsers)

router.put("/userUpdate/:userId", updateUser)

//users can see only their data but needs to signed in
router.get("/userData/:userId",requireSignin,isAuth,(req,res)=>{
    res.json({
        user: req.profile
    })
})

router.param('userId',userById)


module.exports = router;