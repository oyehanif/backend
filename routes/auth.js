const express = require('express');
const router = express.Router();
const {validateToken,getUser,
    blockUser,unBlockUser,signup,signin,signout,requireSignin,confirmotp,forgotPassword,resetPassword,AccChangePass,verifyTwoFA,
    enableTwoFA,disableTwoFA,create_dealer,create_ticket,get_all_tickets,create_technician,
    get_all_technicians,assign_ticket,get_assigned_tickets,get_user_tickets
} = require('../controllers/auth')
const {userSignUpValidator} = require('../validator');
const { upload } = require('../middleware');

router.get('/test',(req, res) =>{
    return res.send("testing")
})
router.post('/signup',userSignUpValidator , signup)
router.post('/signin', signin)
router.post('/confirmotp', confirmotp)
router.get('/signout', signout)
router.post('/forgotpassword', forgotPassword)
router.post('/resetpassword', resetPassword)
router.post('/AccChangePass', AccChangePass)
router.post('/verifyTwoFA', verifyTwoFA)
router.post('/enableTwoFA', enableTwoFA)
router.post('/disableTwoFA', disableTwoFA)
router.post('/blockUser', blockUser)
router.post('/unBlockUser', unBlockUser)
router.post('/getUser', getUser)
router.get('/validateToken', validateToken)

router.post('/create_dealer', create_dealer)
router.get('/get_all_tickets', get_all_tickets)
router.post('/create_ticket', create_ticket)
router.post('/create_technician', create_technician)
router.get('/get_all_technicians', get_all_technicians)
router.post('/assign_ticket', assign_ticket)
router.get('/get_assigned_tickets', get_assigned_tickets)
router.get('/get_user_tickets', get_user_tickets)

module.exports = router;