exports.userSignUpValidator = (req,res,next)=>{
    const errors =req.validationErrors();
    if(errors){
        const firstError = errors.map(error => error.msg)[0];
        return res.status(400).json({error:firstError});
    }
    next();
}
