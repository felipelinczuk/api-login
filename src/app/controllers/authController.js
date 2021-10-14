const express = require('express')
const User = require('../models/User')
const router = express.Router();
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const authconfig = require('../../config/auth.json')
const crypto = require('crypto')
const mailer = require('../../modules/mailer.js')

function generateToken(params={}){
    return jwt.sign(params, authconfig.secret, {expiresIn: 86400});  
};

router.post('/register', async(req, res) => {
    const {email} = req.body
    console.log(email)
    try{
        if(await User.findOne({email}))
            return res.status(400).send({error: 'E-mail is already used'});

        const user = await User.create(req.body);
        user.password = undefined
        return res.send({user, token: generateToken({id: user.id})});
    }
    catch(err){
        console.log(err)
        return res.status(400).send({error: 'Registration failed'});
    }
});

router.post('/authenticate', async(req, res) => {
    const {email, password} = req.body
    const user = await User.findOne({email}).select('+password')

    if(!user)
        return res.status(400).send({error: 'User not found'});
    
    if(!await bcrypt.compare(password, user.password))
        return res.status(400).send({error: 'Invalid password'});

      
    user.password = undefined    
    res.send({user, token: generateToken({id: user.id})});
});

router.post('/forgot_password', async (req, res) => {
    const {email} = req.body

    try{
        const user = await User.findOne({email})

        if(!user)
            return res.status(400).send({error: 'User not found'})


        const token = crypto.randomBytes(20).toString('hex')
        const expires = new Date()

        expires.setHours(expires.getHours() + 1)

        await User.findByIdAndUpdate(user.id, {
            '$set': {
                passwordResetToken: token,
                passwordResetExpires: expires,
            }
        })

        mailer.sendMail({
            to: email,
            from: 'noreply-password@services.com',
            template: 'auth/forgot_password',
            context: {token}

        }, (err) => {
            if(err){
                console.log(err)
                return res.status(400).send({error: 'Cannot send reset password e-mail'});
            }   

            return res.send();
        })
        
    }
    catch(err){
        res.status(400).send({ error: `Error! Try again. Details: ${err}`})
    }
});

router.post('/reset_password', async(req, res) => {
    const {email, token, password} = req.body

    try{
        const user = await User.findOne({email})
            .select('+passwordResetToken passwordResetExpires')
        
        if(!user)
            return res.status(400).send({error: 'User not found'})

        if(token !== user.passwordResetToken)
            return res.status(400).send({error: 'Invalid token'})

        const now = new Date()

        if(now > user.passwordResetExpires)
            return res.status(400).send({error: 'Expired token'})


        user.password = password

        await user.save()
        res.send();
    }
    catch(err){
        return res.status(400).send({error: 'Cannot reset password'})
    }
});

module.exports = (app) => app.use('/auth', router);

