const Router = require('express').Router;
const userController = require('../controllers/user-controller');
const { body } = require('express-validator');

const router  = new Router();


router.post('/registration',
    body('email').isEmail(),
    body('password').isLength({min: 5, max: 24}),
    userController.registration);
router.post('/login', userController.login)
router.post('/reset-password', userController.resetPassword)
router.post('/forgot-password', userController.forgotPassword)
router.get('/activate/:link', userController.activate)
router.get('/users', userController.users)
router.get('/registration/google', userController.registrationGoogle)
router.get('/twitch/callback', userController.twitchCallback)
router.get('/twitch', userController.twitch)

router.get('/github/callback', userController.twitchCallback)
router.get('/github', userController.twitch)

module.exports = router;