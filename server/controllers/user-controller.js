const userService = require('../service/user-service');
const {validationResult} = require('express-validator')
const ApiError = require("../exceptions/api-error");

class UserController {
    async registration(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return next(ApiError.BadRequest('Validation failed'), errors.array());
            }
            const {username, email, password} = req.body;
            const userData = await userService.registration(username, email, password);
            res.cookie('refreshToken', userData.refreshToken, {maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true});

            return res.json(userData);
        } catch (e) {
            next(e)
        }
    }

    async login(req, res, next) {
        try {
            const {email, password} = req.body;
            const userData = await userService.login(email, password);

            res.cookie('refreshToken', userData.refreshToken, {maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true});

            return res.json(userData);
        } catch (e) {
            next(e)
        }
    }

    async activate(req, res, next) {
        try {
            const activationLink = req.params.link;
            await userService.activate(activationLink);
            return res.redirect(process.env.CLIENT_URL);
        } catch (e) {
            next(e)
        }
    }

    async users(req, res, next) {
        try {
            const users = await userService.getAllUsers()
            return res.json(users);
        } catch (e) {
            next(e)
        }
    }

    async registrationGoogle(req, res, next) {
        const { token } = req.body;
        try {
            const userInfo = await userService.verifyToken(token);
            const registration = await userService.registrationGoogle(userInfo);


            res.status(200).json(registration);
        } catch (e) {
            next(e)
        }
    }

    async resetPassword(req, res, next) {
        try {
            const {email, password, link} = req.body;
            const token = req.headers['authorization'].split(' ')[1];

            const resetPassword = await userService.resetPassword(email, password, link, token);
            return res.json(resetPassword);
        } catch (e) {
            next(e)
        }
    }

    async forgotPassword(req, res, next) {
        try {
            const {email} = req.body;
            const forgotPassword = await userService.forgotPassword(email);
            return res.json(forgotPassword);
        } catch (e) {
            next(e)
        }
    }

    async twitch(req, res) {
        const redirectUri = `https://id.twitch.tv/oauth2/authorize?client_id=${process.env.TWITCH_CLIENT_ID}&redirect_uri=${process.env.TWITCH_REDIRECT_URI}&response_type=code&scope=user:read:email`;
        res.redirect(redirectUri);
    }

    async twitchCallback(req, res, next) {
        try {
            const { code } = req.query;
            const data = await userService.twitchAuth(code);


            res.redirect('http://localhost:5173');
        } catch (e) {
            next(e)
        }
    }
}

module.exports = new UserController();