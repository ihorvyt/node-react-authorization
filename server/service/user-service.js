const UserModel = require("../models/user-model");
const bcrypt = require("bcrypt");
const mailService = require("./mail-service");
const tokenService = require("./token-service");
const UserDto = require("../dto/user-dto");
const { v4: uuidv4 } = require('uuid');
const ApiError = require("../exceptions/api-error");
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const axios  = require('axios')
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

class UserService {
    async registration(username, email, password) {
        const candidate = await UserModel.findOne({email})
        if (candidate) {
            throw ApiError.BadRequest("User with this email already exists");
        }
        const hashPassword = bcrypt.hashSync(password, 3);
        const activationLink = uuidv4(); // ⇨ '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'
        const user = await UserModel.create({username, email, password: hashPassword, activationLink})
        await mailService.sendActivationMail(email, `${process.env.API_URL}/api/activate/${activationLink}`)

        const userDto = new UserDto(user)
        const tokens = tokenService.generateTokens({...userDto})
        await tokenService.saveToken(userDto.id, tokens.refreshToken)

        return {
            accessToken: tokens.accessToken
        }
    }

    async activate(activationLink){
        const user = await UserModel.findOne({activationLink})
        if (!user) {
            throw ApiError.BadRequest("This link doesn't exist");
        }
        user.isActivated = true

        await user.save()
    }

    async login(email, password) {
        const user = await UserModel.findOne({email})
        if (!user) {
            throw ApiError.BadRequest("User with this email doesn't exists");
        }
        const isPassEqual = await bcrypt.compareSync(password, user.password);
        if(!isPassEqual)    {
            throw ApiError.BadRequest("Password is not correct");
        }
        const userDto = new UserDto(user)
        const tokens = tokenService.generateTokens({...userDto})

        return {
            accessToken: tokens.accessToken
        }
    }

    async getAllUsers() {
        const users = await UserModel.find()
        return users
    }

    async verifyToken(token) {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const { email, name, picture }= ticket.getPayload();

        return {
            email,
            name,
            picture
        };
    }

    async registrationGoogle(payload) {
        try {
            const { email, name, picture } = payload;

            const candidate = await UserModel.findOne({email})

            if (candidate) {
                const userDto = new UserDto(candidate)
                const tokens = tokenService.generateTokens({...userDto})
                await tokenService.saveToken(userDto.id, tokens.refreshToken)

                return {
                    accessToken: tokens.accessToken
                }
            }

            const fakePassword = uuidv4(); // ⇨ '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'
            const hashPassword = bcrypt.hashSync(fakePassword, 3);
            const user = await UserModel.create({
                username: name,
                email,
                password: hashPassword,
                randomPasswordIsSet: true,
                picture: picture
            })

            const userDto = new UserDto(user)
            const tokens = tokenService.generateTokens({...userDto})
            await tokenService.saveToken(userDto.id, tokens.refreshToken)

            console.log(tokens.accessToken)

            return {
                accessToken: tokens.accessToken
            }
        } catch (e) {
            console.log(e)
        }
    }

    async resetPassword(email, password, link, token) {
        const candidate = await UserModel.findOne({email})
        if (!candidate) {
            throw ApiError.BadRequest('User with this email doesnt exist');
        }

        if (token) {
            const decoded = jwt.verify(token, process.env.JWT_ACCESS);
            if (decoded.email !== email) {
                throw ApiError.BadRequest('No permission to reset password');
            }
        }
        if (!token && candidate.forgotPasswordLink !== link) {
            throw ApiError.BadRequest('No permission to reset password');
        }

        candidate.password = bcrypt.hashSync(password, 3);

        candidate.save();
        return {'message': 'password was successfully reset'};
    }

    async forgotPassword(email) {
        const candidate = await UserModel.findOne({email})
        if (!candidate) {
            throw ApiError.BadRequest("User with this email doesn't exists");
        }
        const forgotPasswordLink = uuidv4(); // ⇨ '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'
        await mailService.sendResetPasswordMail(email, `${process.env.API_URL}/api/activate/${forgotPasswordLink}`)
        candidate.forgotPasswordLink = forgotPasswordLink;
        candidate.save()
        return {'message': 'reset password message was successfully sent'};
    }

    async twitchAuth(code) {
        try {
            const tokenResponse = await axios.post(`https://id.twitch.tv/oauth2/token`, null, {
                params: {
                    client_id: process.env.TWITCH_CLIENT_ID,
                    client_secret: process.env.TWITCH_CLIENT_SECRET,
                    code,
                    grant_type: 'authorization_code',
                    redirect_uri: process.env.TWITCH_REDIRECT_URI,
                }
            });

            const { access_token } = tokenResponse.data;

            const userResponse = await axios.get('https://api.twitch.tv/helix/users', {
                headers: {
                    'Authorization': `Bearer ${access_token}`,
                    'Client-ID': process.env.TWITCH_CLIENT_ID
                }
            });

            const { email, display_name, profile_image_url } = userResponse.data.data[0];

            const candidate = await UserModel.findOne({ email });
            if (candidate) {
                const userDto = new UserDto(candidate);
                const tokens = tokenService.generateTokens({ ...userDto });
                await tokenService.saveToken(userDto.id, tokens.refreshToken);
                return { accessToken: tokens.accessToken };
            }

            // Creating new User
            const fakePassword = uuidv4();
            const hashPassword = bcrypt.hashSync(fakePassword, 3);
            const user = await UserModel.create({
                username: display_name,
                email: email,
                password: hashPassword,
                randomPasswordIsSet: true,
                picture: profile_image_url
            });

            const userDto = new UserDto(user);
            const tokens = tokenService.generateTokens({ ...userDto });
            await tokenService.saveToken(userDto.id, tokens.refreshToken);

            return { accessToken: tokens.accessToken };
        } catch (error) {
            console.log(error);
            throw ApiError.BadRequest("Error during Twitch authentication");
        }
    }

    async githubAuth(code) {
        try {
            // Отримати токен доступу від GitHub
            const tokenResponse = await axios.post(`https://github.com/login/oauth/access_token`, null, {
                params: {
                    client_id: process.env.GITHUB_CLIENT_ID,
                    client_secret: process.env.GITHUB_CLIENT_SECRET,
                    code,
                },
                headers: {
                    'Accept': 'application/json',
                },
            });

            const { access_token } = tokenResponse.data;

            // Отримати інформацію про користувача
            const userResponse = await axios.get('https://api.github.com/user', {
                headers: {
                    'Authorization': `Bearer ${access_token}`,
                },
            });

            const { email, login, avatar_url } = userResponse.data;

            // Перевірте, чи користувач вже існує
            const candidate = await UserModel.findOne({ email });
            if (candidate) {
                const userDto = new UserDto(candidate);
                const tokens = tokenService.generateTokens({ ...userDto });
                await tokenService.saveToken(userDto.id, tokens.refreshToken);
                return { accessToken: tokens.accessToken };
            }

            // Створення нового користувача
            const fakePassword = uuidv4();
            const hashPassword = bcrypt.hashSync(fakePassword, 3);
            const user = await UserModel.create({
                username: login,
                email: email,
                password: hashPassword,
                randomPasswordIsSet: true,
                picture: avatar_url,
            });

            const userDto = new UserDto(user);
            const tokens = tokenService.generateTokens({ ...userDto });
            await tokenService.saveToken(userDto.id, tokens.refreshToken);

            return { accessToken: tokens.accessToken };
        } catch (error) {
            console.log(error);
            throw ApiError.BadRequest("Error during GitHub authentication");
        }
    }
}

module.exports = new UserService();


