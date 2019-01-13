import { Request, Response, Router } from 'express';
import * as moment from 'moment';
import Axios from 'axios';
import * as jwt from 'jsonwebtoken';
import { IUser, User } from "../../models/user/model";
import Config from '../../../config';
import * as Validator from 'validator';
import * as express from "express";
import HttpError from "../../models/http-error";
import { authenticator } from 'otplib';
import * as QRCode from 'qrcode';

function createJWT(user: IUser, otpPassed: Boolean = false) {
  let payload = {
    id: user._id,
    otpPassed,
    iat: moment().unix(),
    exp: moment().add(14, 'days').unix()
  };
  return jwt.sign(payload, Buffer.from(Config.JWT, 'base64'));
}

export class AuthRouter {

  private router: Router = Router();

  public getRouter(): Router {

    /**
     * @swagger
     * /api/auth/signup:
     *   post:
     *     tags:
     *      - Authentication
     *     description:
     *      Creates a new account
     *     parameters:
     *       - in: body
     *         description: The user to create.
     *         schema:
     *           type: object
     *           required:
     *             - name
     *             - firstName
     *             - lastName
     *             - login
     *             - email
     *             - password
     *           properties:
     *             name:
     *               type: string
     *             firstName:
     *               type: string
     *             lastName:
     *               type: string
     *             login:
     *               type: string
     *             email:
     *               type: string
     *             password:
     *               type: string
     *               format: password
     *     responses:
     *       200:
     *         description: OK
     *         schema:
     *           type: object
     *           properties:
     *             access_token:
     *               type: string
     *               description: JWT Access Token
     *       default:
     *         $ref: "#/definitions/HttpError"
     */
    this.router.post('/signup', async (request: Request, response: Response, next: express.NextFunction) => {
      if (request.user != null) {
        next(new HttpError('NOT_GUEST', 409));
        return;
      }

      if (
        !request.body.name ||
        !request.body.firstName ||
        !request.body.lastName ||
        !request.body.login ||
        !request.body.email ||
        !request.body.password
      ) {
        next(new HttpError('INCOMPLETE_REQUEST', 400));
        return;
      }

      if (!Validator.isEmail(request.body.email)) {
        next(new HttpError('INVALID_EMAIL', 400));
        return;
      }
      if (!Validator.isAlphanumeric(request.body.login)) {
        next(new HttpError('INVALID_LOGIN', 400));
        return;
      }
      if (!/^[a-zA-Zа-яА-ЯёЁйЙÀ-ž]+$/.exec(request.body.firstName) || !/^[a-zA-Zа-яА-ЯёЁйЙÀ-ž]+$/.exec(request.body.lastName)) {
        next(new HttpError('INVALID_REAL_NAME', 400));
        return;
      }
      if (!/^[a-zA-Z 0-9]+$/.exec(request.body.name)) {
        next(new HttpError('INVALID_USER_NAME', 400));
        return;
      }

      if (await User.findLoginOrMail(request.body.login)) {
        next(new HttpError('LOGIN_ALREADY_TAKEN', 400));
        return;
      }
      if (await User.findLoginOrMail(Validator.normalizeEmail(request.body.email) || '')) {
        next(new HttpError('EMAIL_ALREADY_TAKEN', 400));
        return;
      }

      let user = new User();
      user.name = request.body.name;
      user.firstName = request.body.firstName;
      user.lastName = request.body.lastName;
      user.login = request.body.login;
      user.email = Validator.normalizeEmail(request.body.email) || '';
      user.password = request.body.password;
      user.permissions = ['authenticated'];
      await user.save();

      let token = createJWT(user);
      response.send({access_token: token});
    });

    /**
     * @swagger
     * /api/auth/login:
     *   post:
     *     tags:
     *      - Authentication
     *     description:
     *      Authenticates with login and password
     *     parameters:
     *       - in: body
     *         description: User's credentials.
     *         schema:
     *           type: object
     *           required:
     *             - login
     *             - password
     *           properties:
     *             login:
     *               type: string
     *               description: E-Mail or Login
     *             password:
     *               type: string
     *               format: password
     *     responses:
     *       200:
     *         description: OK
     *         schema:
     *           type: object
     *           properties:
     *             access_token:
     *               type: string
     *               description: JWT Access Token
     *       default:
     *         $ref: "#/definitions/HttpError"
     */
    this.router.post('/login', async (request: Request, response: Response, next: express.NextFunction) => {
      if (request.user != null) {
        next(new HttpError('NOT_GUEST', 409));
        return;
      }

      let user = await User.findLoginOrMail(request.body.login);
      if (user === null) {
        next(new HttpError('UNKNOWN_ACCOUNT', 400));
        return;
      }
      if (!await user.comparePasswords(request.body.password)) {
        next(new HttpError('WRONG_PASSWORD', 400));
        return;
      }
      let token = createJWT(user);
      response.send({access_token: token});
    });

    /**
     * @swagger
     * /api/auth/steam:
     *   post:
     *     tags:
     *      - Authentication
     *     description:
     *      Authenticates with Steam's OpenID 2 response
     *     parameters:
     *       - in: body
     *         description: OpenID 2 parameters + id property
     *         schema:
     *           type: object
     *     responses:
     *       200:
     *         description: OK
     *         schema:
     *           type: object
     *           properties:
     *             access_token:
     *               type: string
     *               description: JWT Access Token
     *       default:
     *         $ref: "#/definitions/HttpError"
     */
    this.router.post('/steam', async (request: Request, response: Response, next: express.NextFunction) => {
      let params = Object.assign({
        'openid.mode': 'check_authentication',
      }, request.body);
      params.id = undefined;
      params['openid.mode'] = 'check_authentication';
      let result = await Axios.get('https://steamcommunity.com/openid/login', {
        params,
        responseType: 'text'
      });
      if (!/is_valid:true/.test(result.data)) {
        next(new HttpError('Wrong sign', 400));
        return;
      }

      if (request.user != null) {
        let user = await User.findById(request.user.id).exec();
        if (user == null) {
          next(new Error('Logged in as unknown user'));
        return;
        }
        if (request.user.otpPassed !== true && user.checkOTPEnabled()) {
          next(new HttpError('You should pass OTP check', 403));
        return;
        }
        user.steamID = request.body['openid.identity'].split('/').pop();
        let token = createJWT(user, true);
        response.send({access_token: token});
        await user.save();
        return;
      }

      let user = await User.findOne({ steamID: request.body['openid.identity'].split('/').pop() }).exec();
      if (user === null) {
        next(new HttpError('Unknown account', 400));
        return;
      }
      let token = createJWT(user);
      response.send({access_token: token});
    });

    /**
     * @swagger
     * /api/auth/refresh:
     *   post:
     *     tags:
     *      - Authentication
     *     description:
     *      Refreshes JWT token
     *     security:
     *       - JWT
     *     parameters:
     *       - in: body
     *         schema:
     *           type: object
     *           properties:
     *             otp:
     *               type: string
     *               description: Non-required OTP code (if submitted, otpPassed will be true), else "as was"
     *     responses:
     *       200:
     *         description: OK
     *         schema:
     *           type: object
     *           properties:
     *             access_token:
     *               type: string
     *               description: JWT Access Token
     *             permissions:
     *               description: Array of permissions
     *               type: array
     *               items:
     *                 type: string
     *       400:
     *         description: Bad request
     *         schema:
     *           type: object
     *           properties:
     *             message:
     *               type: string
     *               description: Error message
     *             permissions:
     *               description: Array of permissions (typically ['guest'] in this case)
     *               type: array
     *               items:
     *                 type: string
     *       401:
     *         description: Unauthorised
     *         schema:
     *           type: object
     *           properties:
     *             message:
     *               type: string
     *               description: Error message
     *             permissions:
     *               description: Array of permissions (typically ['guest'] in this case)
     *               type: array
     *               items:
     *                 type: string
     *       default:
     *         description: An error occurred
     *         $ref: "#/definitions/HttpError"
     */

    this.router.post('/refresh', async function (request: Request, response: Response) {
      function error(message: string, code: number = 500): void {
        response.status(code);
        response.json({
          message: message,
          permissions: ['guest']
        });
      }
      if (!request.user) {
        error('You must be signed in', 401);
        return;
      }
      let user: IUser|null = await User.findById(request.user.id).exec();
      if (user === null) {
        error('Unknown account', 400);
        return;
      }
      if (request.body.otp && user.verifyOTP(request.body.otp)) {
        request.user.otpPassed = true;
      }
      if (user.checkOTPEnabled()) {
        user.permissions.push(request.user.otpPassed ? 'otpPassed' : 'otpRequired');
      }
      let token = createJWT(user, request.user.otpPassed);
      response.send({access_token: token, permissions: user.permissions });
    });

    /**
     * @swagger
     * /api/auth/me:
     *   get:
     *     tags:
     *      - Authentication
     *     description:
     *      Refreshes JWT token
     *     security:
     *       - JWT
     *     parameters:
     *       - in: body
     *         schema:
     *           type: object
     *           properties:
     *             otp:
     *               type: string
     *               description: Non-required OTP code (if submitted, otpPassed will be true), else "as was"
     *     responses:
     *       200:
     *         description: OK
     *         schema:
     *           type: object
     *           properties:
     *             access_token:
     *               type: string
     *               description: JWT Access Token
     *             permissions:
     *               description: Array of permissions
     *               type: array
     *               items:
     *                 type: string
     *       400:
     *         description: Bad request
     *         schema:
     *           $ref: "#/definitions/User"
     *       401:
     *         description: Unauthorised
     *         schema:
     *           type: object
     *           properties:
     *             message:
     *               type: string
     *               description: Error message
     *             permissions:
     *               description: Array of permissions (typically ['guest'] in this case)
     *               type: array
     *               items:
     *                 type: string
     *       default:
     *         description: An error occurred
     *         $ref: "#/definitions/HttpError"
     */

    this.router.get('/me', async function (request: Request, response: Response) {
      function error(message: string, code: number = 500): void {
        response.status(code);
        response.json({
          message: message,
          permissions: ['guest']
        });
      }
      if (!request.user) {
        error('You must be signed in', 401);
        return;
      }
      let user = await User.findById(request.user.id, [
        '_id',
        'birthDate',
        'firstName',
        'lastName',
        'create',
        'lastLogin',
        'login',
        'email',
        'name',
        'steamID'
      ]).exec();
      if (user === null) {
        error('Unknown account', 400);
        return;
      }
      response.send({ user });
    });

    /**
     * @swagger
     * /api/auth/me:
     *   put:
     *     tags:
     *      - Authentication
     *     description:
     *      Refreshes JWT token
     *     security:
     *       - JWT
     *     parameters:
     *       - in: body
     *         schema:
     *           $ref: "#/definitions/UserEdit"
     *     responses:
     *       200:
     *         description: OK
     *         schema:
     *           $ref: "#/definitions/User"
     *       400:
     *         description: Bad request
     *         schema:
     *           type: object
     *           properties:
     *             message:
     *               type: string
     *               description: Error message
     *             permissions:
     *               description: Array of permissions (typically ['guest'] in this case)
     *               type: array
     *               items:
     *                 type: string
     *       401:
     *         description: Unauthorised
     *         schema:
     *           type: object
     *           properties:
     *             message:
     *               type: string
     *               description: Error message
     *             permissions:
     *               description: Array of permissions (typically ['guest'] in this case)
     *               type: array
     *               items:
     *                 type: string
     *       default:
     *         description: An error occurred
     *         $ref: "#/definitions/HttpError"
     */

    this.router.put('/me', async function (request: Request, response: Response) {
      function error(message: string, code: number = 500): void {
        response.status(code);
        response.json({
          message: message,
          permissions: ['guest']
        });
      }
      if (!request.user) {
        error('You must be signed in', 401);
        return;
      }
      let user = await User.findById(request.user.id, [
        '_id',
        'birthDate',
        'firstName',
        'lastName',
        'create',
        'lastLogin',
        'login',
        'email',
        'name',
        'steamID'
      ]).exec();
      if (user === null) {
        error('Unknown account', 400);
        return;
      }
      let params: {[key: string]: ((s: string) => boolean)} = {
        birthDate: (s: string) => Validator.toDate(s) !== null,
        firstName: (s: string) => /^[a-zA-Zа-яА-ЯёЁйЙÀ-ž]+$/.exec(s) !== null,
        lastName: (s: string) => /^[a-zA-Zа-яА-ЯёЁйЙÀ-ž]+$/.exec(s) !== null,
        email: (s: string) => Validator.isEmail(s),
        name: (s: string) => /^[a-zA-Z 0-9]+$/.exec(s) !== null
      };
      Object.keys(params).forEach((p: string) => {
        if (request.body[p] !== undefined && params[p](request.body[p])) {
          // @ts-ignore
          user[p] = request.body[p];
        }
      });
      if (typeof request.body.password === 'string' &&
        typeof request.body.newPassword === 'string' &&
        user.comparePasswords(request.body.password)) {
        user.password = request.body.newPassword;
      }
      response.send({ user });
      await user.save();
    });

    /**
     * @swagger
     * /api/auth/otp:
     *   post:
     *     tags:
     *      - Authentication
     *     description:
     *      Returns Base64-encoded QR-code for Google Authenticator
     *     security:
     *       - JWT
     *     parameters:
     *       - in: body
     *         schema:
     *           type: object
     *           required:
     *             - otp
     *           properties:
     *             otp:
     *               type: string
     *               description: OTP code. Required if OTP already enabled
     *     responses:
     *       200:
     *         description: OK
     *         schema:
     *           type: object
     *           properties:
     *             success:
     *               type: boolean
     *               description: Should be true
     *       default:
     *         $ref: "#/definitions/HttpError"
     */

    this.router.post('/otp', async function (request: Request, response: Response, next: express.NextFunction) {
      if (!request.user) {
        next(new HttpError('UNAUTHORISED', 401));
        return;
      }
      if (!request.body.otp) {
        next(new HttpError('OTP_NOT_SUBMITTED', 400));
        return;
      }
      let user: IUser|null = await User.findById(request.user.id).exec();
      if (user === null) {
        next(new HttpError('UNKNOWN_ACCOUNT', 400));
        return;
      }
      if (!user.checkOTPEnabled()) {
        if (!user.otpSecret) {
          next(new HttpError('SECRET_NOT_SET', 500));
          return;
        }
        if (!authenticator.check(request.body.otp, user.otpSecret)) {
          next(new HttpError('OTP_INVALID', 400));
          return;
        }
        user.permissions.push('otpEnabled');
        await user.save();
      }
      if (!user.verifyOTP(request.body.otp)) {
        next(new HttpError('OTP_INVALID', 400));
        return;
      }
      response.send({ success: true });
    });

    /**
     * @swagger
     * /api/auth/otp:
     *   delete:
     *     tags:
     *      - Authentication
     *     description:
     *      Removes OTP from account
     *     security:
     *       - JWT
     *     parameters:
     *       - in: query
     *         name: otp
     *         type: string
     *         description: OTP code. Required if OTP already enabled
     *     responses:
     *       200:
     *         description: OK
     *         schema:
     *           type: object
     *           properties:
     *             success:
     *               type: boolean
     *               description: Should be true
     *       default:
     *         $ref: "#/definitions/HttpError"
     */

    this.router.delete('/otp', async function (request: Request, response: Response, next: express.NextFunction) {
      if (!request.user) {
        next(new HttpError('UNAUTHORISED', 401));
        return;
      }
      if (!request.query.otp) {
        next(new HttpError('OTP_NOT_SUBMITTED', 400));
        return;
      }
      let user: IUser|null = await User.findById(request.user.id).exec();
      if (user === null) {
        next(new HttpError('UNKNOWN_ACCOUNT', 400));
        return;
      }
      if (!user.checkOTPEnabled()) {
        next(new HttpError('OTP_NOT_ENABLED', 400));
        return;
      }
      if (!user.verifyOTP(request.query.otp)) {
        next(new HttpError('OTP_INVALID', 400));
        return;
      }
      user.permissions.splice(user.permissions.indexOf('otpEnabled'), 1);
      await user.save();
      response.send({ success: true });
    });

    /**
     * @swagger
     * /api/auth/otp/qr:
     *   post:
     *     tags:
     *      - Authentication
     *     description:
     *      Returns Base64-encoded QR-code for Google Authenticator
     *     security:
     *       - JWT
     *     parameters:
     *       - in: body
     *         schema:
     *           type: object
     *           properties:
     *             otp:
     *               type: string
     *               description: OTP code. Required if OTP already enabled
     *     responses:
     *       200:
     *         description: OK
     *         schema:
     *           type: object
     *           properties:
     *             image:
     *               type: string
     *               description: Base64-encoded QR-code image for Google Authenticator
     *       default:
     *         $ref: "#/definitions/HttpError"
     */

    this.router.post('/otp/qr', async function (request: Request, response: Response, next: express.NextFunction) {
      if (!request.user) {
        next(new HttpError('UNAUTHORISED', 401));
        return;
      }
      let user: IUser|null = await User.findById(request.user.id).exec();
      if (user === null) {
        next(new HttpError('UNKNOWN_ACCOUNT', 400));
        return;
      }
      if (user.checkOTPEnabled() && !request.body.otp) {
        next(new HttpError('OTP_NOT_SUBMITTED', 400));
        return;
      }
      if (user.checkOTPEnabled() &&  !user.verifyOTP(request.body.otp)) {
        next(new HttpError('OTP_INVALID', 400));
        return;
      }
      if (!user.checkOTPEnabled()) {
        user.otpSecret = authenticator.generateSecret();
        await user.save();
      }
      response.send({ image: await QRCode.toDataURL(authenticator.keyuri(user.login, 'SubwayRanks', user.otpSecret || '')) });
    });

    /**
     * @swagger
     * /api/auth/signout:
     *   post:
     *     tags:
     *      - Authentication
     *     description:
     *      Doing nothing
     *     security:
     *       - JWT
     *     responses:
     *       200:
     *         description: OK
     *         schema:
     *           type: object
     *           properties:
     *             message:
     *               type: string
     *               description: Goodbye!
     */

    this.router.post('/signout', function (request: Request, response: Response) {
      response.send({message: 'Goodbye!'});
    });

    return this.router;
  }
}
