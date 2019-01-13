import { Request, Response, Router } from 'express';
import { IUser, User } from '../../models/user/model';
import * as express from "express";
import HttpError from "../../models/http-error";

/**
 * @swagger
 *
 * definitions:
 *   UserEdit:
 *     type: object
 *     required:
 *       - name
 *       - firstName
 *       - lastName
 *       - email
 *       - steamID
 *       - password
 *     properties:
 *       birthDate:
 *         type: string
 *         format: date
 *       name:
 *         type: string
 *       firstName:
 *         type: string
 *       lastName:
 *         type: string
 *       login:
 *         type: string
 *       email:
 *         type: string
 *       steamID:
 *         type: string
 *       create:
 *         type: string
 *         format: date
 *       lastLogin:
 *         type: string
 *         format: date
 *       note:
 *         type: string
 *   User:
 *     allOf:
 *       - type: object
 *         required:
 *           - id
 *           - login
 *           - permissions
 *         properties:
 *           id:
 *             type: string
 *           permissions:
 *             type: array
 *             items:
 *               type: string
 *           password:
 *             type: string
 *             format: password
 *       - $ref: '#/definitions/UserEdit'
 */
export class UsersRouter {

  private router: Router = Router();

  public getRouter(): Router {
    /**
     * @swagger
     * /api/users:
     *   get:
     *     tags:
     *      - Users
     *     description:
     *      List of all users registered in system.
     *     parameters:
     *       - name: limit
     *         in: query
     *         type: number
     *       - name: skip
     *         in: query
     *         type: number
     *       - name: page
     *         in: query
     *         type: number
     *       - name: name
     *         in: query
     *         type: string
     *       - name: steamID
     *         in: query
     *         type: string
     *     responses:
     *       200:
     *         schema:
     *           type: object
     *           properties:
     *             users:
     *               type: array
     *               description: Array of users
     *               items:
     *                 $ref: "#/definitions/User"
     *       default:
     *         $ref: "#/definitions/HttpError"
     */
    this.router.get('/', async (request: Request, response: Response) => {
      const limit: number = Math.min(100, (request.query.limit || 25));
      const skip: number = (Number(request.query.skip)  || ((Math.max(request.query.page || 1, 1) - 1) * limit) || 0);
      let projection = ['_id', 'name', 'firstName', 'lastName', 'steamID', 'create', 'birthDate'];
      const users: IUser[] = await User.find({
      }, projection).limit(limit).skip(skip).exec();

      response.json({ users });
    });

    /**
     * @swagger
     * /api/users/{id}:
     *   get:
     *     tags:
     *      - Users
     *     description:
     *      List of all users registered in system.
     *     parameters:
     *       - name: id
     *         in: path
     *         required: true
     *         type: string
     *     responses:
     *       200:
     *         schema:
     *           $ref: "#/definitions/User"
     *       default:
     *         $ref: "#/definitions/HttpError"
     */
    this.router.get('/:id', async (request: Request, response: Response, next: express.NextFunction) => {
      let projection = ['_id', 'name', 'firstName', 'lastName', 'steamID', 'create', 'birthDate'];
      let user;
      try {
        user = await User.findById(request.params.id, projection).exec();
      } catch (e) {
        next(new HttpError("NOT_FOUND", 404));
        return;
      }
      if (user == null) {
        next(new HttpError("NOT_FOUND", 404));
        return;
      }
      response.json(user);
    });

    return this.router;
  }
}
