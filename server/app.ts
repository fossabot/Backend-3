import { json, urlencoded } from 'body-parser';
import * as express from 'express';
import * as expressJWT from 'express-jwt';
import * as http from 'http';
import * as path from 'path';

import { AuthRouter } from './routes/auth/auth';
import { UsersRouter } from './routes/users/users';
import { APIDocsRouter } from './routes/swagger';
import Config from '../config';
import HttpError from "./models/http-error";
import { NextFunction } from "express";

const app = express();

app.use(json());
app.use(urlencoded({
  extended: true,
}));

app.use(expressJWT({ secret: Buffer.from(Config.JWT, 'base64'), credentialsRequired: false }));

app.use('/api/auth', new AuthRouter().getRouter());
app.use('/api/users', new UsersRouter().getRouter());

if (process.env.NODE_ENV === 'development') {
  app.use('/api/docs/swagger', new APIDocsRouter().getRouter());
  app.use('/api/docs', express.static(path.join(__dirname, './assets/swagger')));
}

app.use((err: HttpError, request: express.Request, response: express.Response, next: NextFunction): void => {

  response.status(err.errorCode || 500);
  response.json({
    error: true,
    message: err.message || 'Internal server error',
  });
});

const server: http.Server = app.listen(process.env.PORT || 3000);

export { server };
