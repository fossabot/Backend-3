process.env.NODE_ENV = 'testing';

import * as chai from 'chai';
import { server } from '../../app';
import chaiHttp = require('chai-http');

const expect = chai.expect;
chai.use(chaiHttp);

describe('Auth test', function (): void {

  const NAME = 'TestUser';
  const FIRST_NAME = 'TestUserName';
  const LAST_NAME = 'TestUserLastName';
  const LOGIN = 'TestLogin';
  const EMAIL = 'test@cscleague.org';
  const PASSWORD = 'testpassword';
  let token: string;

  it('should be able to create user', (done: Function): void => {
    chai.request(server)
      .post('/api/auth/signup')
      .set('content-type', 'application/json')
      .send({
        name: NAME,
        firstName: FIRST_NAME,
        lastName: LAST_NAME,
        login: LOGIN,
        email: EMAIL,
        password: PASSWORD,
      })
      .end((err: Error, res: any): void => {
        expect(res.statusCode).to.be.equal(200);
        token = res.body.access_token;
        done();
      });
  });

  it('should check returned after registration token', (done: Function): void => {
    chai.request(server)
      .post('/api/auth/refresh')
      .set('Authorization', 'Bearer ' + token)
      .end((err: Error, res: any): void => {
        token = res.body.access_token;
        expect(res.statusCode).to.be.equal(200);
        done();
      });
  });

  it('should check returned after refresh token', (done: Function): void => {
    chai.request(server)
      .post('/api/auth/refresh')
      .set('Authorization', 'Bearer ' + token)
      .end((err: Error, res: any): void => {
        token = res.body.access_token;
        expect(res.statusCode).to.be.equal(200);
        done();
      });
  });

  it('should authorize user by login', (done: Function): void => {
    chai.request(server)
      .post('/api/auth/login')
      .send({
        login: LOGIN,
        password: PASSWORD,
      })
      .end((err: Error, res: any): void => {
        expect(res.statusCode).to.be.equal(200);
        token = res.body.access_token;
        done();
      });
  });

  it('should check returned token', (done: Function): void => {
    chai.request(server)
      .post('/api/auth/refresh')
      .set('Authorization', 'Bearer ' + token)
      .end((err: Error, res: any): void => {
        expect(res.statusCode).to.be.equal(200);
        done();
      });
  });

  it('should authorize user by email', (done: Function): void => {
    chai.request(server)
      .post('/api/auth/login')
      .send({
        login: EMAIL,
        password: PASSWORD,
      })
      .end((err: Error, res: any): void => {
        expect(res.statusCode).to.be.equal(200);
        token = res.body.access_token;
        done();
      });
  });

  it('should check returned token', (done: Function): void => {
    chai.request(server)
      .post('/api/auth/refresh')
      .set('Authorization', 'Bearer ' + token)
      .end((err: Error, res: any): void => {
        expect(res.statusCode).to.be.equal(200);
        done();
      });
  });
});
