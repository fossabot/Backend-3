import { IUser, User } from "../../models/user/model";

process.env.NODE_ENV = 'testing';

import * as chai from 'chai';

const expect = chai.expect;

describe('Models User', function () {

  let userObject: IUser;

  const TEST_LOGIN = 'test';
  const TEST_EMAIL = 'test@metrostroi.org';
  const TEST_PASS = 'testpassword';
  const TEST_PASS_NEW = 'testpasswordnew';

  it('should insert new user', async function () {

    const user = new User();
    user.birthDate = new Date();
    user.name = 'Test';
    user.firstName = 'Test';
    user.lastName = 'Unit';
    user.login = TEST_LOGIN;
    user.email = TEST_EMAIL;
    user.password = TEST_PASS;
    user.create = new Date();

    const res = await user.save();
    userObject = res;

    expect(res).to.be.an('object');
    expect(res.login).to.be.equal(TEST_LOGIN);
  });

  it('should find by login', async function () {
    const user: IUser = await User.findLoginOrMail(TEST_LOGIN) as IUser;

    expect(user.email).to.be.equal(TEST_EMAIL);
    expect(user._id.toString()).to.be.equal(userObject._id.toString());
  });

  it('should update passwords', async function () {
    const user: IUser = await User.findById(userObject._id).exec() as IUser;
    expect(await user.comparePasswords(TEST_PASS)).to.be.equal(true);
    expect(await user.comparePasswords(TEST_PASS_NEW)).to.be.equal(false);

    user.password = TEST_PASS_NEW;
    await user.save();

    expect(await user.comparePasswords(TEST_PASS_NEW)).to.be.equal(true);
    expect(await user.comparePasswords(TEST_PASS)).to.be.equal(false);
  });

  it('should find by email', async function () {
    const user: IUser = await User.findLoginOrMail(TEST_EMAIL) as IUser;

    expect(user.email).to.be.equal(TEST_EMAIL);
    expect(user._id.toString()).to.be.equal(userObject._id.toString());
  });
});
