import { Document, Model, Schema } from 'mongoose';
import { mongoose } from '../../config/database';
import * as bcrypt from 'bcrypt';
import { authenticator } from 'otplib';
import { differenceInYears } from 'date-fns';
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
 *       - login
 *       - email
 *       - steamID
 *       - password
 *       - permissions
 *     properties:
 *       birthDate:
 *         type: date
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
 *       name:
 *         type: string
 *       steamID:
 *         type: string
 *         format: password
 *       password:
 *         type: string
 *       permissions:
 *         type: array
 *         items:
 *           type: string
 *       create:
 *         type: date
 *       lastLogin:
 *         type: date
 *       note:
 *         type: string
 *   User:
 *     allOf:
 *       - $ref: '#/definitions/UserEdit'
 *       - required:
 *         - id
 *       - properties:
 *         id:
 *           type: integer
 *           format: int64
 */
export interface IUser extends Document {
  birthDate?: Date;
  name: string;
  firstName: string;
  lastName: string;
  login: string;
  email: string;
  steamID: string;
  password: string;
  permissions: string[];
  otpSecret?: string;
  create?: Date;
  lastLogin?: Date;
  note?: string;
  comparePasswords(password: string): Promise<Boolean>;
  verifyOTP(password: string): boolean;
  checkOTPEnabled(): boolean;
  hasPermission(permission: string): boolean;
}

export interface IUserModel extends Model<IUser> {
  findLoginOrMail(login: string): Promise<IUser>;
}

const schema = new Schema({
  birthDate: {
    type: Date,
  },
  name: {
    type: String,
    required: true,
  },
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  login: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  steamID: {
    type: String,
  },
  password: {
    type: String,
    required: true,
  },
  permissions: [{
    type: String,
    required: true,
    default: ['authenticated']
  }],
  create: {
    type: Date,
    default: Date.now,
  },
  lastLogin: {
    type: Date,
    default: Date.now,
  },
  otpSecret: {
    type: String,
  },
  note: {
    type: String,
  },
});

schema.static('findLoginOrMail', (login: string) => {

  return User
    .findOne({
      $or: [
        { login },
        { email: login }
      ]
    })
    .exec();
});

schema.set('toJSON', {
  transform: function (doc: any, ret: any, options: any) {
    ret.id = ret._id;
    delete ret._id;
    delete ret.__v;
    if (ret.birthDate) {
      ret.age = -differenceInYears(ret.birthDate, new Date());
    }
  }
});

schema.pre('save', async function (next) {
  const self = this as IUser;
  if (!self.isModified('password')) {
    return next();
  }
  self.password = await bcrypt.hash(self.password, 8);
  return next();
});

schema.methods.comparePasswords = function (password: string) {
  const self = this as IUser;
  return bcrypt.compare(password, self.password);
};

schema.methods.verifyOTP = function (password: string) {
  const self = this as IUser;
  if (!self.hasPermission('otpEnabled') || self.otpSecret === undefined) {
    return true;
  }
  return authenticator.verify({ token: password, secret: self.otpSecret });
};

schema.methods.checkOTPEnabled = function () {
  const self = this as IUser;
  return self.hasPermission('otpEnabled') && self.otpSecret !== undefined;
};

schema.methods.hasPermission = function (permission: string) {
  const self = this as IUser;
  return self.permissions.some(p => p === permission || (p === '*' && !/^otp/.test(permission)));
};

export const User = mongoose.model<IUser>('User', schema) as IUserModel;
