export default class HttpError extends Error {
  public errorCode: number;
  constructor (message: string, code: number = 500) {
    super(message);
    this.errorCode = code;
  }
}
