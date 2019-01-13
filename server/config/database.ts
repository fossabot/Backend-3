import { Mockgoose } from 'mock-mongoose';
import * as mongoose from 'mongoose';

(mongoose as any).Promise = global.Promise;

if (process.env.NODE_ENV === 'testing') {

  const mockgoose = new Mockgoose(mongoose);
  mockgoose.helper.setDbVersion('3.4.3');

  mockgoose.prepareStorage().then((): void => {
    mongoose.connect('mongodb://127.0.0.1:27017/TestingSubwayRanksDB', { useNewUrlParser: true });
  });

} else {

  mongoose.connect('mongodb://127.0.0.1:27017/subwayranks', { useNewUrlParser: true });

}
mongoose.set('useCreateIndex', true);
export { mongoose };
