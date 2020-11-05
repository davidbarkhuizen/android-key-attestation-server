import { default as express } from 'express';
import { router as deviceRegController } from './deviceRegistration';

export const router = express.Router();

router.use('/device-registration', deviceRegController);

router.get('/', function (req, res) {
  res.send('indrajala-fluid-server');
});