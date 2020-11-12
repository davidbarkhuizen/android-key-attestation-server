import { default as express } from 'express';
import { attestationRouter  } from './attestation/attestation';

export const rootRouter = express.Router();

rootRouter.use('/attestation', attestationRouter);

rootRouter.get('/', function (req, res) {
  res.send('indrajala-fluid-server');
});