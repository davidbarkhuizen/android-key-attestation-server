import { default as express } from 'express';

export const router = express.Router();

router.get('/', function (req, res) {
  res.send('indrajala-fluid-server');
});