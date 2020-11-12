import { default as express } from 'express';
import { keyRouter } from './key';

export const attestationRouter = express.Router()
    .use('/key', keyRouter);