import { default as express } from 'express';
import { router as deviceRegistrationRouter } from './registration';

export const router = express.Router()
    .use('/registration', deviceRegistrationRouter);
