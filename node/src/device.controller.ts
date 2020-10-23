import { default as express } from 'express';

export const router = express.Router();

router.post('/register', function (req, res) {
    console.log(req.body);
    res.send('registered');
});