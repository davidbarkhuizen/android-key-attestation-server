import { default as express } from 'express';
import { IDevRegInitRq, IDevRegInitRsp } from '../../model/device';
// import { describeCert } from '../../crypto/x509';

export const router = express.Router();

let registrationID = 0;
let challenge: string = '';
let keySizeBits: 2048;

let keyLifeTimeMinutes = 24 * 60;

router.post('/intent', function (req, res) {

    const rq = req.body as IDevRegInitRq;

    registrationID = registrationID + 1;

    const challenge = '';
    
    res.status(200).json({
        registrationID: registrationID.toString(),
        keyAttestationChallenge: challenge,
        keyLifeTimeMinutes,
        keySizeBits,
        keySN: registrationID
    });
});

router.post('/execute', function (req, res) {

    const rq = req.body as IDevRegInitRq;

    console.log(rq);

    res.status(500).send('not yet implemented');
});