import { default as express } from 'express';
import { describeCert } from '../crypto/x509';

export const router = express.Router();

router.post('/register', function (req, res) {

    console.log('registering device...');
    
    console.log('device public key');
    console.log(req.body.asn1hex);
    console.log(req.body.attestationChain);

    describeCert('PUBLIC KEY', req.body.asn1hex);

    req.body.chain.forEach(function (value, i) {
        console.log('%d: %s', i, value);
    });
    
    console.log('CHAIN:')
    req.body.chain.forEach((cert, i) => {
        describeCert(`LINK ${i}`, cert)
    })

    // ---------------------------------------------------------------

    res.status(500).send('not yet implemented');
});