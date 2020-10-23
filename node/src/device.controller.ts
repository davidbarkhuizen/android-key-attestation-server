import { default as express } from 'express';
import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';

export const router = express.Router();

router.post('/register', function (req, res) {

    console.log('registering device...');

    const raw = new Uint8Array(Buffer.from(req.body.asn1hex, 'hex')).buffer;

    const asn1 = asn1js.fromBER(raw);
    console.log('asn1', asn1);

    const certificate = new Certificate({ schema: asn1.result });
    console.log(certificate);

    res.send('registered!');
});