import { default as express } from 'express';
import * as forge from 'node-forge';

export const router = express.Router();

const describeCert = (label: string, hex: string) => {

    var certAsn1 = forge.asn1.fromDer(Buffer.from(hex, 'hex').toString('binary'));
    var cert = forge.pki.certificateFromAsn1(certAsn1);

    const issuerCN = cert.issuer.getField('CN')?.value ?? 'no issuer';
    
    const subjectCN = cert.subject.getField('CN')?.value ?? 'no subject';

    console.log(`CERT: ${label}`);

    const description = [
        `issuer ${issuerCN}`, 
        `subject ${subjectCN}`, 
        `SN ${cert.serialNumber}`, 
        `valid: ${cert.validity.notBefore} - ${cert.validity.notAfter}`
    ];
    
    console.log(description.join('\n'));
}

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