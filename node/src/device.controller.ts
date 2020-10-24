import { default as express } from 'express';
import * as forge from 'node-forge';

export const router = express.Router();

router.post('/register', function (req, res) {

    console.log('registering device...');
    
    console.log(req.body.asn1hex);

    // ---------------------------------------------------------------

    var certAsn1 = forge.asn1.fromDer(Buffer.from(req.body.asn1hex, 'hex').toString('binary'));
    var cert = forge.pki.certificateFromAsn1(certAsn1);

    const issuerCN = cert.issuer.getField('CN').value;
    const subjectCN = cert.subject.getField('CN').value;

    const description = [
        `issuer ${issuerCN}`, 
        `subject ${subjectCN}`, 
        `SN ${cert.serialNumber}`, 
        `valid: ${cert.validity.notBefore} - ${cert.validity.notAfter}`
    ];
    
    console.log(description.join('\n'));

    console.log(cert.subject.attributes);

    res.send('device registration incomplete - not yet implemented');
});