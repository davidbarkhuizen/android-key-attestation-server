import * as forge from 'node-forge';

export const describeCert = (label: string, hex: string) => {

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

export const pemFromDer = (hex: string) =>
    '-----BEGIN CERTIFICATE-----\n' 
    + (Buffer.from(hex, 'hex')).toString('base64').match(/.{0,64}/g).join('\n')
    + '-----END CERTIFICATE-----';

export const derFromPem = (pem: string) => {

    const b64 = pem
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace('\n', '');

    return Buffer.from(b64, 'base64').toString('hex');
}