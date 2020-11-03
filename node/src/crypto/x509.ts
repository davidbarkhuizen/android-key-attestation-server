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