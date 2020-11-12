import { fromBER } from 'asn1js';
import * as forge from 'node-forge';
import { IX509Cert } from './IX509Cert';


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

const expectedExtensions = [
    'subjectKeyIdentifier',
    'authorityKeyIdentifier',
    'basicConstraints',
    'keyUsage',
    'cRLDistributionPoints'
];

export const IX509CertFromPKICert = (cert: forge.pki.Certificate): IX509Cert => {

    // basic constraints
    //
    const basicConstraintsExt = cert.extensions.filter(it => it.name == 'basicConstraints')
    const ca = basicConstraintsExt.length > 0 && basicConstraintsExt[0].cA == true

    // key usage constraints
    //
    const keyUsageExt = cert.extensions.find(it => it.name == 'keyUsage');

    // name constraints
    //
    const nameConstraintsExt = cert.extensions.find(it => it.name == 'nameConstraints');
    // TODO nameConstraintsExt
    
    return {
        version: cert.version,
        serialNumber: cert.serialNumber,
        signature: Buffer.from(cert.signature).toString('hex').substring(0, 20) + '...',
        validity: {
            notBefore: cert.validity.notBefore,
            notAfter: cert.validity.notAfter
        },
        issuerDN: cert.issuer.attributes
            .map(attr => [attr.shortName, attr.value].filter(it => it != null).join('='))
            .join(', '),
        subjectDN: cert.subject.attributes
            .map(attr => [attr.shortName, attr.value].filter(it => it != null).join('='))
            .join(', '),
        sigAlgoOID: cert.siginfo.algorithmOid,
        extensions: cert.extensions
            .filter(it => !expectedExtensions.includes(it.name))
            .map(it => it.name),
        isCA: ca,
        keyUsage: {
            digitalSignature: keyUsageExt.digitalSignature,
            nonRepudiation: keyUsageExt.nonRepudiation,
            keyEncipherment: keyUsageExt.keyEncipherment,
            dataEncipherment: keyUsageExt.dataEncipherment,
            keyAgreement: keyUsageExt.keyAgreement,
            keyCertSign: keyUsageExt.keyCertSign,
            cRLSign: keyUsageExt.cRLSign,
            encipherOnly: keyUsageExt.encipherOnly,
            decipherOnly: keyUsageExt.decipherOnly,
        }
    }
}