import * as forge from 'node-forge';

const expectedExtensions = [
    'subjectKeyIdentifier',
    'authorityKeyIdentifier',
    'basicConstraints',
    'keyUsage',
    'cRLDistributionPoints'
];

export interface IX509Cert {

    version: Number,
    serialNumber: string,
    signature: string,
    // siginfo: { algorithmOid: '1.2.840.113549.1.1.11', parameters: {} },
    sigAlgoOID: string
    validity: {
        notBefore: Date,
        notAfter: Date
      },
    issuerDN: string,
    subjectDN: string,
    extensions: Array<string>,
    isCA: boolean,
    keyUsage: {
        digitalSignature: boolean,
        nonRepudiation: boolean,
        keyEncipherment: boolean,
        dataEncipherment: boolean,
        keyAgreement: boolean,
        keyCertSign: boolean,
        cRLSign: boolean,
        encipherOnly: boolean,
        decipherOnly: boolean
    }   
}

export const describeCert = (label: string, hex: string) => {

    // var certAsn1 = forAsn1
    // console.log(description.join('\n'));
    
}

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