import * as forge from 'node-forge';
import { pki } from 'node-forge';

// OID: X509 Extension
//
// "2.5.29.1": "old Authority Key Identifier",
// "2.5.29.2": "old Primary Key Attributes",
// "2.5.29.3": "Certificate Policies",
// "2.5.29.4": "Primary Key Usage Restriction",
// "2.5.29.9": "Subject Directory Attributes",
// "2.5.29.14": "Subject Key Identifier",
// "2.5.29.15": "Key Usage",
// "2.5.29.16": "Private Key Usage Period",
// "2.5.29.17": "Subject Alternative Name",
// "2.5.29.18": "Issuer Alternative Name",
// "2.5.29.19": "Basic Constraints",
// "2.5.29.28": "Issuing Distribution Point",
// "2.5.29.29": "Certificate Issuer",
// "2.5.29.30": "Name Constraints",
// "2.5.29.31": "CRL Distribution Points",
// "2.5.29.32": "Certificate Policies",
// "2.5.29.33": "Policy Mappings",
// "2.5.29.35": "Authority Key Identifier",
// "2.5.29.36": "Policy Constraints",
// "2.5.29.37": "Extended key usage",
// "2.5.29.54": "X.509 version 3 certificate extension Inhibit Any-policy"

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

export const IX509CertFromPKICert = (cert: pki.Certificate): IX509Cert => {

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
    if (nameConstraintsExt) {
        console.log(nameConstraintsExt);
    }

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