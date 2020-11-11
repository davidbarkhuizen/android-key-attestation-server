import * as forge from 'node-forge';

import { parseDER, authorizationListLookup } from '@indrajala/asn1der';
import { IKeyDescriptionFromAsn1Node, Padding } from '../model/attestation/att_schema_v3';
import { LocalConstructedValueBlock } from 'asn1js';

const OIDS = Object.freeze({
    GoogleAttestationExtension: '1.3.6.1.4.1.11129.2.1.17'
});

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

    // google key attestation
    //
    const attestationExt = cert.extensions.find(it => it.id == OIDS.GoogleAttestationExtension);
    if (attestationExt) {

        const asn1Seq = Buffer.from(attestationExt.value, 'ascii');
        console.log('asn1SeqHex', asn1Seq.toString('hex'));

        const parsed = parseDER(asn1Seq)[0];

        const attAppIdNode = parsed.get('6.1.0');
        //console.log(attAppIdNode.toString(authorizationListLookup));
        attAppIdNode.reparse();

        // DEV
        //
        parsed
            .summary(4, authorizationListLookup)
            .forEach(line => console.log(line));

        const keyDescription = IKeyDescriptionFromAsn1Node(parsed);
        console.log(JSON.stringify(keyDescription, null, 4));

        const stripped = JSON.parse(JSON.stringify(keyDescription));

        const describe = (o: any, indent = 0) => {
            for(const key of Object.keys(o)) {
                const val = o[key];
                const type = typeof val;
                
                if (type == 'object') {
                    console.log(`${' '.repeat(indent)}${key}`);
                    describe(val, indent + 4)
                } else {
                    console.log(`${' '.repeat(indent)}${key} ${val.toString()}`);
                }
            }
        };

        describe(stripped);   
        
        const handle = (o: any) => {
            for (const key of Object.keys(o)) {
                
                if (!isNaN(parseInt(key)))
                    console.log(key, typeof key, o[key]);
            }
        };
        
        handle(Padding);
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