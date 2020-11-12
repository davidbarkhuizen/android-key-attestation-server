import * as forge from 'node-forge';

import { parseDER, authorizationListLookup } from '@indrajala/asn1der';
import { Algorithm, Digest, ECCurve, KeyOrigin, KeyPurpose, Padding, SecurityLevel, VerifiedBootState } from '../model/attestation/enums';
import { enumMap } from '../util';
import { IKeyDescriptionFromAsn1Node } from '../model/attestation/factory';

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

        const parsed = parseDER(asn1Seq)[0];

        const attAppIdNode = parsed.get('6.1.0');
        attAppIdNode.reparse();

        // DEV
        //
        // parsed // asn1.der
        //     .summary(4, authorizationListLookup)
        //     .forEach(line => console.log(line));

        const keyDescription = IKeyDescriptionFromAsn1Node(parsed);

        const stripped = JSON.parse(JSON.stringify(keyDescription));

        const describe = (o: any, indent = 0, enums: Map<string, Map<number, string>>) => {
            
            for(const key of Object.keys(o)) {
                const val = o[key];
                const valueType = typeof val;
                
                const isMapped = [...enums.keys()].includes(key); 

                let mappedVal = null;

                if (Array.isArray(val) && isMapped) {
                    const mappedVals = [];
                    for (const element of val as Array<any>) {
                        mappedVal = enums.get(key).get(element);
                        mappedVals.push(mappedVal);
                    }
                    console.log(`${' '.repeat(indent)}${key}: ${mappedVals}`);
                }
                else if (valueType == 'object') {
                    console.log(`${' '.repeat(indent)}${key}`);
                    describe(val, indent + 4, enums)
                } else {
                    
                    if (isMapped) {
                        mappedVal = enums.get(key).get(val);
                    }

                    const printVal = mappedVal ?? val;

                    console.log(`${' '.repeat(indent)}${key} ${printVal.toString()}`);

                }
            }
        };

        const enumMapLookup = new Map(
            [
                ['purpose', enumMap(KeyPurpose)],
                ['algorithm', enumMap(Algorithm)],
                ['digest', enumMap(Digest)],
                ['padding', enumMap(Padding)],
                ['ecCurve', enumMap(ECCurve)],
                ['origin', enumMap(KeyOrigin)],
                ['verifiedBootState', enumMap(VerifiedBootState)],
                ['attestationSecurityLevel', enumMap(SecurityLevel)],
                ['keymasterSecurityLevel', enumMap(SecurityLevel)],
            ]
        );

        // describe(stripped, 0, enumMapLookup);
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