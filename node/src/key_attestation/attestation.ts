import { Validator } from 'jsonschema';
import { pki, asn1 } from 'node-forge';

import { promisify } from 'util';
import { randomBytes } from 'crypto';
const randomBytesAsync = promisify(randomBytes);

const { v4: uuidv4 } = require('uuid');

import { parseDER, authorizationListLookup } from '@indrajala/asn1der';
import { Algorithm, Digest, ECCurve, KeyOrigin, KeyPurpose, Padding, SecurityLevel, VerifiedBootState } from './model/google/enums';
import { enumMap } from '../general/util';
import { IKeyDescriptionFromAsn1Node } from './factory';

import { default as fetch } from 'node-fetch';
import { derFromPem, IX509CertFromPKICert, pemFromDer } from '../crypto/x509';
import { IKeyAttInitRsp } from '../api/attestation/rqrsp/IKeyAttInitRsp';
import { IMinimumDeviceRequirements } from './model/google/IMinimumDeviceRequirements';
import { IDeviceFingerprint } from './model/IDeviceFingerprint';

const crlSchema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
      "entries": {
        "description" : "Each entry represents the status of an attestation key. The dictionary-key is the certificate serial number in lowercase hex.",
        "type": "object",
        "propertyNames": {
           "pattern": "^[a-f0-9]*$"
        },
        "additionalProperties": {
          "type": "object",
          "properties": {
            "status": {
              "description": "[REQUIRED] Current status of the key.",
              "type": "string",
              "enum": ["REVOKED", "SUSPENDED"]
            },
            "expires": {
              "description": "[OPTIONAL] UTC date when certificate expires in ISO8601 format (YYYY-MM-DD). Can be used to clear expired certificates from the status list.",
              "type": "string",
              "format": "date"
            },
            "reason": {
              "description": "[OPTIONAL] Reason for the current status.",
              "type": "string",
              "enum": ["UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "SUPERSEDED", "SOFTWARE_FLAW"]
            },
            "comment": {
              "description": "[OPTIONAL] Free form comment about the key status.",
              "type": "string",
              "maxLength": 140
            }
          },
          "required": ["status"],
          "additionalProperties": false
        }
      }
    },
    "required": ["entries"],
    "additionalProperties": false
  };

export const fetchGoogleAttestationCRL = async (): Promise<Array<string>> => {

    const url = 'https://android.googleapis.com/attestation/status';

    const rsp = await fetch(url);
    const crl = await rsp.json();

    var v = new Validator();
    const validationResult = v.validate(crl, crlSchema);

    console.log(`valid: ${validationResult.valid}`);

    return Object
        .keys(crl.entries)
        .map(it => it.toUpperCase());
};

export const getAttestationExtension = (
    cert: pki.Certificate
) => {

    const GoogleAttestationExtensionOID = '1.3.6.1.4.1.11129.2.1.17';
    
    // google key attestation
    //
    const attestationExt = cert.extensions.find(it => it.id == GoogleAttestationExtensionOID);
    if (attestationExt) {

        const asn1Seq = Buffer.from(attestationExt.value, 'ascii');

        const parsed = parseDER(asn1Seq)[0];

        const attAppIdNode = parsed.get('6.#709.0');
        attAppIdNode.reparse();

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

        describe(stripped, 0, enumMapLookup);
    }
};

export const attestHardwareKey = async (
    challenge: String,
    certChainDER: Array<string>,
    validGoogleRootCertsDER: Array<string>,
): Promise<string> => {

    console.log('HW key attestation');

    const certChain = certChainDER
        .map(der => ({
            der,
            pki: pki.certificateFromAsn1(asn1.fromDer(Buffer.from(der, 'hex').toString('binary'))),
            pem: pemFromDer(der)
        }))
        .map(it => ({ ...it,
            ix509: IX509CertFromPKICert(it.pki)
        }));

    console.log(`${
        certChainDER.length} certs in chain: ${
        certChain.map(it => it.ix509.subjectDN).join(', ')}`);

    const rootCerts = certChain.filter(it => it.ix509.issuerDN == it.ix509.subjectDN);
    console.log(`${
        rootCerts.length} root certs(s): ${
        rootCerts.map(it => it.ix509.subjectDN).join(', ')}`);

    if (rootCerts.length == 0) {
        return 'no self-signed root cert';
    } else if (rootCerts.length > 1) {
        return 'too many root certs';
    }

    const rootCert = rootCerts[0];
    console.log(`root cert: ${rootCert.ix509.subjectDN}`);

    // verify self-signature of root cert
    //
    let rootSigVerified = false;
    try {
        const caStore = pki.createCaStore([ rootCert.pem ]);
        rootSigVerified = pki.verifyCertificateChain(caStore, [ rootCert.pki ]);
    } catch (e) {
        console.log(`error during verification of self-signature of root cert: ${e}`);
        return e.toString(e);
    }
    console.log(`${rootSigVerified ? 'verified' : 'failed to verify'} self-signature of 0 ${rootCert.ix509.subjectDN} root cert`)
    
    if (!rootSigVerified) {
        return `failed to verify self-signature of root cert ${rootCert.ix509.subjectDN}`;
    }

    // confirm root cert as known
    //
    const isKnownValidRootCert = validGoogleRootCertsDER.includes(rootCert.der);
    console.log(`root cert ${isKnownValidRootCert ? "is": "is not"} a known valid Google root HW attestation cert`);
    
    if (!isKnownValidRootCert) {
        return `root cert ${rootCert.ix509.subjectDN} is not a known valid Google root`;
    }

    const sortedChain = [rootCert];
    let nonRootCerts = certChain.filter(it => it != rootCert);

    // sort chain, verifying signatures
    //
    let childChainIndex = 0;
    while (sortedChain.length < certChain.length) {
        const parent = sortedChain[sortedChain.length - 1];
        const child = nonRootCerts.find(it => it.ix509.issuerDN == parent.ix509.subjectDN);
        childChainIndex = childChainIndex + 1;
        if (child === undefined) {
            const error = `break in chain: ${parent.ix509.subjectDN
                } has no child, yet ${nonRootCerts.length
                } unprocessed certs remain`;
            
            console.log(error);
            return error;
        }
        sortedChain.push(child);
        nonRootCerts = nonRootCerts.filter(it => it != child);

        // verify signature
        //
        let sigVerified = false;
        try {
            const caStore = pki.createCaStore([ parent.pem ]);
            sigVerified = pki.verifyCertificateChain(caStore, [ child.pki ]);
        } catch (e) {
            console.error(e);
            const error = `error during verification of signature of cert ${child.ix509.subjectDN} by ${parent.ix509.subjectDN}: ${e.toString()}`;
            console.log(error);
            return error;
        }

        console.log(`${sigVerified ? 'verified' : 'failed to verify'} ${childChainIndex} ${child.ix509.subjectDN} signed by ${childChainIndex - 1} ${parent.ix509.subjectDN}`)
    }

    // (double) check temporal validity of certs
    //
    const now = new Date();
    console.log(`checking temporal validity`);
    for(const cert of sortedChain) {

        const notBefore = cert.pki.validity.notBefore;
        if (notBefore > now) {
            const error = `cert ${cert.ix509.subjectDN} is not yet valid as of ${now} (not before ${notBefore})`;
            console.log(error);      
            return error;
        }

        const notAfter = cert.pki.validity.notAfter;
        if (notAfter < now) {
            const error = `cert ${cert.ix509.subjectDN} has already expired (not after ${notAfter})`;
            console.log(error);
            return error;
        }
    }
    console.log(`all certs are temporally valid as of ${now}`);
    
    // check against CRL

    const crl = await fetchGoogleAttestationCRL();
    console.log('checking against official Google CRL...');

    const revoked = sortedChain.filter(cert => 
        crl.includes(cert.ix509.subjectDN.toUpperCase())
    );

    if (revoked.length > 0) {
        
        const revokedSubjects = revoked
            .map(it => it.ix509.subjectDN)
            .join(', ');

        const error = `chain is invalid - it contains ${revoked.length} revoked cert(s): ${revokedSubjects}`;
        console.log(error);
        
        return error;
    }

    console.log('chain contains no known revoked certs');

    console.log('validated cert chain:');
    sortedChain.forEach((it, index) => {

        const usages = [];
        if (it.ix509.keyUsage.cRLSign) {
            usages.push('Sign CRL');
        }
        if (it.ix509.keyUsage.dataEncipherment) {
            usages.push('Enc Data');
        }
        if (it.ix509.keyUsage.decipherOnly) {
            usages.push('Only Dec Data');
        }
        if (it.ix509.keyUsage.digitalSignature) {
            usages.push('Sign Data');
        }
        if (it.ix509.keyUsage.encipherOnly) {
            usages.push('Only Enc Data');
        }
        if (it.ix509.keyUsage.keyAgreement) {
            usages.push('Key Agreement');
        }
        if (it.ix509.keyUsage.keyCertSign) {
            usages.push('Sign Key Cert');
        }
        if (it.ix509.keyUsage.nonRepudiation) {
            usages.push('Non Repudiation');
        }

        const remainingLifetimeMinutes = 
            Math.floor(
                (it.ix509.validity.notAfter.getTime() - (new Date()).getTime()) / 1000 / 60
            );

        console.log(`${index
        } ${it.ix509.isCA ? "(CA)": "    "
        } ${it.ix509.subjectDN.padEnd(25, ' ')
        } ${remainingLifetimeMinutes} mins - ${usages.join(', ')}, `);
    })

    const keyCert = sortedChain[sortedChain.length - 1];

    getAttestationExtension(keyCert.pki);

    return null;
};

export const initiateKeyAttestation = async (
    minDeviceReqs: IMinimumDeviceRequirements,
    deviceFingerprint: IDeviceFingerprint
): Promise<IKeyAttInitRsp> => {

    // TODO do not return response, controller method must do that
    // return InitKeyAttestationResult {
    //      succeeded: boolean;
    //      failureReason: KeyAttestationFailureReason;
    //      reference: string;
    // }

    // check min requirements (e.g. OS level) based on fingerprint
    //
    if (deviceFingerprint.apiLevel < minDeviceReqs.apiLevel) {
        console.log(`device os api level (${deviceFingerprint.apiLevel}) is not sufficient (${minDeviceReqs.apiLevel})`)
        return null
    }

    // create random challenge for hw key attestation
    //
    const challenge = await randomBytesAsync(8);
  
    // persist request with nonces, returning reg ID (not DB id)

    return {
        succeeded: true,
        reference: uuidv4(),
        keyParams: {
            challenge: challenge.toString('hex'),
            lifetimeMinutes: 60,
            digest: Digest.SHA_2_512,
            ecCurve: null,
            padding: Padding.RSA_PKCS1_1_5_ENCRYPT,
            purpose: KeyPurpose.Encrypt,
            rsaExponent: 65537,
            serialNumber: 1,
            sizeInBits: 2048
        }
    }
};

export const attestKey = async (
    minDeviceReqs: IMinimumDeviceRequirements,
    registrationID: string,
    hwAttestationKeyChain: Array<string>
) => {

    const keyAttestation = await attestHardwareKey(
        hwAttestationChallenge, 
        hwAttestationKeyChain,
        googleRootCertsPEM.map(pem => derFromPem(pem))
    );

    return {
        registered: false
    };
};