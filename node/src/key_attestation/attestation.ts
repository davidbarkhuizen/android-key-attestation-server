import { Validator } from 'jsonschema';
import { pki, asn1 } from 'node-forge';

import { promisify } from 'util';
import { randomBytes } from 'crypto';
const randomBytesAsync = promisify(randomBytes);

import { v4 } from 'uuid';

import { parseDER } from '@indrajala/asn1der';
import { Algorithm, Digest, ECCurve, KeyOrigin, KeyPurpose, Padding, SecurityLevel, VerifiedBootState } from './model/google/enums';
import { enumMap } from '../general/util';
import { IKeyDescriptionFromAsn1Node } from './factory';

import { default as fetch } from 'node-fetch';
import { derFromPem, IX509CertFromPKICert, pemFromDer } from '../crypto/x509';
import { IDeviceFingerprint } from './model/IDeviceFingerprint';
import { IInitKeyAttestationResult } from './model/IInitKeyAttestationResult';
import { KeyAttestationFailureReason } from './model/KeyAttestationFailureReason';
import { InitKeyAttestationFailureReason } from './model/InitKeyAttestationFailureReason';
import { IKeyAttestationRecord } from '../dal/model/IKeyAttestationRecord';
import { getGoogleKeyAttestationRootCertsPEM, getKeyAttRecordForReference, setKeyAttRecord } from '../dal/dal';
import { IKeyAttestationResult } from './model/IKeyAttestationResult';

// TODO get from repo
const minDeviceReqs = {
    apiLevel: 28
};

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

    const v = new Validator();
    const validationResult = v.validate(crl, crlSchema);

    console.log(`valid: ${validationResult.valid}`);

    return Object
        .keys(crl.entries)
        .map(it => it.toUpperCase());
};

export const getAttestationExtension = (
    cert: pki.Certificate
): void => {

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

        const describe = (o: unknown, indent = 0, enums: Map<string, Map<number, string>>) => {
            
            for(const key of Object.keys(o)) {
                const val = o[key];
                const valueType = typeof val;
                
                const isMapped = [...enums.keys()].includes(key); 

                let mappedVal = null;

                if (Array.isArray(val) && isMapped) {
                    const mappedVals = [];
                    for (const element of val as Array<number>) {
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
    reference: string,
    trustChainDER: Array<string>
): Promise<IKeyAttestationResult> => {

    console.log('HW key attestation');

    const record = await getKeyAttRecordForReference(reference);
    if (record == null) {
        throw Error('unknown attestation record');
    }

    const googleRootCertsPEM = await getGoogleKeyAttestationRootCertsPEM();
    const googleRootCertsDER = googleRootCertsPEM.map(pem => derFromPem(pem));

    const certChain = trustChainDER
        .map(der => ({
            der,
            pki: pki.certificateFromAsn1(asn1.fromDer(Buffer.from(der, 'hex').toString('binary'))),
            pem: pemFromDer(der)
        }))
        .map(it => ({ ...it,
            ix509: IX509CertFromPKICert(it.pki)
        }));

    console.log(`${
        trustChainDER.length} certs in chain: ${
        certChain.map(it => it.ix509.subjectDN).join(', ')}`);

    const rootCerts = certChain.filter(it => it.ix509.issuerDN == it.ix509.subjectDN);
    console.log(`${
        rootCerts.length} root certs(s): ${
        rootCerts.map(it => it.ix509.subjectDN).join(', ')}`);

    if (rootCerts.length == 0) {
        return {
            succeeded: false,
            error: KeyAttestationFailureReason.TrustChainDoesNotContainARoot,
            reference: record.reference
        }
    } else if (rootCerts.length > 1) {
        return {
            succeeded: false,
            error: KeyAttestationFailureReason.TrustChainContainsMultipleRoots,
            reference: record.reference
        }
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
        return {
            succeeded: false,
            error: KeyAttestationFailureReason.TrustChainSignatureError,
            reference: record.reference
        }
    }
    console.log(`${rootSigVerified ? 'verified' : 'failed to verify'} self-signature of 0 ${rootCert.ix509.subjectDN} root cert`)
    
    if (!rootSigVerified) {
        return {
            succeeded: false,
            error: KeyAttestationFailureReason.TrustChainSignatureError,
            reference: record.reference
        }
    }

    // confirm root cert as known
    //
    const isKnownValidRootCert = googleRootCertsDER.includes(rootCert.der);
    console.log(`root cert ${isKnownValidRootCert ? "is": "is not"} a known valid Google root HW attestation cert`);
    
    if (!isKnownValidRootCert) {
        return {
            succeeded: false,
            error: KeyAttestationFailureReason.TrustChainDoesNotContainAValidKnownRoot,
            reference: record.reference
        }
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
            
            return {
                succeeded: false,
                error: KeyAttestationFailureReason.TrustChainIsMissingALink,
                reference: record.reference
            }
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
            
            return {
                succeeded: false,
                error: KeyAttestationFailureReason.TrustChainSignatureError,
                reference: record.reference
            }
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
            
            return {
                succeeded: false,
                error: KeyAttestationFailureReason.TrustChainNodeNotYetValid,
                reference: record.reference
            };
        }

        const notAfter = cert.pki.validity.notAfter;
        if (notAfter < now) {
            const error = `cert ${cert.ix509.subjectDN} has already expired (not after ${notAfter})`;
            console.log(error);
            
            return {
                succeeded: false,
                error: KeyAttestationFailureReason.TrustChainNodeExpired,
                reference: record.reference
            };
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
        
        return {
            succeeded: false,
            error: KeyAttestationFailureReason.TrustChainContainsARevokedElement,
            reference: record.reference
        };
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

    // TODO check
    // TODO update record

    return {
        error: null,
        reference: record.reference,
        succeeded: true
    }
};

export const initiateKeyAttestation = async (
    deviceFingerprint: IDeviceFingerprint
): Promise<IInitKeyAttestationResult> => {

    // check min requirements (e.g. OS level) based on fingerprint
    //
    if (deviceFingerprint.apiLevel < minDeviceReqs.apiLevel) {
        console.log(`device os api level (${deviceFingerprint.apiLevel}) is not sufficient, minimum is ${minDeviceReqs.apiLevel}`)
        return {
            succeeded: false,
            failureReason: InitKeyAttestationFailureReason.InsufficientApiLevel,
            keyParams: null,
            reference: null
        }
    }

    // create random challenge for hw key attestation
    //
    let challenge: Buffer = null;
    try {
        challenge = await randomBytesAsync(8);
    } catch (e) {
        console.error('error getting random bytes for challenge', e);
        return {
            succeeded: false,
            failureReason: InitKeyAttestationFailureReason.NoSourceOfRandomness,
            keyParams: null,
            reference: null
        } 
    }
  
    // persist request with nonces, returning reg ID (not DB id)

    const keyParams = {
        challenge: challenge.toString('hex'),
        lifetimeMinutes: 60,
        digest: Digest.SHA_2_512,
        ecCurve: null,
        padding: Padding.RSA_PKCS1_1_5_ENCRYPT,
        purpose: KeyPurpose.Encrypt,
        rsaExponent: 65537,
        serialNumber: 1,
        sizeInBits: 2048
    };
    
    const record: IKeyAttestationRecord = {
        id: v4(),
        reference: v4(),

        keyParams, 
        chain: null,
        claims: null,        
    
        attested: null,
        error: null
    };

    let persisted = false;
    try {
        persisted = await setKeyAttRecord(record);
    } catch (e) {
        console.error('error persisting AttestationRecord', e);
        return {
            succeeded: false,
            failureReason: InitKeyAttestationFailureReason.DataAccessLayerError,
            keyParams: null,
            reference: null
        }
    }

    return {
        succeeded: persisted,
        failureReason: null,
        keyParams,
        reference: record.reference
    }
};