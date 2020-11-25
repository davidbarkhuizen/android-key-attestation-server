import { pki } from 'node-forge';

import { promisify } from 'util';
import { randomBytes } from 'crypto';
const randomBytesAsync = promisify(randomBytes);

import { v4 } from 'uuid';

import { parseDER } from '@indrajala/asn1der';
import { Algorithm, Digest, ECCurve, KeyOrigin, KeyPurpose, Padding, SecurityLevel, VerifiedBootState } from './model/google/enums';
import { enumMap } from '../general/util';
import { IKeyDescriptionFromAsn1Node } from './factory';

import { IDeviceFingerprint } from './model/IDeviceFingerprint';
import { IInitKeyAttestationResult } from './model/IInitKeyAttestationResult';
import { InitKeyAttestationFailureReason } from './model/InitKeyAttestationFailureReason';
import { IKeyAttestationRecord } from '../dal/model/IKeyAttestationRecord';
import { getKeyAttRecordForReference, setKeyAttRecord } from '../dal/dal';
import { IKeyAttestationResult } from './model/IKeyAttestationResult';
import { validateHWAttestationTrustChain } from './chain';
import { IKeyDescription } from './model/IKeyDescription';
import { IAsymKeyParams } from './model/IAsymKeyParams';
import { KeyAttestationFailureReason } from './model/KeyAttestationFailureReason';

// TODO get from repo
const minDeviceRequirements = {
    apiLevel: 28
};

export const initiateKeyAttestation = async (
    deviceFingerprint: IDeviceFingerprint
): Promise<IInitKeyAttestationResult> => {

    // check min requirements (e.g. OS level) based on fingerprint
    //
    if (deviceFingerprint.apiLevel < minDeviceRequirements.apiLevel) {
        console.log(`device os api level (${deviceFingerprint.apiLevel}) is not sufficient, minimum is ${minDeviceRequirements.apiLevel}`)
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

    const keyParams: IAsymKeyParams = {
        requireHSM: false,
        algorithm: Algorithm.RSA,
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
    
    // const keyParams: IAsymKeyParams = {
    //     requireHSM: false,
    //     algorithm: Algorithm.EC,
    //     challenge: challenge.toString('hex'),
    //     lifetimeMinutes: 60,
    //     digest: Digest.SHA_2_512,
    //     ecCurve: 'secp256r1',
    //     padding: Padding.RSA_PKCS1_1_5_ENCRYPT,
    //     purpose: KeyPurpose.Encrypt,
    //     rsaExponent: 65537,
    //     serialNumber: 1,
    //     sizeInBits: 256
    // };

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

const validateAttestedDataAgainstInstruction = (
    instruction: IAsymKeyParams,
    attested: IKeyDescription
): KeyAttestationFailureReason => {

    // Challenge

    const instructedChallenge = Buffer.from(instruction.challenge, 'hex');
    const attestedChallenge = Buffer.from(attested.attestationChallenge, 'hex');

    if (instructedChallenge.compare(attestedChallenge) != 0) {
        console.log(`challenge failed: instructed ${instructedChallenge.toString('hex')
            }, attested ${attestedChallenge.toString('hex')}`);

        return KeyAttestationFailureReason.ChallengeFailed;
    }

    // Key Purpose

    if (attested.teeEnforced.purpose.length > 1) {
        console.log(`generated key has multiple purposes: ${
            attested.teeEnforced.purpose.join(', ')}, expected purpose: ${instruction.purpose}`);
        
        return KeyAttestationFailureReason.MultiPurposeKeyNotAllowed;
    }

    const purpose = attested.teeEnforced.purpose[0];
    if (instruction.purpose != purpose) {
        console.log(`unexpected purpose ${purpose}, expected ${instruction.purpose}`);

        return KeyAttestationFailureReason.UnexpectedKeyPurpose;
    }

    // Key Size

    if (attested.teeEnforced.keySize != instruction.sizeInBits) {
        console.log(`unexpected key size ${attested.teeEnforced.keySize}, expected ${instruction.sizeInBits}`);

        return KeyAttestationFailureReason.UnexpectedKeySize;
    }

    // Digest

    if (attested.teeEnforced.digest.length > 1) {
        console.log(`generated key supports multiple digests: ${
            attested.teeEnforced.digest.join(', ')}, expected purpose: ${instruction.digest}`);
        
        return KeyAttestationFailureReason.KeyNotAllowedToSupportMultipleDigests;
    }

    const digest = attested.teeEnforced.digest[0];
    if (instruction.digest != digest) {
        console.log(`unexpected digest ${digest}, expected ${instruction.digest}`);

        return KeyAttestationFailureReason.UnexpectedKeyDigest;
    }


    // Padding

    if (attested.teeEnforced.padding.length > 1) {
        console.log(`generated key supports multiple paddings: ${
            attested.teeEnforced.padding.join(', ')}, expected: ${instruction.padding}`);
        
        return KeyAttestationFailureReason.KeyNotAllowedToSupportMultiplePaddings;
    }

    const padding = attested.teeEnforced.padding[0];
    if (instruction.padding != padding) {
        console.log(`unexpected padding ${padding}, expected ${instruction.padding}`);

        return KeyAttestationFailureReason.UnexpectedKeyPadding;
    }

    // TODO

    // requireHSM => must be strongbox
    
    // RSA, EC
    // rsaExponent: number;
    // ecCurve: string;

    // basic cert
    //
    // serialNumber: number;
    // lifetimeMinutes: number;

    return KeyAttestationFailureReason.None;
};

export const getKeyDescriptionFromAttestationExtension = (
    cert: pki.Certificate
): IKeyDescription => {

    const GoogleAttestationExtensionOID = '1.3.6.1.4.1.11129.2.1.17';
    
    // google key attestation
    //
    const attestationExt = cert.extensions.find(it => it.id == GoogleAttestationExtensionOID);
    
    if (!attestationExt) {
        console.log('attestation cert does not contain an X.509 attestation extension');
        return null; // TODO result KeyAttestationCertHasNoAttestationExtension
    }    

    const asn1Seq = Buffer.from(attestationExt.value, 'ascii');

    const parsed = parseDER(asn1Seq)[0];

    const attAppIdNode = parsed.get('6.#709.0');
    attAppIdNode.reparse();

    return IKeyDescriptionFromAsn1Node(parsed);
};

export const attestHardwareKey = async (
    reference: string,
    trustChainDER: Array<string>
): Promise<IKeyAttestationResult> => {

    console.log(`processing HW key attestation reference ${reference}`);

    const record = await getKeyAttRecordForReference(reference);
    if (record == null) {
        throw Error('unknown attestation record');
    }

    const chainValidationResult = await validateHWAttestationTrustChain(trustChainDER);
    
    if (chainValidationResult.succeeded == false) {
        
        console.log(`validation of key attestation trust chain failed: ${chainValidationResult.failureReason}`);
        
        return {
            error: chainValidationResult.failureReason,
            reference: record.reference,
            succeeded: false
        };
    }

    const keyDescription = getKeyDescriptionFromAttestationExtension(chainValidationResult.keyCert.pki);

    const stripped = JSON.parse(JSON.stringify(keyDescription));

    const describe = (o: unknown, indent = 0, enums: Map<string, Map<number, string>>) => {
        
        for(const key of Object.keys(o)) {
            const val = o[key];
            const valueType = typeof val;
            
            const isMapped = [...enums.keys()].includes(key); 

            let mappedVal = null;

            if (Array.isArray(val) && isMapped) {
                const mappedValues = [];
                for (const element of val as Array<number>) {
                    mappedVal = enums.get(key).get(element);
                    mappedValues.push(mappedVal);
                }
                console.log(`${' '.repeat(indent)}${key}: ${mappedValues}`);
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

    const keyDeviation = validateAttestedDataAgainstInstruction(
        record.keyParams,
        keyDescription
    );

    if (keyDeviation != KeyAttestationFailureReason.None) {
        console.log(`key as generated does not match instructions: ${keyDeviation}`);
    }

    // TODO update record

    return {
        error: null,
        reference: record.reference,
        succeeded: true
    }
};