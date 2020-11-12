export interface IAttestationRecord {
    
    attestationID: string;
    challenge: string;

    chain: Array<string>;

    key: string;
    keySizeBits: number;
    origin: string;
    purposes: string;

    ecCurve: string;
    rsaExponent: number;

    encryptionPadding: string;
    signaturePading: string;
    digest: string;

    osVersion: string;
    osPatchLevel: string;

    attestationVersion: number;
    attestationSecurityLevel: number;
    keymasterVersion: number;
    keymasterSecurityLevel: number;

    verifiedBootKey: string,
    deviceLocked: boolean,
    verifiedBootState: string

    rollbackResistance: boolean;    

    uniqueId: string;

    applicationPackageName: string;
    applicationPackageVersion: string;
    applicationSignatureDigest: string;

    attested: boolean;
    error: string;
}