import { KeyOrigin } from "../../key_attestation/model/google/enums";

export interface IHWAttestationClaims {

    origin: KeyOrigin;

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
}