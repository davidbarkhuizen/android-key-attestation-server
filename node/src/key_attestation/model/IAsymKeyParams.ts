import { Algorithm, Digest, KeyPurpose, Padding } from "./google/enums";

export interface IAsymKeyParams {

    requireHSM: boolean;

    algorithm: Algorithm;

    challenge: string;

    purpose: KeyPurpose;
    sizeInBits: number;
    serialNumber: number;

    lifetimeMinutes: number;
    digest: Digest;
    padding: Padding;

    rsaExponent: number;
    ecCurve: string;
}