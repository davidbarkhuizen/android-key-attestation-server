import { Digest, KeyPurpose, Padding } from "./google/enums";

export interface IAsymKeyParams {

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