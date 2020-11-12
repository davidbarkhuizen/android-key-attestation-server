import { VerifiedBootState } from "../../hw_attestation/model/enums";

export interface IRootOfTrust {
    verifiedBootKey: string,
    deviceLocked: boolean,
    verifiedBootState: VerifiedBootState,
    verifiedBootHash: string,
}