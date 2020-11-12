import { VerifiedBootState } from "./enums";

export interface IRootOfTrust {
    verifiedBootKey: string,
    deviceLocked: boolean,
    verifiedBootState: VerifiedBootState,
    verifiedBootHash: string,
}