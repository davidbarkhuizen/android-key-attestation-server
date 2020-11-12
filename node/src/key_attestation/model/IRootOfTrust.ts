import { VerifiedBootState } from "./google/enums";

export interface IRootOfTrust {
    verifiedBootKey: string,
    deviceLocked: boolean,
    verifiedBootState: VerifiedBootState,
    verifiedBootHash: string,
}