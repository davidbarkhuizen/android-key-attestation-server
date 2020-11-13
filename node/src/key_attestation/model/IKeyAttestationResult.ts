import { KeyAttestationFailureReason } from "./KeyAttestationFailureReason";

export interface IKeyAttestationResult {
    reference: string;
    succeeded: boolean;
    error: KeyAttestationFailureReason
}