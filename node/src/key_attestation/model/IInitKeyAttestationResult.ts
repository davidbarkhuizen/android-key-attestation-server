import { IAsymKeyParams } from "./IAsymKeyParams";
import { KeyAttestationFailureReason } from "./KeyAttestationFailureReason";

export interface IInitKeyAttestationResult {
    succeeded: boolean;
    failureReason: KeyAttestationFailureReason;
    
    reference: string;
    keyParams: IAsymKeyParams;
}