import { IAsymKeyParams } from "./IAsymKeyParams";
import { InitKeyAttestationFailureReason } from "./InitKeyAttestationFailureReason";

export interface IInitKeyAttestationResult {
    succeeded: boolean;
    failureReason: InitKeyAttestationFailureReason;
    
    reference: string;
    keyParams: IAsymKeyParams;
}