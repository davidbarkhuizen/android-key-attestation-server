import { KeyAttestationFailureReason } from "./KeyAttestationFailureReason";
import { pki } from "node-forge";

export interface IKeyAttestationChainValidationResult {
    succeeded: boolean;
    failureReason: KeyAttestationFailureReason;
    keyCert: {
        der: string,
        pki: pki.Certificate
        pem: string
    };
}