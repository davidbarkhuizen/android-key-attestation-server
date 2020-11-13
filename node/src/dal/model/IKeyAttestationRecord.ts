import { IAsymKeyParams } from "../../key_attestation/model/IAsymKeyParams";
import { IHWAttestationClaims } from "./IHWAttestationClaims";

export interface IKeyAttestationRecord {
    id: string;
    reference: string;

    keyParams: IAsymKeyParams;
    
    chain: Array<string>;
    claims: IHWAttestationClaims;    

    attested: boolean | null;
    error: string;
}