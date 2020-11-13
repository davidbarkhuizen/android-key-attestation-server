import { IAsymKeyParams } from "../../../key_attestation/model/IAsymKeyParams";

export interface IKeyAttInitRsp {
    succeeded: boolean;
    reference: string;    
    keyParams: IAsymKeyParams;
}