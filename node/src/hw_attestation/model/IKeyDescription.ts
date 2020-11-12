import { SecurityLevel } from "./google/enums";
import { IAuthorizationList } from "../../hw_attestation/model/IAuthorizationList";

export interface IKeyDescription {
    attestationVersion: number;
    attestationSecurityLevel: SecurityLevel,
    keymasterVersion: number,
    keymasterSecurityLevel: SecurityLevel,
    attestationChallenge: string,
    uniqueId: string,
    softwareEnforced: IAuthorizationList,
    teeEnforced: IAuthorizationList,
}