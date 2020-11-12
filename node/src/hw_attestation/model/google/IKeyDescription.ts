import { SecurityLevel } from "./enums";
import { IAuthorizationList } from "./IAuthorizationList";

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