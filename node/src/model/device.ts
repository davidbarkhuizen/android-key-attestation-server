import { Integer } from "asn1js"

export interface IDevRegInitRq {}

export interface IDevRegInitRsp {
    registrationID: string,
    keyAttestationChallenge: string
    keyLifeTimeMinutes: Integer,
    keySizeBits: Integer,
    keySN: Integer
}

export interface IDevRegCompletionRq {
    registrationID: string,
    attKeyChainDER: Array<string>
}

export interface IDevRegCompletionRsp {
    succeeded: Boolean
}