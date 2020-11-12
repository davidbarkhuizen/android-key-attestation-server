export interface IKeyAttInitRsp {
    registrationID: string,
    keyAttestationChallenge: string
    keyLifeTimeMinutes: Number,
    keySizeBits: Number,
    keySN: Number
}