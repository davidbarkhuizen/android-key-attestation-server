export interface IKeyAttInitRsp {
    attestationID: string,
    challenge: string
    
    keyLifeTimeMinutes: Number,
    keySizeBits: Number,
    keySerialNumber: Number
}