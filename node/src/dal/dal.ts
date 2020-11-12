import { IAttestationRecord } from "./model/IKeyAttestationRecord";

const keyAttRecRepo = new Map<string, IAttestationRecord>();

export const setKeyAttRecord = async (rec: IAttestationRecord): Promise<boolean> => {
    keyAttRecRepo.set(rec.attestationID, rec);
    return true;
};

export const getKeyAttRecord = async (id: string): Promise<IAttestationRecord> => {
    return keyAttRecRepo.get(id);
};