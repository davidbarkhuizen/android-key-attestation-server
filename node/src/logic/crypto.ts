export const pemFromDer = (hex: string) =>
    '-----BEGIN CERTIFICATE-----\n' 
    + (Buffer.from(hex, 'hex')).toString('base64').match(/.{0,64}/g).join('\n')
    + '-----END CERTIFICATE-----';

export const derFromPem = (pem: string) => {

    const b64 = pem
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace('\n', '');

    return Buffer.from(b64, 'base64').toString('hex');
}