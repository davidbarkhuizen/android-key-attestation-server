"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.router = void 0;
const express_1 = __importDefault(require("express"));
const forge = __importStar(require("node-forge"));
exports.router = express_1.default.Router();
const describeCert = (label, hex) => {
    var _a, _b, _c, _d;
    var certAsn1 = forge.asn1.fromDer(Buffer.from(hex, 'hex').toString('binary'));
    var cert = forge.pki.certificateFromAsn1(certAsn1);
    const issuerCN = (_b = (_a = cert.issuer.getField('CN')) === null || _a === void 0 ? void 0 : _a.value) !== null && _b !== void 0 ? _b : 'no issuer';
    const subjectCN = (_d = (_c = cert.subject.getField('CN')) === null || _c === void 0 ? void 0 : _c.value) !== null && _d !== void 0 ? _d : 'no subject';
    console.log(`CERT: ${label}`);
    const description = [
        `issuer ${issuerCN}`,
        `subject ${subjectCN}`,
        `SN ${cert.serialNumber}`,
        `valid: ${cert.validity.notBefore} - ${cert.validity.notAfter}`
    ];
    console.log(description.join('\n'));
};
exports.router.post('/register', function (req, res) {
    console.log('registering device...');
    console.log('device public key');
    console.log(req.body.asn1hex);
    console.log(req.body.attestationChain);
    describeCert('PUBLIC KEY', req.body.asn1hex);
    req.body.chain.forEach(function (value, i) {
        console.log('%d: %s', i, value);
    });
    console.log('CHAIN:');
    req.body.chain.forEach((cert, i) => {
        describeCert(`LINK ${i}`, cert);
    });
    // ---------------------------------------------------------------
    res.status(500).send('not yet implemented');
});
//# sourceMappingURL=device.controller.js.map