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
const asn1js = __importStar(require("asn1js"));
const pkijs_1 = require("pkijs");
exports.router = express_1.default.Router();
exports.router.post('/register', function (req, res) {
    console.log('registering device...');
    const raw = new Uint8Array(Buffer.from(req.body.asn1hex, 'hex')).buffer;
    const asn1 = asn1js.fromBER(raw);
    // console.log('asn1', asn1);
    const certificate = new pkijs_1.Certificate({ schema: asn1.result });
    console.log('Certificate Serial Number');
    console.log(Buffer.from(certificate.serialNumber.valueBlock.valueHex).toString("hex"));
    console.log('Certificate Issuance');
    console.log(certificate.notBefore.value.toString());
    console.log('Certificate Expiry');
    console.log(certificate.notAfter.value.toString());
    console.log(certificate.issuer);
    res.send('registered!');
});
//# sourceMappingURL=pkis_example.js.map