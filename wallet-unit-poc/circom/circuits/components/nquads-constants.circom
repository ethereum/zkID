pragma circom 2.2.3;

// "https://example.org/eid#": the predicate namespace of the claim lines.
function NQ_BASE_LEN() { return 24; }
function NQ_BASE() {
    return [104, 116, 116, 112, 115, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46,
            111, 114, 103, 47, 101, 105, 100, 35];
}

// b64url('{"alg":"ES256","b64":false,"crit":["b64"]}') || ".": the RFC 7797
// (b64=false) JWS signing input header the issuer signs over.
function NQ_JWS_HDR_LEN() { return 57; }
function NQ_JWS_HDR() {
    return [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 73, 49, 78, 105,
            73, 115, 73, 109, 73, 50, 78, 67, 73, 54, 90, 109, 70, 115, 99, 50, 85, 115,
            73, 109, 78, 121, 97, 88, 81, 105, 79, 108, 115, 105, 89, 106, 89, 48, 73, 108,
            49, 57, 46];
}

// ' <https://www.w3.org/2018/credentials#credentialSubject> <'
function NQ_CS_PREFIX_LEN() { return 58; }
function NQ_CS_PREFIX() {
    return [32, 60, 104, 116, 116, 112, 115, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111,
            114, 103, 47, 50, 48, 49, 56, 47, 99, 114, 101, 100, 101, 110, 116, 105, 97, 108,
            115, 35, 99, 114, 101, 100, 101, 110, 116, 105, 97, 108, 83, 117, 98, 106, 101, 99,
            116, 62, 32, 60];
}

// "deviceKey"
function NQ_DEVICE_KEY_NAME() {
    return [100, 101, 118, 105, 99, 101, 75, 101, 121];
}
