/// Hybrid post-quantum key agreement: X25519 + ML-KEM-768, bound to a
/// length-prefixed transcript, combined with chained HKDF-Extract steps.
///
/// PQXDH-style, not Signal's PQXDH. See README.md for the design.
library;

export 'src/encoding.dart' show encodeB64url, decodeB64url;
export 'src/mlkem.dart'
    show mlkemGenerateKeyPair, mlkemEncapsulate, mlkemDecapsulate;
export 'src/root_key.dart' show deriveHybridRoot;
export 'src/transcript.dart' show buildTranscript;
export 'src/x25519.dart' show x25519GenerateKeyPair, x25519SharedSecret;
