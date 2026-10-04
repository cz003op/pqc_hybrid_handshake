import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Derives the 32-byte hybrid root key.
///
/// HMAC-SHA256 chain (each line is one HMAC call, `HMAC(key, message)`):
///
/// ```text
/// temp1 = HMAC(key = 32 zero bytes, ssDH)        // HKDF-Extract #1
/// temp2 = HMAC(key = temp1,         ssKEM)       // HKDF-Extract #2
/// root  = HMAC(key = temp2, "cryptaverse-root-v1" || transcript || 0x01)
///                                                 // HKDF-Expand, block 1
/// ```
///
/// [ssDH] is the X25519 shared secret, [ssKEM] the ML-KEM-768 shared
/// secret, [transcript] the output of `buildTranscript`.
///
/// Corresponds to `_derivePqxdhRoot` in Cryptaverse. The label
/// `cryptaverse-root-v1` is kept unchanged for compatibility with the app;
/// see "Naming" in README.md.
Future<List<int>> deriveHybridRoot({
  required List<int> ssDH,
  required List<int> ssKEM,
  required Uint8List transcript,
}) async {
  final hmac   = Hmac.sha256();
  final zeros  = Uint8List(32);
  final mac1  = await hmac.calculateMac(ssDH, secretKey: SecretKey(zeros));
  final temp1 = mac1.bytes;
  final mac2  = await hmac.calculateMac(ssKEM, secretKey: SecretKey(temp1));
  final temp2 = mac2.bytes;
  final info  = [...utf8.encode('cryptaverse-root-v1'), ...transcript, 0x01];
  final mac3  = await hmac.calculateMac(info, secretKey: SecretKey(temp2));
  return mac3.bytes;
}
