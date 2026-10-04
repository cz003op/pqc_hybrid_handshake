import 'dart:convert';
import 'dart:typed_data';

/// Builds the handshake transcript that the root key is bound to.
///
/// Layout: eight fields, each encoded as UTF-8 and preceded by its byte
/// length as a 4-byte big-endian unsigned integer, in this order:
///
///  1. the protocol label `cryptaverse-pqxdh-v1`
///  2. encapsulator fingerprint
///  3. decapsulator fingerprint
///  4. encapsulator X25519 public key (unpadded base64url)
///  5. decapsulator X25519 public key (unpadded base64url)
///  6. encapsulator ML-KEM-768 public key (unpadded base64url)
///  7. decapsulator ML-KEM-768 public key (unpadded base64url)
///  8. ML-KEM-768 ciphertext (unpadded base64url)
///
/// Fields are ordered by role (encapsulator first), not by "me / them", so
/// both parties produce identical bytes.
Uint8List buildTranscript({
  required String encapsulatorFp,
  required String decapsulatorFp,
  required String encapsulatorX25519Pub,
  required String decapsulatorX25519Pub,
  required String encapsulatorMlkemPub,
  required String decapsulatorMlkemPub,
  required String kemCt,
}) {
  final buf = BytesBuilder();
  void add(String s) {
    final b = utf8.encode(s);
    buf.addByte((b.length >> 24) & 0xFF);
    buf.addByte((b.length >> 16) & 0xFF);
    buf.addByte((b.length >>  8) & 0xFF);
    buf.addByte( b.length        & 0xFF);
    buf.add(b);
  }
  add('cryptaverse-pqxdh-v1');
  add(encapsulatorFp);
  add(decapsulatorFp);
  add(encapsulatorX25519Pub);
  add(decapsulatorX25519Pub);
  add(encapsulatorMlkemPub);
  add(decapsulatorMlkemPub);
  add(kemCt);
  return buf.toBytes();
}
