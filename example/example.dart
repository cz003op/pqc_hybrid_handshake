// Two parties complete the hybrid handshake in one process.
// Run with:  dart run example/example.dart

import 'package:pqc_hybrid_handshake/pqc_hybrid_handshake.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Future<void> main() async {
  // ── Setup: each party has an X25519 key pair and an ML-KEM-768 key pair.
  // Public keys and fingerprints are exchanged in advance (in Cryptaverse,
  // via the contact exchange). Fingerprints here are demo values.
  const aliceFp = '1111aaaa2222bbbb';
  const bobFp   = '9999cccc8888dddd';

  final aliceX   = await x25519GenerateKeyPair();
  final aliceKem = mlkemGenerateKeyPair();
  final bobX     = await x25519GenerateKeyPair();
  final bobKem   = mlkemGenerateKeyPair();

  final alicePubX   = encodeB64url(aliceX.publicKey);
  final alicePubKem = encodeB64url(aliceKem.publicKey);
  final bobPubX     = encodeB64url(bobX.publicKey);
  final bobPubKem   = encodeB64url(bobKem.publicKey);

  // ── Alice = encapsulator. ─────────────────────────────────────────────
  final kem      = mlkemEncapsulate(bobKem.publicKey);
  final kemCtB64 = encodeB64url(kem.ciphertext); // sent to Bob

  final aliceTranscript = buildTranscript(
    encapsulatorFp:        aliceFp,
    decapsulatorFp:        bobFp,
    encapsulatorX25519Pub: alicePubX,
    decapsulatorX25519Pub: bobPubX,
    encapsulatorMlkemPub:  alicePubKem,
    decapsulatorMlkemPub:  bobPubKem,
    kemCt:                 kemCtB64,
  );
  final aliceSsDh = await x25519SharedSecret(
      aliceX.privateKey, aliceX.publicKey, bobX.publicKey);
  final aliceRoot = await deriveHybridRoot(
      ssDH: aliceSsDh, ssKEM: kem.sharedSecret, transcript: aliceTranscript);

  // ── Bob = decapsulator, after receiving kemCtB64. ─────────────────────
  final bobKemSecret =
      mlkemDecapsulate(decodeB64url(kemCtB64), bobKem.secretKey);

  final bobTranscript = buildTranscript(
    encapsulatorFp:        aliceFp,
    decapsulatorFp:        bobFp,
    encapsulatorX25519Pub: alicePubX,
    decapsulatorX25519Pub: bobPubX,
    encapsulatorMlkemPub:  alicePubKem,
    decapsulatorMlkemPub:  bobPubKem,
    kemCt:                 kemCtB64,
  );
  final bobSsDh = await x25519SharedSecret(
      bobX.privateKey, bobX.publicKey, aliceX.publicKey);
  final bobRoot = await deriveHybridRoot(
      ssDH: bobSsDh, ssKEM: bobKemSecret, transcript: bobTranscript);

  // ── Result. Printing key material is for this demo only. ──────────────
  print('ML-KEM-768 ciphertext: ${kem.ciphertext.length} bytes');
  print('Transcript:            ${aliceTranscript.length} bytes');
  print('Alice root key:        ${hex(aliceRoot)}');
  print('Bob root key:          ${hex(bobRoot)}');
  final match = hex(aliceRoot) == hex(bobRoot);
  print(match ? 'MATCH: handshake complete' : 'MISMATCH: handshake failed');
}
