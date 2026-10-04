// Step-by-step demo: hybrid handshake, then encrypt and decrypt a message.
//
// Run with:
//   dart run example/encrypt_demo.dart
//   dart run example/encrypt_demo.dart "your own message"
//   dart run example/encrypt_demo.dart --file path/to/file.txt
//
// Everything is printed so you can see what each step produces.
// Secret values are printed ONLY because this is a demo.
//
// The message-encryption step (HKDF -> ChaCha20-Poly1305) is an
// illustration of how a root key is used. It is not part of the
// package API and is not Cryptaverse's message encryption.

import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:pqc_hybrid_handshake/pqc_hybrid_handshake.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// Short preview: first 16 bytes as hex, plus total length.
String preview(List<int> b) {
  final shown = b.length <= 16 ? hex(b) : '${hex(b.sublist(0, 16))}...';
  return '$shown  (${b.length} bytes)';
}

void heading(String s) => print('\n=== $s ===');

String check(bool ok) => ok ? '[MATCH]' : '[DIFFERENT]';

Future<List<int>> readInput(List<String> args) async {
  if (args.length == 2 && args[0] == '--file') {
    return File(args[1]).readAsBytes();
  }
  if (args.isNotEmpty) return utf8.encode(args.join(' '));
  return utf8.encode('Meet at the north entrance at 7pm.');
}

/// Derives a dedicated message key from the root key, so the root key
/// itself is never used directly as a cipher key.
Future<SecretKey> messageKeyFrom(List<int> root) {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  return hkdf.deriveKey(
    secretKey: SecretKey(root),
    info: utf8.encode('pqc-hybrid-demo-message-key-v1'),
  );
}

Future<void> main(List<String> args) async {
  final plaintext = await readInput(args);
  if (plaintext.isEmpty) {
    print('Nothing to encrypt: the message or file is empty.');
    exitCode = 1;
    return;
  }

  // ── 1. Each party creates key pairs ────────────────────────────────────
  heading('1. Key generation');
  const aliceFp = '1111aaaa2222bbbb';
  const bobFp = '9999cccc8888dddd';

  final aliceX = await x25519GenerateKeyPair();
  final aliceKem = mlkemGenerateKeyPair();
  final bobX = await x25519GenerateKeyPair();
  final bobKem = mlkemGenerateKeyPair();

  print('Alice X25519 public key:    ${preview(aliceX.publicKey)}');
  print('Alice X25519 private key:   ${preview(aliceX.privateKey)}  [secret]');
  print('Alice ML-KEM-768 public key: ${preview(aliceKem.publicKey)}');
  print('Bob   X25519 public key:    ${preview(bobX.publicKey)}');
  print('Bob   X25519 private key:   ${preview(bobX.privateKey)}  [secret]');
  print('Bob   ML-KEM-768 public key: ${preview(bobKem.publicKey)}');
  print('Bob   ML-KEM-768 secret key: ${preview(bobKem.secretKey)}  [secret]');

  final alicePubX = encodeB64url(aliceX.publicKey);
  final alicePubKem = encodeB64url(aliceKem.publicKey);
  final bobPubX = encodeB64url(bobX.publicKey);
  final bobPubKem = encodeB64url(bobKem.publicKey);

  // ── 2. Alice encapsulates to Bob's ML-KEM key ──────────────────────────
  heading('2. Alice: ML-KEM-768 encapsulation');
  final kem = mlkemEncapsulate(bobKem.publicKey);
  final kemCtB64 = encodeB64url(kem.ciphertext);
  print('KEM ciphertext (sent to Bob): ${preview(kem.ciphertext)}');
  print('Alice ML-KEM shared secret:   ${preview(kem.sharedSecret)}');

  // ── 3. Bob decapsulates ────────────────────────────────────────────────
  heading('3. Bob: ML-KEM-768 decapsulation');
  final bobKemSecret =
      mlkemDecapsulate(decodeB64url(kemCtB64), bobKem.secretKey);
  print('Bob ML-KEM shared secret:     ${preview(bobKemSecret)}  '
      '${check(hex(bobKemSecret) == hex(kem.sharedSecret))}');

  // ── 4. X25519 on both sides ────────────────────────────────────────────
  heading('4. X25519 shared secret');
  final aliceSsDh = await x25519SharedSecret(
      aliceX.privateKey, aliceX.publicKey, bobX.publicKey);
  final bobSsDh = await x25519SharedSecret(
      bobX.privateKey, bobX.publicKey, aliceX.publicKey);
  print('Alice X25519 secret: ${preview(aliceSsDh)}');
  print('Bob   X25519 secret: ${preview(bobSsDh)}  '
      '${check(hex(aliceSsDh) == hex(bobSsDh))}');

  // ── 5. Transcript (identical on both sides) ────────────────────────────
  heading('5. Handshake transcript');
  final transcript = buildTranscript(
    encapsulatorFp: aliceFp,
    decapsulatorFp: bobFp,
    encapsulatorX25519Pub: alicePubX,
    decapsulatorX25519Pub: bobPubX,
    encapsulatorMlkemPub: alicePubKem,
    decapsulatorMlkemPub: bobPubKem,
    kemCt: kemCtB64,
  );
  print('Transcript: ${preview(transcript)}');
  print('(8 length-prefixed fields: label, both fingerprints, both X25519');
  print(' keys, both ML-KEM keys, and the KEM ciphertext)');

  // ── 6. Root key ────────────────────────────────────────────────────────
  heading('6. Hybrid root key');
  final aliceRoot = await deriveHybridRoot(
      ssDH: aliceSsDh, ssKEM: kem.sharedSecret, transcript: transcript);
  final bobRoot = await deriveHybridRoot(
      ssDH: bobSsDh, ssKEM: bobKemSecret, transcript: transcript);
  print('Alice root key: ${hex(aliceRoot)}');
  print('Bob   root key: ${hex(bobRoot)}  '
      '${check(hex(aliceRoot) == hex(bobRoot))}');
  if (hex(aliceRoot) != hex(bobRoot)) {
    print('\nHandshake failed; stopping.');
    exitCode = 1;
    return;
  }

  // ── 7. Alice encrypts ──────────────────────────────────────────────────
  heading('7. Alice encrypts (ChaCha20-Poly1305)');
  final aead = Chacha20.poly1305Aead();
  final aliceMsgKey = await messageKeyFrom(aliceRoot);
  final box = await aead.encrypt(plaintext, secretKey: aliceMsgKey);
  print('Plaintext:  ${preview(plaintext)}');
  print('Nonce:      ${hex(box.nonce)}  (${box.nonce.length} bytes, random)');
  print('Ciphertext: ${box.cipherText.length <= 64 ? hex(box.cipherText) : preview(box.cipherText)}');
  print('Auth tag:   ${hex(box.mac.bytes)}  (16 bytes)');

  // ── 8. Bob decrypts with the key HE derived ────────────────────────────
  heading('8. Bob decrypts');
  final bobMsgKey = await messageKeyFrom(bobRoot);
  final decrypted = await aead.decrypt(box, secretKey: bobMsgKey);
  final same = hex(decrypted) == hex(plaintext);
  if (args.length == 2 && args[0] == '--file') {
    print('Decrypted ${decrypted.length} bytes  ${check(same)}');
  } else {
    print('Decrypted text: "${utf8.decode(decrypted)}"  ${check(same)}');
  }

  // ── 9. Tampering is detected ───────────────────────────────────────────
  heading('9. Tamper test');
  final tamperedCt = List<int>.from(box.cipherText);
  tamperedCt[0] ^= 0x01;
  final tampered = SecretBox(tamperedCt, nonce: box.nonce, mac: box.mac);
  try {
    await aead.decrypt(tampered, secretKey: bobMsgKey);
    print('Tampered ciphertext was ACCEPTED (this should never happen)');
    exitCode = 1;
  } on SecretBoxAuthenticationError {
    print('Flipped one bit of the ciphertext -> decryption REJECTED [OK]');
  }

  print('\nDone.');
}
