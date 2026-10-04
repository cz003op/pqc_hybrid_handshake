// File encryption demo using the hybrid handshake, with sender signatures.
//
//   dart run example/file_demo.dart keygen alice
//       -> alice.pub (public keys, safe to share)
//       -> alice.key (secret keys, keep private)
//
//   dart run example/file_demo.dart encrypt alice.key bob.pub secret.txt
//       -> secret.txt.enc   (encrypted to Bob, signed by Alice)
//
//   dart run example/file_demo.dart decrypt bob.key alice.pub secret.txt.enc
//       -> secret.decrypted.txt  (only if Alice's signature is valid)
//
// How it works:
//  * Each key pair has three parts: X25519 and ML-KEM-768 (for receiving
//    encrypted files) and Ed25519 (for signing files you send).
//  * To encrypt, the sender creates one-time X25519 and ML-KEM-768 keys,
//    runs the hybrid handshake against the recipient's public keys,
//    derives a file key with HKDF-SHA256 and encrypts with
//    ChaCha20-Poly1305. The sender's identity fingerprint is part of the
//    handshake transcript, so the encryption itself is bound to the sender.
//  * The sender then signs the whole result with Ed25519.
//  * To decrypt, the recipient first checks the signature against the
//    sender's .pub file, then repeats the handshake with their own secret
//    keys.
//
// A valid signature proves the file was made by whoever holds the sender's
// .key file. It does not prove that the .pub file you were given really
// belongs to that person: compare fingerprints with them directly.
//
// DEMO ONLY: key files are stored unencrypted, the file format is specific
// to this demo, Ed25519 is not post-quantum, and none of it has been
// audited. For real secrets use an established tool such as age.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pqc_hybrid_handshake/pqc_hybrid_handshake.dart';

const formatId = 'pqc-hybrid-handshake-file-demo-v2';
const signatureLabel = 'pqc-hybrid-demo-signature-v2';
final jsonOut = JsonEncoder.withIndent('  ');
final ed25519 = Ed25519();

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

String preview(List<int> b) {
  final shown = b.length <= 16 ? hex(b) : '${hex(b.sublist(0, 16))}...';
  return '$shown  (${b.length} bytes)';
}

void usage() {
  print('Usage:');
  print('  dart run example/file_demo.dart keygen <name>');
  print('  dart run example/file_demo.dart encrypt <your>.key <recipient>.pub <file>');
  print('  dart run example/file_demo.dart decrypt <your>.key <sender>.pub <file>.enc');
}

/// Each part is preceded by its length (4 bytes, big-endian), so the
/// boundaries between parts are unambiguous.
Uint8List lengthPrefixed(List<List<int>> parts) {
  final b = BytesBuilder();
  for (final p in parts) {
    b.add([
      (p.length >> 24) & 0xFF,
      (p.length >> 16) & 0xFF,
      (p.length >> 8) & 0xFF,
      p.length & 0xFF,
    ]);
    b.add(p);
  }
  return b.toBytes();
}

/// First 16 bytes of SHA-256 over the length-prefixed public keys, as hex.
Future<String> fingerprintOf(List<List<int>> publicKeys) async {
  final h = await Sha256().hash(lengthPrefixed(publicKeys));
  return hex(h.bytes.sublist(0, 16));
}

Future<SecretKey> fileKeyFrom(List<int> root) {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  return hkdf.deriveKey(
    secretKey: SecretKey(root),
    info: utf8.encode('pqc-hybrid-demo-file-key-v2'),
  );
}

Future<Map<String, dynamic>> readJson(String path, String expectedType) async {
  final file = File(path);
  if (!await file.exists()) {
    throw FormatException('File not found: $path');
  }
  Object? decoded;
  try {
    decoded = jsonDecode(await file.readAsString());
  } on FormatException {
    throw FormatException('$path is not a file created by this demo.');
  }
  if (decoded is! Map<String, dynamic> ||
      decoded['format'] != formatId ||
      decoded['type'] != expectedType) {
    throw FormatException('$path is not a "$expectedType" file created by '
        'this version of the demo. Files from older versions must be '
        'recreated.');
  }
  return decoded;
}

String field(Map<String, dynamic> m, String key) {
  final v = m[key];
  if (v is! String) throw FormatException('Missing field "$key".');
  return v;
}

Uint8List bytesField(Map<String, dynamic> m, String key) {
  try {
    return decodeB64url(field(m, key));
  } on FormatException {
    throw FormatException('Field "$key" is not valid base64url.');
  }
}

Future<void> refuseOverwrite(String path) async {
  if (await File(path).exists()) {
    throw FormatException('$path already exists. Move or delete it first.');
  }
}

/// secret.txt.enc -> secret.decrypted.txt ; notes.enc -> notes.decrypted
String decryptedNameFor(String encPath) {
  final base = encPath.endsWith('.enc')
      ? encPath.substring(0, encPath.length - 4)
      : encPath;
  final slash = base.lastIndexOf(RegExp(r'[/\\]'));
  final dot = base.lastIndexOf('.');
  if (dot > slash + 1) {
    return '${base.substring(0, dot)}.decrypted${base.substring(dot)}';
  }
  return '$base.decrypted';
}

/// A loaded .pub or .key file: public keys plus their verified fingerprint.
class Identity {
  Identity(this.fingerprint, this.x25519Pub, this.mlkemPub, this.ed25519Pub);

  final String fingerprint;
  final Uint8List x25519Pub;
  final Uint8List mlkemPub;
  final Uint8List ed25519Pub;

  static Future<Identity> fromJson(Map<String, dynamic> m, String path) async {
    final x = bytesField(m, 'x25519_public');
    final k = bytesField(m, 'mlkem768_public');
    final e = bytesField(m, 'ed25519_public');
    final fp = await fingerprintOf([x, k, e]);
    if (fp != field(m, 'fingerprint')) {
      throw FormatException('$path is damaged (fingerprint mismatch).');
    }
    return Identity(fp, x, k, e);
  }
}

/// The exact bytes the sender signs: everything in the .enc file except
/// the signature itself.
Uint8List signedBytes(Map<String, dynamic> enc) => lengthPrefixed([
      utf8.encode(signatureLabel),
      utf8.encode(field(enc, 'sender_fingerprint')),
      utf8.encode(field(enc, 'recipient_fingerprint')),
      bytesField(enc, 'ephemeral_x25519_public'),
      bytesField(enc, 'ephemeral_mlkem768_public'),
      bytesField(enc, 'kem_ciphertext'),
      bytesField(enc, 'nonce'),
      bytesField(enc, 'ciphertext'),
      bytesField(enc, 'tag'),
    ]);

// ── keygen ───────────────────────────────────────────────────────────────
Future<void> keygen(String name) async {
  final pubPath = '$name.pub';
  final keyPath = '$name.key';
  await refuseOverwrite(pubPath);
  await refuseOverwrite(keyPath);

  final x = await x25519GenerateKeyPair();
  final k = mlkemGenerateKeyPair();
  final edKp = await ed25519.newKeyPair();
  final edSeed = await edKp.extractPrivateKeyBytes();
  final edPub = (await edKp.extractPublicKey()).bytes;
  final fp = await fingerprintOf([x.publicKey, k.publicKey, edPub]);

  final pub = {
    'format': formatId,
    'type': 'public',
    'fingerprint': fp,
    'x25519_public': encodeB64url(x.publicKey),
    'mlkem768_public': encodeB64url(k.publicKey),
    'ed25519_public': encodeB64url(edPub),
  };
  final key = {
    ...pub,
    'type': 'secret',
    'x25519_private': encodeB64url(x.privateKey),
    'mlkem768_secret': encodeB64url(k.secretKey),
    'ed25519_private_seed': encodeB64url(edSeed),
  };
  await File(pubPath).writeAsString(jsonOut.convert(pub));
  await File(keyPath).writeAsString(jsonOut.convert(key));

  print('Created key pair "$name"');
  print('  Fingerprint: $fp');
  print('  $pubPath  public: share it with people who send or receive files with you');
  print('  $keyPath  SECRET: never share it');
  print('Tell people your fingerprint directly (in person or on a call) so');
  print('they can check that the .pub file they have is really yours.');
  print('Note: the .key file is not password-protected (demo only).');
}

// ── encrypt ──────────────────────────────────────────────────────────────
Future<void> encrypt(String myKeyPath, String theirPubPath, String inPath) async {
  final meJson = await readJson(myKeyPath, 'secret');
  final me = await Identity.fromJson(meJson, myKeyPath);
  final them =
      await Identity.fromJson(await readJson(theirPubPath, 'public'), theirPubPath);

  final inFile = File(inPath);
  if (!await inFile.exists()) throw FormatException('File not found: $inPath');
  final plaintext = await inFile.readAsBytes();
  final outPath = '$inPath.enc';
  await refuseOverwrite(outPath);

  // One-time handshake keys, discarded after this run.
  final eX = await x25519GenerateKeyPair();
  final eKem = mlkemGenerateKeyPair();

  final kem = mlkemEncapsulate(them.mlkemPub);
  final kemCtB64 = encodeB64url(kem.ciphertext);

  // The sender's identity fingerprint is in the transcript, so the file key
  // depends on who the sender claims to be.
  final transcript = buildTranscript(
    encapsulatorFp: me.fingerprint,
    decapsulatorFp: them.fingerprint,
    encapsulatorX25519Pub: encodeB64url(eX.publicKey),
    decapsulatorX25519Pub: encodeB64url(them.x25519Pub),
    encapsulatorMlkemPub: encodeB64url(eKem.publicKey),
    decapsulatorMlkemPub: encodeB64url(them.mlkemPub),
    kemCt: kemCtB64,
  );
  final ssDH =
      await x25519SharedSecret(eX.privateKey, eX.publicKey, them.x25519Pub);
  final root = await deriveHybridRoot(
      ssDH: ssDH, ssKEM: kem.sharedSecret, transcript: transcript);

  final aead = Chacha20.poly1305Aead();
  final box = await aead.encrypt(plaintext, secretKey: await fileKeyFrom(root));

  final enc = <String, dynamic>{
    'format': formatId,
    'type': 'encrypted',
    'sender_fingerprint': me.fingerprint,
    'recipient_fingerprint': them.fingerprint,
    'ephemeral_x25519_public': encodeB64url(eX.publicKey),
    'ephemeral_mlkem768_public': encodeB64url(eKem.publicKey),
    'kem_ciphertext': kemCtB64,
    'nonce': encodeB64url(box.nonce),
    'ciphertext': encodeB64url(box.cipherText),
    'tag': encodeB64url(box.mac.bytes),
  };

  final signingKey =
      await ed25519.newKeyPairFromSeed(bytesField(meJson, 'ed25519_private_seed'));
  final derivedPub = (await signingKey.extractPublicKey()).bytes;
  if (hex(derivedPub) != hex(me.ed25519Pub)) {
    throw FormatException('$myKeyPath is damaged (signing key mismatch).');
  }
  final signature = await ed25519.sign(signedBytes(enc), keyPair: signingKey);
  enc['signature'] = encodeB64url(signature.bytes);

  await File(outPath).writeAsString(jsonOut.convert(enc));

  print('Encrypted $inPath -> $outPath');
  print('  From (signed by): ${me.fingerprint}');
  print('  To:               ${them.fingerprint}');
  print('  KEM ciphertext:   ${preview(kem.ciphertext)}');
  print('  Ciphertext:       ${preview(box.cipherText)}');
  print('  Signature:        ${preview(signature.bytes)}');
  print('Only the holder of the recipient\'s .key file can decrypt it.');
}

// ── decrypt ──────────────────────────────────────────────────────────────
Future<void> decrypt(String myKeyPath, String senderPubPath, String encPath) async {
  final meJson = await readJson(myKeyPath, 'secret');
  final me = await Identity.fromJson(meJson, myKeyPath);
  final sender = await Identity.fromJson(
      await readJson(senderPubPath, 'public'), senderPubPath);
  final enc = await readJson(encPath, 'encrypted');

  if (field(enc, 'recipient_fingerprint') != me.fingerprint) {
    throw FormatException('$encPath was encrypted to a different key '
        '(${field(enc, 'recipient_fingerprint')}), not $myKeyPath '
        '(${me.fingerprint}).');
  }
  if (field(enc, 'sender_fingerprint') != sender.fingerprint) {
    throw FormatException('$encPath says it was sent by '
        '${field(enc, 'sender_fingerprint')}, but $senderPubPath is '
        '${sender.fingerprint}. Use the sender\'s .pub file.');
  }
  final outPath = decryptedNameFor(encPath);
  await refuseOverwrite(outPath);

  // 1. Check the signature before touching anything else.
  final sigOk = await ed25519.verify(
    signedBytes(enc),
    signature: Signature(
      bytesField(enc, 'signature'),
      publicKey: SimplePublicKey(sender.ed25519Pub, type: KeyPairType.ed25519),
    ),
  );
  if (!sigOk) {
    print('SIGNATURE INVALID: this file was not signed by $senderPubPath,');
    print('or it was modified after signing. No output was written.');
    exitCode = 1;
    return;
  }

  // 2. Repeat the handshake as the recipient.
  final eX = bytesField(enc, 'ephemeral_x25519_public');
  final eKem = bytesField(enc, 'ephemeral_mlkem768_public');
  final kemCt = bytesField(enc, 'kem_ciphertext');

  final kemSecret = mlkemDecapsulate(kemCt, bytesField(meJson, 'mlkem768_secret'));
  final transcript = buildTranscript(
    encapsulatorFp: sender.fingerprint,
    decapsulatorFp: me.fingerprint,
    encapsulatorX25519Pub: encodeB64url(eX),
    decapsulatorX25519Pub: encodeB64url(me.x25519Pub),
    encapsulatorMlkemPub: encodeB64url(eKem),
    decapsulatorMlkemPub: encodeB64url(me.mlkemPub),
    kemCt: encodeB64url(kemCt),
  );
  final ssDH = await x25519SharedSecret(
      bytesField(meJson, 'x25519_private'), me.x25519Pub, eX);
  final root = await deriveHybridRoot(
      ssDH: ssDH, ssKEM: kemSecret, transcript: transcript);

  // 3. Decrypt.
  final aead = Chacha20.poly1305Aead();
  final box = SecretBox(
    bytesField(enc, 'ciphertext'),
    nonce: bytesField(enc, 'nonce'),
    mac: Mac(bytesField(enc, 'tag')),
  );
  List<int> plaintext;
  try {
    plaintext = await aead.decrypt(box, secretKey: await fileKeyFrom(root));
  } on SecretBoxAuthenticationError {
    print('DECRYPTION FAILED: the file was modified or the key is wrong.');
    print('No output was written.');
    exitCode = 1;
    return;
  }

  await File(outPath).writeAsBytes(plaintext);
  print('Signature valid: signed by ${sender.fingerprint} ($senderPubPath)');
  print('Decrypted $encPath -> $outPath  (${plaintext.length} bytes)');

  try {
    final text = utf8.decode(plaintext);
    if (text.length <= 2000) {
      print('--- decrypted text ---');
      print(text);
      print('----------------------');
    }
  } on FormatException {
    // Not UTF-8 text (e.g. an image); the file is still written.
  }
}

Future<void> main(List<String> args) async {
  try {
    if (args.length == 2 && args[0] == 'keygen') {
      await keygen(args[1]);
    } else if (args.length == 4 && args[0] == 'encrypt') {
      await encrypt(args[1], args[2], args[3]);
    } else if (args.length == 4 && args[0] == 'decrypt') {
      await decrypt(args[1], args[2], args[3]);
    } else {
      usage();
      exitCode = 64;
    }
  } on FormatException catch (e) {
    print('Error: ${e.message}');
    exitCode = 1;
  } on FileSystemException catch (e) {
    final reason = e.osError?.message ?? e.message;
    print('Error: cannot access ${e.path ?? 'file'}: $reason');
    exitCode = 1;
  }
}
