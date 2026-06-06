import 'dart:convert';
import 'package:cryptography/cryptography.dart';

class SecurityManager {
  late final SecretKey _secretKey;
  final _algorithm = AesGcm.with256bits();

  void initialize(String sharedSecretHex) {
    if (sharedSecretHex.isEmpty) {
      throw Exception('SECRET_KEY cannot be empty!');
    }
    _secretKey = SecretKey(_hexDecode(sharedSecretHex));
  }

  List<int> _hexDecode(String hexStr) {
    final result = <int>[];
    for (int i = 0; i < hexStr.length; i += 2) {
      result.add(int.parse(hexStr.substring(i, i + 2), radix: 16));
    }
    return result;
  }

  Future<String> encryptMessage(Map<String, dynamic> messageDict) async {
    final plaintext = utf8.encode(jsonEncode(messageDict));
    
    final secretBox = await _algorithm.encrypt(
      plaintext,
      secretKey: _secretKey,
    );

    // To interoperate with python's cryptography AESGCM:
    // Python returns ciphertext + mac as a single bytes object.
    final dataBytes = <int>[...secretBox.cipherText, ...secretBox.mac.bytes];

    final payload = {
      'iv': base64Encode(secretBox.nonce),
      'data': base64Encode(dataBytes),
    };

    return jsonEncode(payload);
  }

  Future<Map<String, dynamic>?> decryptMessage(String payloadStr) async {
    try {
      final payload = jsonDecode(payloadStr);
      if (payload['iv'] == null || payload['data'] == null) return null;

      final nonce = base64Decode(payload['iv']);
      final dataBytes = base64Decode(payload['data']);
      
      if (dataBytes.length < 16) return null; // Needs at least the 16 byte MAC

      final cipherText = dataBytes.sublist(0, dataBytes.length - 16);
      final macBytes = dataBytes.sublist(dataBytes.length - 16);

      final secretBox = SecretBox(
        cipherText,
        nonce: nonce,
        mac: Mac(macBytes),
      );

      final clearTextBytes = await _algorithm.decrypt(
        secretBox,
        secretKey: _secretKey,
      );

      return jsonDecode(utf8.decode(clearTextBytes));
    } catch (e) {
      print('Decryption failed: $e');
      return null;
    }
  }
}
