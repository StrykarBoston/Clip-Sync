import 'dart:async';
import 'dart:io';

import 'package:nsd/nsd.dart';
import 'package:uuid/uuid.dart';
import 'package:clip_sync/sync/security_manager.dart';
import 'dart:convert';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:cryptography/cryptography.dart';

class SyncManager {
  static final SyncManager _instance = SyncManager._internal();
  factory SyncManager() => _instance;
  SyncManager._internal();

  final String deviceId = const Uuid().v4();

  Registration? _registration;
  Discovery? _discovery;

  HttpServer? _server;
  final List<WebSocket> _clients = [];

  final _clipboardStreamController = StreamController<String>.broadcast();
  Stream<String> get onClipboardReceived => _clipboardStreamController.stream;

  final Set<String> _connectedPeers = {};
  final SecurityManager _securityManager = SecurityManager();

  int get port => int.tryParse(dotenv.env['PORT'] ?? '52300') ?? 52300;
  bool get syncSensitiveData => dotenv.env['SYNC_SENSITIVE_DATA']?.toLowerCase() == 'true';
  String get secretKey => dotenv.env['SECRET_KEY'] ?? '';

  Future<String> _getNetworkFingerprint() async {
    if (secretKey.isEmpty) return "";
    final algorithm = Sha256();
    final hash = await algorithm.hash(utf8.encode(secretKey));
    return hash.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join().substring(0, 16);
  }

  bool isSensitive(String text) {
    if (syncSensitiveData) return false;
    if (RegExp(r'\b(?:\d[ -]*?){13,19}\b').hasMatch(text)) return true;
    if (text.contains('-----BEGIN') && text.contains('PRIVATE KEY-----')) return true;
    return false;
  }

  Future<void> initialize() async {
    // Start local WebSocket server
    await _startServer();

    // Register mDNS service
    await _registerService();

    // Start discovering peers
    await _startDiscovery();
  }

  Future<void> _startServer() async {
    try {
      final certBytes = await rootBundle.load('assets/certs/tls_cert.pem');
      final keyBytes = await rootBundle.load('assets/certs/tls_key.pem');
      
      SecurityContext securityContext = SecurityContext()
        ..useCertificateChainBytes(certBytes.buffer.asUint8List())
        ..usePrivateKeyBytes(keyBytes.buffer.asUint8List());

      _server = await HttpServer.bindSecure(InternetAddress.anyIPv4, port, securityContext);
      print('Secure WSS Server started on port ${_server!.port}');

      _server!.listen((HttpRequest request) {
        if (WebSocketTransformer.isUpgradeRequest(request)) {
          WebSocketTransformer.upgrade(request).then((WebSocket ws) {
            _handleConnection(ws);
          });
        }
      });
    } catch (e) {
      print('Failed to start server: $e');
    }
  }

  void _handleConnection(WebSocket ws) async {
    _clients.add(ws);
    
    bool isAuthenticated = false;
    Timer? authTimeout;
    
    authTimeout = Timer(const Duration(seconds: 2), () {
      if (!isAuthenticated) {
        print('Peer auth handshake timed out');
        ws.close();
      }
    });

    ws.listen(
      (data) async {
        try {
          final message = await _securityManager.decryptMessage(data as String);
          if (message == null) {
            // Decryption failed or invalid payload, ignore to prevent attacks
            return;
          }

          if (message['type'] == 'hello') {
            isAuthenticated = true;
            authTimeout?.cancel();
            final peerId = message['deviceId'];
            _connectedPeers.add(peerId);
            print('Securely connected to peer: $peerId');
          } else if (message['type'] == 'clipboard') {
            if (!isAuthenticated) return;
            final text = message['text'];
            _clipboardStreamController.add(text);
          }
        } catch (e) {
          print('Invalid message: $e');
        }
      },
      onDone: () {
        _clients.remove(ws);
      },
      onError: (e) {
        _clients.remove(ws);
      },
    );

    // Say hello
    final helloMessage = await _securityManager.encryptMessage({'type': 'hello', 'deviceId': deviceId});
    ws.add(helloMessage);
  }

  Future<void> _registerService() async {
    if (_server == null) return;
    
    try {
      _registration = await register(
        Service(
          name: 'ClipSync Android-${deviceId.substring(0, 4)}',
          type: '_clipsync._tcp',
          host: '', 
          port: _server!.port,
          txt: {'fingerprint': utf8.encode(await _getNetworkFingerprint())},
        ),
      );
    } catch (e) {
      print('Register failed: $e');
    }
  }

  Future<void> _startDiscovery() async {
    try {
      _discovery = await startDiscovery('_clipsync._tcp');
      _discovery!.addListener(() {
        for (final service in _discovery!.services) {
          _connectToService(service);
        }
      });
    } catch (e) {
      print('Discovery failed: $e');
    }
  }

  Future<void> _connectToService(Service service) async {
    if (service.host == null || service.port == null) return;
    
    final host = service.host!;
    final port = service.port!;

    final fingerprint = service.txt?['fingerprint'];
    final expected = await _getNetworkFingerprint();
    if (fingerprint == null || utf8.decode(fingerprint) != expected) {
      print('Discovered peer $host:$port with invalid fingerprint. Ignoring.');
      return;
    }

    try {
      final ws = await WebSocket.connect('wss://$host:$port');
      _handleConnection(ws);
    } catch (e) {
      print('Could not connect to service $host:$port: $e');
    }
  }

  Future<void> broadcastClipboard(String text) async {
    if (isSensitive(text)) {
      print('Sensitive data detected in clipboard. Sync paused for this item.');
      return;
    }
    final message = await _securityManager.encryptMessage({'type': 'clipboard', 'text': text});
    for (final ws in _clients) {
      ws.add(message);
    }
  }

  void dispose() {
    if (_registration != null) unregister(_registration!);
    if (_discovery != null) stopDiscovery(_discovery!);
    _server?.close();
  }
}
