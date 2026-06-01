import 'dart:async';
import 'dart:io';

import 'package:nsd/nsd.dart';
import 'package:uuid/uuid.dart';
import 'package:clip_sync/sync/security_manager.dart';

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
      _server = await HttpServer.bind(InternetAddress.anyIPv4, 0);
      print('Secure WebSocket Server started on port ${_server!.port}');

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
    ws.listen(
      (data) async {
        try {
          final message = await _securityManager.decryptMessage(data as String);
          if (message == null) {
            // Decryption failed or invalid payload, ignore to prevent attacks
            return;
          }

          if (message['type'] == 'clipboard') {
            final text = message['text'];
            _clipboardStreamController.add(text);
          } else if (message['type'] == 'hello') {
            final peerId = message['deviceId'];
            _connectedPeers.add(peerId);
            print('Securely connected to peer: $peerId');
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
          name: 'ClipSync Service',
          type: '_clipsync._tcp',
          host: '', 
          port: _server!.port,
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

    try {
      final ws = await WebSocket.connect('ws://$host:$port');
      _handleConnection(ws);
    } catch (e) {
      print('Could not connect to service $host:$port: $e');
    }
  }

  Future<void> broadcastClipboard(String text) async {
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
