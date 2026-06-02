import 'dart:io';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:receive_sharing_intent/receive_sharing_intent.dart';
import 'dart:async';
import 'package:flutter/foundation.dart';

class AndroidManager {
  static final AndroidManager _instance = AndroidManager._internal();
  factory AndroidManager() => _instance;
  AndroidManager._internal();

  final FlutterLocalNotificationsPlugin _notificationsPlugin = FlutterLocalNotificationsPlugin();
  
  Function(String text)? onShareReceived;
  Function()? onSyncAction;

  StreamSubscription? _intentDataStreamSubscription;

  Future<void> initialize() async {
    if (kIsWeb || !Platform.isAndroid) return;

    // 1. Setup Notifications
    const AndroidInitializationSettings initializationSettingsAndroid =
        AndroidInitializationSettings('@mipmap/launcher_icon');
    const InitializationSettings initializationSettings =
        InitializationSettings(android: initializationSettingsAndroid);

    await _notificationsPlugin.resolvePlatformSpecificImplementation<
        AndroidFlutterLocalNotificationsPlugin>()?.requestNotificationsPermission();

    await _notificationsPlugin.initialize(
      settings: initializationSettings,
      onDidReceiveNotificationResponse: (NotificationResponse response) {
        if (response.actionId == 'sync_clipboard') {
          if (onSyncAction != null) onSyncAction!();
        }
      },
    );

    _showPersistentNotification();

    // 2. Setup Share Intent
    _intentDataStreamSubscription = ReceiveSharingIntent.instance.getMediaStream().listen((List<SharedMediaFile> value) {
      if (value.isNotEmpty && value.first.type == SharedMediaType.text) {
        if (onShareReceived != null) onShareReceived!(value.first.path); // Usually path holds text for TEXT intent
      }
    }, onError: (err) {
      print("Share Intent Error: $err");
    });

    // Get the media sharing coming from outside the app while the app is closed.
    ReceiveSharingIntent.instance.getInitialMedia().then((List<SharedMediaFile> value) {
      if (value.isNotEmpty && value.first.type == SharedMediaType.text) {
        if (onShareReceived != null) onShareReceived!(value.first.path);
      }
    });
  }

  Future<void> _showPersistentNotification() async {
    const AndroidNotificationDetails androidPlatformChannelSpecifics =
        AndroidNotificationDetails(
      'clip_sync_channel',
      'Clipboard Sync',
      channelDescription: 'Persistent notification for manual clipboard sync',
      importance: Importance.low,
      priority: Priority.low,
      ongoing: true, // Persistent
      actions: <AndroidNotificationAction>[
        AndroidNotificationAction(
          'sync_clipboard',
          'Sync Clipboard',
          showsUserInterface: true,
        ),
      ],
    );
    const NotificationDetails platformChannelSpecifics =
        NotificationDetails(android: androidPlatformChannelSpecifics);

    await _notificationsPlugin.show(
      id: 0,
      title: 'ClipSync Active',
      body: 'Tap Sync to share your clipboard',
      notificationDetails: platformChannelSpecifics,
    );
  }

  void dispose() {
    _intentDataStreamSubscription?.cancel();
  }
}
