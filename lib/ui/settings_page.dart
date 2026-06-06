import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:clip_sync/ui/setup_page.dart';

class SettingsPage extends StatelessWidget {
  final String currentKey;
  
  const SettingsPage({super.key, required this.currentKey});

  void _clearKey(BuildContext context) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('SECRET_KEY');
    
    if (context.mounted) {
      Navigator.pushAndRemoveUntil(
        context,
        MaterialPageRoute(builder: (context) => const SetupPage()),
        (route) => false,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Current Secret Key:', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.black12,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                currentKey,
                style: const TextStyle(fontFamily: 'monospace', color: Colors.grey),
              ),
            ),
            const SizedBox(height: 32),
            Center(
              child: ElevatedButton.icon(
                onPressed: () => _clearKey(context),
                icon: const Icon(Icons.delete, color: Colors.red),
                label: const Text('Clear Key & Disconnect', style: TextStyle(color: Colors.red)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.red.withOpacity(0.1),
                ),
              ),
            )
          ],
        ),
      ),
    );
  }
}
