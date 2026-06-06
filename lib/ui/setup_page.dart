import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:clip_sync/main.dart';

class SetupPage extends StatefulWidget {
  const SetupPage({super.key});

  @override
  State<SetupPage> createState() => _SetupPageState();
}

class _SetupPageState extends State<SetupPage> {
  final _keyController = TextEditingController();

  void _saveAndConnect() async {
    final key = _keyController.text.trim();
    if (key.length != 64) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Key must be exactly 64 characters long (Hexadecimal).')),
      );
      return;
    }

    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('SECRET_KEY', key);

    if (mounted) {
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (context) => HomePage(secretKey: key)),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('ClipSync Setup')),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.security, size: 80, color: Colors.blueAccent),
            const SizedBox(height: 32),
            const Text(
              'Enter your 64-character Secret Key to join the mesh network.',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 18),
            ),
            const SizedBox(height: 32),
            TextField(
              controller: _keyController,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                labelText: 'Secret Key',
                hintText: 'e.g. 082aafe0...',
              ),
              maxLength: 64,
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: _saveAndConnect,
              icon: const Icon(Icons.save),
              label: const Text('Save & Connect'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
