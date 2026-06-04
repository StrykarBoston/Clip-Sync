<p align="center">
  <img src="assets/icon.jpg" width="150" alt="ClipSync Logo">
</p>

# ClipSync
**A seamless, cross-platform clipboard synchronizer for Windows, Linux, and Android.**

ClipSync creates an encrypted, decentralized P2P mesh network over your local Wi-Fi. The moment you copy text on one device, it instantly appears on the clipboards of all your other connected devices. No cloud servers, no accounts, no internet routing—just instant, secure local synchronization.

---

## 🌟 Features
* **Cross-Platform**: Native support for Windows 11, Kali Linux (and other distros), and Android (10+).
* **True P2P Architecture**: Decentralized mesh network using mDNS (Zeroconf) and Secure WebSockets (`wss://`).
* **Military-Grade Security**: TLS 1.3 Transport Encryption + 100% End-to-End Encrypted (E2EE) payloads using AES-256-GCM.
* **Content Filtering**: Automatically detects and blocks syncing of highly sensitive data like Credit Cards and Private Keys.
* **No Cloud Dependency**: Works entirely offline on your local Local Area Network (LAN).
* **Lightweight Desktop Clients**: The Windows and Linux clients are written in pure Python, bypassing the need for heavy Visual Studio Build Tools or Flutter desktop environments.

---

## 🔒 Security Configuration (Required)

Before running ClipSync on any device, you MUST configure your encryption key. Without this, devices will reject connections.

1. Locate the `.env.example` file in any of the project directories.
2. Rename `.env.example` to `.env`.
3. Generate a secure, random 64-character hexadecimal string (32 bytes). You can do this in Python via:
   ```python
   import secrets; print(secrets.token_hex(32))
   ```
4. Paste the generated key into the `.env` file and set the static port:
   ```env
   SECRET_KEY=your_generated_hex_key_here
   PORT=52300
   SYNC_SENSITIVE_DATA=false
   ```
5. **Crucial:** You must copy this exact same `.env` file to the root of the Windows, Linux, and Android project folders on all your devices.

> **Warning:** Never upload your `.env` file to a public repository! (Especially if you build the Android APK, as it gets compiled into the assets).

---

## 💻 Installation & Setup

### 🪟 Windows Setup
The Windows client runs silently as a background Python script.

**Prerequisites:** Python 3.10+
1. Navigate to the Windows directory: `cd clip_sync_windows`
2. Install dependencies:
   ```cmd
   pip install pyperclip websockets zeroconf cryptography python-dotenv
   ```
3. Run the client:
   ```cmd
   python clip_sync.py
   ```
   *(Pro tip: Create a `.bat` file and place it in your Windows Startup folder to run ClipSync automatically on boot).*

### 🐧 Linux Setup
The Linux client is also a lightweight Python script.

**Prerequisites:** Python 3.10+ and an X11/Wayland clipboard manager.
1. Install system clipboard tools:
   ```bash
   sudo apt-get update
   sudo apt-get install xclip xsel
   ```
2. Navigate to the Linux directory: `cd clip_sync_linux`
3. Install dependencies:
   ```bash
   pip3 install pyperclip websockets zeroconf cryptography python-dotenv
   ```
4. Run the client:
   ```bash
   python3 clip_sync.py
   ```

### 📱 Android Setup (Flutter)
Due to Android 10+ background clipboard restrictions, the Android app integrates with your system's "Share" menu and provides a persistent notification for manual syncing.

**Prerequisites:** Flutter SDK installed, or you can compile an APK directly.
1. Navigate to the main directory: `cd clip_sync`
2. Fetch dependencies: `flutter pub get`
3. Build the release APK:
   ```bash
   flutter build apk --release
   ```
4. Transfer `build/app/outputs/flutter-apk/app-release.apk` to your phone and install it.
5. **Usage on Android:** 
   * **To send to PC:** Highlight text -> tap "Share" -> choose "ClipSync".
   * **To receive from PC:** Open the persistent ClipSync notification and tap "Sync" to grab the latest text from the mesh network.

---

## 🛠️ Troubleshooting & Debugging

If devices aren't syncing, check the following:

**1. Devices cannot find each other (No mDNS Discovery)**
* **Cause:** Your router is blocking mDNS multicast packets, or "AP Isolation" (Guest Mode) is turned on in your Wi-Fi settings.
* **Fix:** Log into your router and disable "AP Isolation", "Client Isolation", or "Guest Network". Ensure multicasting is enabled.

**2. "SECRET_KEY not found" or "Decryption Failed" Logs**
* **Cause:** Your `.env` files don't perfectly match across devices, or you forgot to rename `.env.example`.
* **Fix:** Verify that `SECRET_KEY=...` is identical on Windows, Linux, and Android.

**3. Linux client crashes with `PyperclipException`**
* **Cause:** `pyperclip` cannot interface with your Linux clipboard.
* **Fix:** Ensure you ran `sudo apt-get install xclip xsel`. If you are using Wayland instead of X11, you may need to install `wl-clipboard` (`sudo apt-get install wl-clipboard`).

**4. Windows Script closes immediately**
* **Cause:** Missing Python dependencies or syntax errors.
* **Fix:** Open CMD, run `python clip_sync.py` manually, and read the console output. Ensure `cryptography` and `python-dotenv` are installed globally or in your active virtual environment.


## 🤝 Contributing
Feel free to open issues or submit Pull Requests for enhancements!
