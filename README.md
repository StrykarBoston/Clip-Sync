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
* **Advanced Replay Protection**: Strict 30-second timestamp windows and dynamic Nonce caching to thwart Replay Attacks.
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
5. **Crucial:** You must copy this exact same `.env` file to the root of the **Windows** and **Linux** project folders. *(For Android, you will simply paste the key directly into the app's Setup screen!)*

> **Warning:** Never upload your `.env` file to a public repository! The desktop `.env` files are kept strictly local.

### 🔑 TLS Certificate Management

ClipSync uses transport-layer encryption via Secure WebSockets (`wss://`). Each device operates as an autonomous node with its own self-signed TLS certificates.

* **Self-Healing Auto-Regeneration:** At startup, the **Windows** and **Linux** Python nodes will check if the Subject Alternative Name (SAN) inside their existing certificate matches their current local LAN IP. If there is a mismatch (e.g., due to DHCP assignment), the client automatically regenerates a secure, 1-year validity TLS certificate with the correct IP SAN in-place.
* **Manual Certificate Generation:** You can manually generate certificates for specific platforms using the upgraded `generate_cert.py` script:
  ```bash
  # Generate for a specific platform (outputs directly to the target folders)
  python generate_cert.py --target [windows|linux|android|certs|all]

  # Generate with an explicit IP override (useful if node has multiple network interfaces)
  python generate_cert.py --target android --ip 192.168.1.7
  ```

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

**You do NOT need to compile the app from source!** You can simply install the pre-compiled APK.

1. Download the latest `app-release.apk` from GitHub and install it on your Android device.
2. Open the ClipSync app. It will present a **Setup Screen**.
3. Paste the exact same 64-character `SECRET_KEY` that you generated for your Windows/Linux nodes into the text field.
4. Tap **Save & Connect**. The key is securely saved to your phone's encrypted local storage—your key is never uploaded anywhere.
5. **Usage on Android:** 
   * **To send to PC:** Highlight text -> tap "Share" -> choose "ClipSync".
   * **To receive from PC:** Open the persistent ClipSync notification and tap "Sync" to grab the latest text from the mesh network.
   * **To change your key:** Tap the Settings gear icon in the top right of the app.

---

## 🛠️ Troubleshooting & Debugging

If devices aren't syncing, check the following:

**1. Devices cannot find each other (No mDNS Discovery)**
* **Cause:** Your router is blocking mDNS multicast packets, or "AP Isolation" (Guest Mode) is turned on in your Wi-Fi settings.
* **Fix:** Log into your router and disable "AP Isolation", "Client Isolation", or "Guest Network". Ensure multicasting is enabled.

**2. "SECRET_KEY not found" or "Decryption Failed" Logs**
* **Cause:** Your secret keys do not perfectly match across your devices.
* **Fix:** Verify that the `SECRET_KEY=...` in your Windows/Linux `.env` files perfectly matches the 64-character key you typed into the Android Settings screen.

**3. Linux client crashes with `PyperclipException`**
* **Cause:** `pyperclip` cannot interface with your Linux clipboard.
* **Fix:** Ensure you ran `sudo apt-get install xclip xsel`. If you are using Wayland instead of X11, you may need to install `wl-clipboard` (`sudo apt-get install wl-clipboard`).

**4. Windows Script closes immediately**
* **Cause:** Missing Python dependencies or syntax errors.
* **Fix:** Open CMD, run `python clip_sync.py` manually, and read the console output. Ensure `cryptography` and `python-dotenv` are installed globally or in your active virtual environment.


## 🤝 Contributing
Feel free to open issues or submit Pull Requests for enhancements!
