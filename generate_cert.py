import argparse
import datetime
import socket
import ipaddress
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Maps --target values to output directories
TARGET_DIRS = {
    'windows': ['clip_sync_windows'],
    'linux':   ['clip_sync_linux'],
    'android': ['assets/certs'],
    'certs':   ['certs'],
}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def generate_self_signed_cert(output_dirs, override_ip=None):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate public certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ClipSync Local Mesh"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    
    local_ip = override_ip or get_local_ip()
    san_list = [
        x509.DNSName(u"localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    if local_ip != "127.0.0.1":
        san_list.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        # Valid for 1 year
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    for output_dir in output_dirs:
        os.makedirs(output_dir, exist_ok=True)
        cert_path = os.path.join(output_dir, 'tls_cert.pem')
        key_path = os.path.join(output_dir, 'tls_key.pem')

        with open(cert_path, 'wb') as f:
            f.write(cert_pem)
        with open(key_path, 'wb') as f:
            f.write(key_pem)

        print(f"  ✓ Written to {output_dir}/")

    # Print verification info
    san_names = [str(s.value) for s in san_list]
    not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
    print(f"\n  Detected LAN IP:  {local_ip}")
    print(f"  SAN entries:      {', '.join(san_names)}")
    print(f"  Validity:         1 year (expires {not_after.strftime('%Y-%m-%d')})")
    print(f"  Key size:         2048-bit RSA")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate self-signed TLS certificates for ClipSync nodes."
    )
    parser.add_argument(
        '--target',
        choices=['windows', 'linux', 'android', 'all'],
        default='all',
        help='Which platform to generate certs for (default: all)'
    )
    parser.add_argument(
        '--ip',
        default=None,
        help='Override auto-detected LAN IP (e.g. 192.168.1.11)'
    )
    args = parser.parse_args()

    if args.target == 'all':
        output_dirs = []
        for dirs in TARGET_DIRS.values():
            output_dirs.extend(dirs)
    else:
        output_dirs = TARGET_DIRS[args.target]

    print(f"Generating TLS cert for target: {args.target}")
    generate_self_signed_cert(output_dirs, override_ip=args.ip)
    print("\nDone! Each device should generate its own cert independently.")
    print("Do NOT copy certs between devices — run this script on each device.")
