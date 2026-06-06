import datetime
import socket
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def generate_self_signed_cert():
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
    
    local_ip = get_local_ip()
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
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valid for 1 year
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    os.makedirs('certs', exist_ok=True)
    os.makedirs('assets/certs', exist_ok=True)

    with open('certs/tls_cert.pem', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open('certs/tls_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    print("Certificate generated successfully in certs/ directory.")

if __name__ == "__main__":
    generate_self_signed_cert()
