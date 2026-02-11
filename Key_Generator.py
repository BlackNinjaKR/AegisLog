from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys(name):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    with open(f"{name}_private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
        )

    with open(f"{name}_public_key.pem", "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

generate_keys("server")
generate_keys("client")