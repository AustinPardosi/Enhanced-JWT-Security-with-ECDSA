from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


class ECC:
    def generate_keys():
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_private_key(private_key: ec.EllipticCurvePrivateKey) -> str:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pem.decode("utf-8")

    def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")

    def deserialize_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
        private_key = serialization.load_pem_private_key(
            pem.encode("utf-8"), password=None
        )
        return private_key

    def deserialize_public_key(pem: str) -> ec.EllipticCurvePublicKey:
        public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        return public_key
