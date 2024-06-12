from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature,
)


class ECDSA:
    def __init__(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        public_key: ec.EllipticCurvePublicKey,
    ):
        self.private_key = private_key
        self.public_key = public_key

    def sign(self, data: bytes) -> bytes:
        signature = self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False