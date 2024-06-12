import base64
import json
from datetime import datetime, timedelta
from Algorithm.ECDSA import ECDSA

class JWT:
    def __init__(self, ecdsa: ECDSA):
        self.ecdsa = ecdsa

    def base64_url_encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip("=")

    def base64_url_decode(self, data: str) -> bytes:
        padding = '=' * (4 - (len(data) % 4))
        return base64.urlsafe_b64decode(data + padding)

    def datetime_to_str(self, dt: datetime) -> str:
        return dt.isoformat()

    def str_to_datetime(self, dt_str: str) -> datetime:
        return datetime.fromisoformat(dt_str)

    def encode(self, header: dict, payload: dict) -> str:
        # Convert datetime objects to strings
        for key, value in payload.items():
            if isinstance(value, datetime):
                payload[key] = self.datetime_to_str(value)

        header_encoded = self.base64_url_encode(json.dumps(header).encode('utf-8'))
        payload_encoded = self.base64_url_encode(json.dumps(payload).encode('utf-8'))

        signature_input = f'{header_encoded}.{payload_encoded}'.encode('utf-8')
        signature = self.ecdsa.sign(signature_input)

        jwt_token = f'{header_encoded}.{payload_encoded}.{self.base64_url_encode(signature)}'
        return jwt_token

    def decode(self, token: str) -> dict:
        header_encoded, payload_encoded, signature_encoded = token.split('.')

        signature_input = f'{header_encoded}.{payload_encoded}'.encode('utf-8')
        signature = self.base64_url_decode(signature_encoded)

        if self.ecdsa.verify(signature_input, signature):
            payload = json.loads(base64.urlsafe_b64decode(payload_encoded + "=="))
            # Convert string dates back to datetime objects
            for key, value in payload.items():
                if isinstance(value, str):
                    try:
                        payload[key] = self.str_to_datetime(value)
                    except ValueError:
                        pass
            return payload
        else:
            raise ValueError('Invalid Token')
