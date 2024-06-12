from Algorithm.ECC import ECC
from Algorithm.ECDSA import ECDSA
from Algorithm.JWT import JWT
from datetime import datetime, timedelta

# Generate keys using ECC
private_key, public_key = ECC.generate_keys()

# Serialize keys to store them
private_key_pem = ECC.serialize_private_key(private_key)
public_key_pem = ECC.serialize_public_key(public_key)

print("Private Key:")
print(private_key_pem)

print("Public Key:")
print(public_key_pem)

# Deserialize keys to use them
private_key = ECC.deserialize_private_key(private_key_pem)
public_key = ECC.deserialize_public_key(public_key_pem)

# Create ECDSA instance
ecdsa_instance = ECDSA(private_key, public_key)

# Create JWT instance
jwt_instance = JWT(ecdsa_instance)

# Create JWT
header = {
    'alg': 'ES256',
    'typ': 'JWT'
}

# payload = {
#     'sub': '13521084',
#     'name': 'Austin Gabriel Pardosi'
# }

# payload = {
#     'sub': '13521084',
#     'name': 'Austin Gabriel Pardosi',
#     'email': 'gabrielpardosi26@gmail.com',
#     'iat': datetime.utcnow().isoformat(),
#     'exp': (datetime.utcnow() + timedelta(minutes=30)).isoformat()
# }

payload = {
    'sub': '13521084',
    'name': 'Austin Gabriel Pardosi',
    'email': 'gabrielpardosi26@gmail.com',
    'address': 'Jl. Ganesa No.10, Lb. Siliwangi, Kecamatan Coblong, Kota Bandung, Jawa Barat 40132',
    'phone': '+6281313131313',
    'roles': ['admin', 'user', 'guest'],
    'permissions': {
        'read': True,
        'write': True,
        'delete': False
    },
    'iat': datetime.utcnow().isoformat(),
    'exp': (datetime.utcnow() + timedelta(hours=1)).isoformat(),
    'additional_info': 'This is a very large payload to test the limits of the JWT implementation. ' * 10 
}


token = jwt_instance.encode(header, payload)
print("\nJWT Token:")
print(token)

# Decode JWT
try:
    decoded_payload = jwt_instance.decode(token)
    print("\nDecoded Payload:")
    print(decoded_payload)
except ValueError as e:
    print("\nError decoding token:", e)
