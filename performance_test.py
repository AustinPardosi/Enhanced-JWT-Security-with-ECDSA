import time
import psutil
import jwt as pyjwt
from Algorithm.ECC import ECC
from Algorithm.ECDSA import ECDSA
from Algorithm.JWT import JWT
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Function to measure memory usage
def memory_usage():
    process = psutil.Process()
    mem_info = process.memory_info()
    return mem_info.rss

# Generate keys using ECC
private_key, public_key = ECC.generate_keys()
ecdsa_instance = ECDSA(private_key, public_key)
jwt_instance = JWT(ecdsa_instance)

# Serialize keys for pyjwt
private_key_pem = ECC.serialize_private_key(private_key)
public_key_pem = ECC.serialize_public_key(public_key)

header = {
    'alg': 'ES256',
    'typ': 'JWT'
}

# payload = {
#     'sub': '13521084',
#     'name': 'Austin Gabriel Pardosi'
# }

payload = {
    'sub': '13521084',
    'name': 'Austin Gabriel Pardosi',
    'email': 'gabrielpardosi26@gmail.com',
    'iat': datetime.utcnow().isoformat(),
    'exp': (datetime.utcnow() + timedelta(minutes=30)).isoformat()
}

# payload = {
#     'sub': '13521084',
#     'name': 'Austin Gabriel Pardosi',
#     'email': 'gabrielpardosi26@gmail.com',
#     'address': 'Jl. Ganesa No.10, Lb. Siliwangi, Kecamatan Coblong, Kota Bandung, Jawa Barat 40132',
#     'phone': '+6281313131313',
#     'roles': ['admin', 'user', 'guest'],
#     'permissions': {
#         'read': True,
#         'write': True,
#         'delete': False
#     },
#     'iat': datetime.utcnow().isoformat(),
#     'exp': (datetime.utcnow() + timedelta(hours=1)).isoformat(),
#     'additional_info': 'This is a very large payload to test the limits of the JWT implementation. ' * 10 
# }



# Measure time and memory to create JWT with custom ECDSA implementation
start_time = time.time()
start_memory = memory_usage()
custom_token = jwt_instance.encode(header, payload)
end_memory = memory_usage()
end_time = time.time()
custom_creation_time = end_time - start_time
custom_memory_usage_creation = end_memory - start_memory
print("\n\nCustom ECDSA JWT Token (before encoding):")
print(payload)
print("\nCustom ECDSA JWT Token (after encoding):")
print(custom_token)
print(f"\nTime to create JWT with custom ECDSA: {custom_creation_time:.6f} seconds")
print(f"\nMemory used to create JWT with custom ECDSA: {custom_memory_usage_creation / 1024:.2f} KB")

# Measure time and memory to verify JWT with custom ECDSA implementation
start_time = time.time()
start_memory = memory_usage()
try:
    custom_decoded_payload = jwt_instance.decode(custom_token)
    custom_verification_success = True
except ValueError:
    custom_verification_success = False
end_memory = memory_usage()
end_time = time.time()
custom_verification_time = end_time - start_time
custom_memory_usage_verification = end_memory - start_memory
print("\n\nCustom ECDSA JWT Token (after decoding):")
print(custom_decoded_payload)
print(f"\nTime to verify JWT with custom ECDSA: {custom_verification_time:.6f} seconds")
print(f"\nMemory used to verify JWT with custom ECDSA: {custom_memory_usage_verification / 1024:.2f} KB")
print(f"\nCustom verification success: {custom_verification_success}")

# Measure time and memory to create JWT with pyjwt
start_time = time.time()
start_memory = memory_usage()
pyjwt_token = pyjwt.encode(payload, private_key_pem, algorithm='ES256', headers=header)
end_memory = memory_usage()
end_time = time.time()
pyjwt_creation_time = end_time - start_time
pyjwt_memory_usage_creation = end_memory - start_memory
print("\n\npyjwt JWT Token (before encoding):")
print(payload)
print("\npyjwt JWT Token (after encoding):")
print(pyjwt_token)
print(f"\nTime to create JWT with pyjwt: {pyjwt_creation_time:.6f} seconds")
print(f"\nMemory used to create JWT with pyjwt: {pyjwt_memory_usage_creation / 1024:.2f} KB")

# Measure time and memory to verify JWT with pyjwt
start_time = time.time()
start_memory = memory_usage()
try:
    pyjwt_decoded_payload = pyjwt.decode(pyjwt_token, public_key_pem, algorithms=['ES256'])
    pyjwt_verification_success = True
except pyjwt.InvalidTokenError:
    pyjwt_verification_success = False
    pyjwt_decoded_payload = None
end_memory = memory_usage()
end_time = time.time()
pyjwt_verification_time = end_time - start_time
pyjwt_memory_usage_verification = end_memory - start_memory
print("\n\npyjwt JWT Token (after decoding):")
print(pyjwt_decoded_payload)
print(f"\nTime to verify JWT with pyjwt: {pyjwt_verification_time:.6f} seconds")
print(f"\nMemory used to verify JWT with pyjwt: {pyjwt_memory_usage_verification / 1024:.2f} KB")
print(f"\npyjwt verification success: {pyjwt_verification_success}")
