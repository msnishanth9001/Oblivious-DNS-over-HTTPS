import os
import random
import struct
import pyhpke
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyPair
import hashlib
import hmac
import inspect

import requests
import http.client

OBLIVIOUS_DOH_CONTENT_TYPE = "application/oblivious-dns-message"

ODOH_VERSION = 0x0001
ODOH_SECRET_LENGTH = 32
ODOH_PADDING_BYTE = 0
ODOH_LABEL_KEY_ID = "odoh key id".encode()
ODOH_LABEL_KEY = "odoh key".encode()
ODOH_LABEL_NONCE = "odoh nonce".encode()
ODOH_LABEL_QUERY = "odoh query".encode()
ODOH_LABEL_RESPONSE = "odoh response".encode()

ODOH_DEFAULT_KEMID = KEMId.DHKEM_P256_HKDF_SHA256
ODOH_DEFAULT_KDFID = KDFId.HKDF_SHA256
ODOH_DEFAULT_AEADID = AEADId.AES128_GCM


class ObliviousDoHConfigContents:
    def __init__(self, kemID, kdfID, aeadID, publicKeyBytes):
        self.KemID = KEMId.DHKEM_X25519_HKDF_SHA256
        self.KdfID = KDFId.HKDF_SHA256
        self.AeadID = AEADId.AES128_GCM
        self.PublicKeyBytes = publicKeyBytes
    def __str__(self):
        return f"ObliviousDoHConfigContents: KemID={self.KemID}, KdfID={self.KdfID}, AeadID={self.AeadID}, PublicKeyBytes={' '.join(str(byte) for byte in self.PublicKeyBytes)}"

def CreateObliviousDoHConfigContents(kemID, kdfID, aeadID, publicKeyBytes):
    suite, err = hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
    if err != None:
        raise err

    _, err = suite.KEM.DeserializePublicKey(publicKeyBytes)
    if err != None:
        raise err

    return ObliviousDoHConfigContents(kemID, kdfID, aeadID, publicKeyBytes)

def Marshal(k):
    identifiers = struct.pack('>HHHH', k.KemID, k.KdfID, k.AeadID, len(k.PublicKeyBytes))
    return identifiers + k.PublicKeyBytes

def Unmarshal(buffer):
    if len(buffer) < 8:
        raise ValueError("Invalid serialized ObliviousDoHConfigContents")

    kemID, kdfID, aeadID, publicKeyLength = struct.unpack('>HHHH', buffer[:8])

    if len(buffer[8:]) < publicKeyLength:
        raise ValueError("Invalid serialized ObliviousDoHConfigContents")

    publicKeyBytes = buffer[8 : 8 + publicKeyLength]

    kemID = pyhpke.KEMId(kemID)
    kdfID = pyhpke.KDFId(kdfID)
    aeadID = pyhpke.AEADId(aeadID)

    if not kemID or not kdfID or not aeadID:
        raise ValueError(f"Unsupported KEMID: {kemID}, KDFID: {kdfID}, AEADID: {aeadID}")

    suite = CipherSuite.new(kemID, kdfID, aeadID)
    x = suite.kem.deserialize_public_key(publicKeyBytes)

    return ObliviousDoHConfigContents(kemID, kdfID, aeadID, publicKeyBytes)

class ObliviousDoHConfig:
    def __init__(self, version, contents):
        self.Version = version
        self.Contents = contents
    def __str__(self):
        return f"ObliviousDoHConfig: Version={self.Version}, Contents={self.Contents}"

def CreateObliviousDoHConfig(contents):
    return ObliviousDoHConfig(ODOH_VERSION, contents)

def ParseConfigHeader(buffer):
    if len(buffer) < 4:
        raise ValueError("Invalid ObliviousDoHConfig encoding")

    version, length = struct.unpack('>HH', buffer[:4])
    return version, length

def IsSupportedConfigVersion(version):
    return version == ODOH_VERSION

def UnmarshalObliviousDoHConfig(buffer):
    version, length = ParseConfigHeader(buffer)
    if not IsSupportedConfigVersion(version):
        raise ValueError(f"Unsupported version: {version}")

    if len(buffer[4:]) < length:
        raise ValueError("Invalid serialized ObliviousDoHConfig")

    contents = Unmarshal(buffer[4:])
    return ObliviousDoHConfig(version, contents)

class ObliviousDoHConfigs:
    def __init__(self, configs):
        self.Configs = configs
    def __str__(self):
        return f"ObliviousDoHConfigs: Configs={self.Configs}"

def CreateObliviousDoHConfigs(configs):
    return ObliviousDoHConfigs(configs)

def UnmarshalObliviousDoHConfigs(buffer):
    if len(buffer) < 2:
        raise ValueError("Invalid ObliviousDoHConfigs encoding")

    length = struct.unpack('>H', buffer[:2])[0]
    offset = 2
    configs = []

    while offset < length + 2:
        version, configLength = ParseConfigHeader(buffer[offset:])

        if IsSupportedConfigVersion(version) and offset + configLength <= length + 2:
            config = UnmarshalObliviousDoHConfig(buffer[offset:])
            configs.append(config)

        offset += configLength + 4

    return CreateObliviousDoHConfigs(configs)

class ObliviousDNSMessage:
    def __init__(self, KeyID, MessageType, EncryptedMessage):
        self.MessageType = MessageType
        self.KeyID = KeyID
        self.EncryptedMessage = EncryptedMessage

class QueryContext:
    def __init__(self, secret, suite, query, publicKey):
        self.secret = secret
        self.suite = suite
        self.query = query
        self.publicKey = publicKey

def encodeLengthPrefixedSlice(slice_data):
    length_prefix = len(slice_data).to_bytes(2, byteorder='big')
    return length_prefix + bytes(slice_data)

import hmac
from hashlib import sha256

def Extract(salt, ikm):
    hash_algorithm = sha256
    salt_or_zero = salt if salt is not None else bytes([0] * hash_algorithm().digest_size)
    h = hmac.new(salt_or_zero, msg = ikm, digestmod = hash_algorithm)
    return h.digest()

def Expand(prk, info, out_len):
    hash_algorithm=sha256
    out = bytearray()
    T = b''
    i = 1
    while len(out) < out_len:
        block = T + info + bytes([i])
        T = hmac.new(prk, msg = block, digestmod = hash_algorithm).digest()
        out.extend(T)
        i += 1
    return bytes(out[:out_len])

def KeyID(k):
    suite = CipherSuite.new(k.KemID, k.KdfID, k.AeadID)
    identifiers = struct.pack('>HHHH', 32, 1, 1, len(k.PublicKeyBytes))
    config = identifiers + k.PublicKeyBytes
    return Expand(Extract(None, config), ODOH_LABEL_KEY_ID, 32)

def encrypt_query(dns_message, target_key):
    kem_id = target_key.KemID
    kdf_id = target_key.KdfID
    aead_id = target_key.AeadID

    suite = CipherSuite.new(kem_id, kdf_id, aead_id)
    #to do add check if valid kem kdf aead.    

    public_key_bytes = target_key.PublicKeyBytes

    pkR = suite.kem.deserialize_public_key(public_key_bytes)
    #to do add deserialize error.

    ODOH_LABEL_QUERY = b"odoh query"
    # pk = bytes([185, 46, 17, 18, 250, 114, 197, 242, 103, 162, 108, 19, 198, 60, 27, 109, 217, 188, 162, 172, 51, 238, 166, 178, 244, 219, 225, 2, 92, 42, 229, 74])
    # sk = bytes([212, 46, 236, 37, 95, 134, 158, 162, 50, 42, 195, 28, 62, 55, 54, 1, 43, 144, 253, 36, 47, 149, 13, 43, 77, 127, 239, 70, 152, 51, 56, 224])

    # pke = suite.kem.deserialize_public_key(pk)
    # ske = suite.kem.deserialize_private_key(sk)
    # eks = KEMKeyPair(ske, pke)
    # enc, sender = suite.create_sender_context(pkR, info=ODOH_LABEL_QUERY, eks=eks)

    enc, sender = suite.create_sender_context(pkR, info=ODOH_LABEL_QUERY)

    keyID = KeyID(target_key)
    QueryType = 1
    aad = struct.pack('!BH', QueryType, len(keyID)) + keyID

    encoded_message = encodeLengthPrefixedSlice(dns_message) + encodeLengthPrefixedSlice(bytes())

    ct = sender.seal(encoded_message, aad)

    print(">>>>> == enc is",' '.join(str(byte) for byte in enc))
    print(">>>>> == ct is",' '.join(str(byte) for byte in ct))
    print(">>>>> == aad is",' '.join(str(byte) for byte in aad))
    print(">>>>> == encoded_message is",' '.join(str(byte) for byte in encoded_message))
    print(">>>>> == keyID is",' '.join(str(byte) for byte in keyID))

    odns_message = ObliviousDNSMessage(
        MessageType=QueryType.to_bytes(1, byteorder='big'),
        KeyID=keyID,
        EncryptedMessage=[item for item in (enc + ct)]
    )

    query_context = QueryContext(
        secret=sender._exporter_secret,
        suite=suite,
        query=encoded_message,
        publicKey=target_key
    )

    return odns_message, query_context

def create_odoh_question(dns_message, public_key):
    # print(">>>>> == create_odoh_question has dns_message", dns_message)
    return encrypt_query(dns_message, public_key)

def prepareHttpRequest(Query):
    url = "odoh.cloudflare-dns.com"

    headers = {
        'accept': OBLIVIOUS_DOH_CONTENT_TYPE,
        'content-type': OBLIVIOUS_DOH_CONTENT_TYPE
    }

    odoh_endpoint = "https://odoh.cloudflare-dns.com/dns-query"

    serialized_odns_message = Query.MessageType + encodeLengthPrefixedSlice(Query.KeyID) + encodeLengthPrefixedSlice(Query.EncryptedMessage)

    # print(serialized_odns_message)

    response = requests.post(odoh_endpoint, data=serialized_odns_message, headers=headers)
    
    print(">>>>> == dns_query_Packed is",' '.join(str(byte) for byte in serialized_odns_message))

    print(response)
