import os
import random
import struct
import pyhpke
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
import hashlib
import hmac
import inspect

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

def KeyID(k):
    suite, err = hpke.AssembleCipherSuite(k.KemID, k.KdfID, k.AeadID)
    if err != None:
        return None

    identifiers = struct.pack('>HHHH', k.KemID, k.KdfID, k.AeadID, len(k.PublicKeyBytes))
    config = identifiers + k.PublicKeyBytes
    prk = suite.KDF.Extract(None, config)
    return suite.KDF.Expand(prk, ODOH_LABEL_KEY_ID, suite.AEAD.KeySize())

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
