import os
import dns
import ast
import sys
import hmac
import base64
import struct
import argparse
import requests
import ipaddress
import subprocess
import validators
import dns.resolver
import pyhpke as hpke
import dns.rdtypes.svcbbase as svcb_helper

from dns import rcode
from time import sleep
from hashlib import sha256
from urllib3.exceptions import InsecureRequestWarning
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

QueryType = 1
ResponseType = 2
ODOH_VERSION = 0x0001
ODOH_SECRET_LENGTH = 32
ODOH_PADDING_BYTE = 0

ODOH_LABEL_KEY = "odoh key".encode()
ODOH_LABEL_QUERY = "odoh query".encode()
ODOH_LABEL_NONCE = "odoh nonce".encode()
ODOH_LABEL_KEY_ID = "odoh key id".encode()
ODOH_LABEL_RESPONSE = "odoh response".encode()

OBLIVIOUS_DOH_CONTENT_TYPE = "application/oblivious-dns-message"

KEM_ID = hpke.KEMId.DHKEM_X25519_HKDF_SHA256
KDF_ID = hpke.KDFId.HKDF_SHA256
AEAD_ID = hpke.AEADId.AES128_GCM

"""
here all class objects are containers to store data.
"""

class ObliviousDoHConfigContents:
    def __init__(self, kemID, kdfID, aeadID, publicKeyBytes):
        self.KemID = KEM_ID
        self.KdfID = KDF_ID
        self.AeadID = AEAD_ID
        self.PublicKeyBytes = publicKeyBytes
    def __str__(self):
        return f"ObliviousDoHConfigContents: KemID={self.KemID}, KdfID={self.KdfID}, " \
       f"AeadID={self.AeadID}, PublicKeyBytes={' '.join(str(byte) for byte in self.PublicKeyBytes)}"

class ObliviousDoHConfig:
    def __init__(self, version, contents):
        self.Version = version
        self.Contents = contents
    def __str__(self):
        return f"ObliviousDoHConfig: Version={self.Version}, Contents={self.Contents}"

class ObliviousDoHConfigs:
    def __init__(self, configs):
        self.Configs = configs
    def __str__(self):
        return f"ObliviousDoHConfigs: Configs={self.Configs}"

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

class ObliviousDNSMessageBody:
    def __init__(self, DnsMessage, Padding):
        self.DnsMessage = DnsMessage
        self.Padding = Padding

# Step 1 ODOH Service Discovery

# Method_1 to fetch odoh configs By url request
def Fetch_Configs(url, v):
    """
    fetches the odoh config, from the url specified.

    Positional arguments:
    url -- url where odoh config is hosted.
    """

    if v:
        print(f"\n\n -- Fetch ODOH-Config from: {url}")
    response = requests.get(url)
    if response.status_code == 200:
        byte_data = response.content
        # byte_integers = [byte for byte in byte_data]
    else:
        print(f"Request failed with status code {response.status_code}")
    return response.content

# Method_2 to fetch odoh configs By DNS request
def SVCB_DNS_Request(domain_name: str, resolver: str, ddrRType: dns.rdatatype, v):
    """
    returns the odoh_config retrieved from the DNS request.

    Positional arguments:
    domain_name -- domain to lookup.
    ddrRType -- which resource record to ask for.
    resolver -- which resolver to pick for DNS request.
    """

    # Set the default resolver to the specified resolver
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = [resolver]

    if v:
        print(f"\n\n -- DNS domain Look up for {domain_name} with resolver {resolver} for rtype {ddrRType}")

    # Create a DNS request for (SVCB/ HTTPS)
    qname = dns.name.from_text(domain_name)

    try:
        if ddrRType.upper() == "SVCB":
            dns_response = dns.resolver.resolve(qname, rdtype=dns.rdatatype.SVCB)
        elif ddrRType.upper() == "HTTPS":
            dns_response = dns.resolver.resolve(qname, rdtype=dns.rdatatype.HTTPS)
        else:
            return None, None
    except Exception as e:
        print(" -- SVCB Resolution Failed")
        return None, None

    answer = dns_response.rrset
    additional = dns_response.response.additional

    """
    Parse the ANSWER Section and extract odohconfig value.
    SvcParamKey is Key32769.
    the config is parsed as a GenericParam of SVCB Class
    from dnspython lib.
    which escapes the byte-stream for formatting if it
    receives non-printable ASCII characters.
    """

    odoh_config = str(answer).split('key32769')[-1][2:-1]

    """
    sample additional RRset after split.
    ['wip.example.net.', '30', 'IN', 'A', '10.0.0.60']
    """

    if additional:
        rr = additional[0]
        additional = rr.to_text().split()[4]
    else:
        additional = None

    return svcb_helper._unescape(odoh_config), additional

def Unmarshal(buffer):
    """
    given the odoh_config as buffer, this returns
    the odoh_config as a structered data for use.

    Positional arguments:
    buffer -- odoh_config content as buffer.
    """

    if len(buffer) < 8:
        raise ValueError("Invalid serialized ObliviousDoHConfigContents")

    kemID, kdfID, aeadID, publicKeyLength = struct.unpack('>HHHH', buffer[:8])

    if len(buffer[8:]) < publicKeyLength:
        raise ValueError("Invalid serialized ObliviousDoHConfigContents")
    publicKeyBytes = buffer[8 : 8 + publicKeyLength]

    # convert IDs to their respective algorithm.
    kemID = hpke.KEMId(kemID)
    kdfID = hpke.KDFId(kdfID)
    aeadID = hpke.AEADId(aeadID)

    if KEM_ID != kemID or KDF_ID != kdfID or AEAD_ID != aeadID:
        raise ValueError(f"Unsupported KEMID: {kemID}, KDFID: {kdfID}, AEADID: {aeadID}")

    # suite = hpke.CipherSuite.new(kemID, kdfID, aeadID)
    return ObliviousDoHConfigContents(kemID, kdfID, aeadID, publicKeyBytes)

def CreateObliviousDoHConfig(contents):
    """
    given the odoh_config buffer, it is segregated as odoh_version
    and contents, which is used as part of hpke cryptograpgy.

    Positional arguments:
    contents -- buffer data of the odoh_config.
    """

    return ObliviousDoHConfig(ODOH_VERSION, contents)

def ParseConfigHeader(buffer):
    """
    this takes odoh_config buffer and validates the buffer data
    before parsing it for odoh_config contents.
    returns odoh version and odoh_config length.

    Positional arguments:
    buffer -- odoh_config buffer data to parse.
    """

    if len(buffer) < 4:
        raise ValueError("Invalid ObliviousDoHConfig encoding")

    version, length = struct.unpack('>HH', buffer[:4])
    return version, length

def IsSupportedConfigVersion(version):
    """
    to validate the odoh_version in the odoh_config.

    Positional arguments:
    version -- version info parsed from the odoh_config
    """

    return version == ODOH_VERSION

def UnmarshalObliviousDoHConfig(buffer):
    """
    The wrapped odoh_config is unmarshalled.

    Positional arguments:
    buffer -- odoh_config.
    """

    version, length = ParseConfigHeader(buffer)
    if not IsSupportedConfigVersion(version):
        raise ValueError("Unsupported ODOH version: {version}")

    if len(buffer[4:]) < length:
        raise ValueError("Invalid serialized ObliviousDoHConfig")

    contents = Unmarshal(buffer[4:])
    return ObliviousDoHConfig(version, contents)

def CreateObliviousDoHConfigs(configs):
    """
    retrieved odoh configs are parsed as a list
    of odoh configs for client odoh query usage.

    Positional arguments:
    configs -- list of configs.
    """

    return ObliviousDoHConfigs(configs)

def UnmarshalObliviousDoHConfigs(buffer):
    """
    retieved odoh config from the wire is parsed to
    make sense of the config.

    Positional arguments:
    buffer -- raw wire data for key32769.
    """

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

def EncodeLengthPrefixedSlice(slice_data):
    """
    return encoded data with length of the
    data (in 2B) added as a header to the data.

    Positional arguments:
    slice_data -- data to encode.
    """

    length_prefix = len(slice_data).to_bytes(2, byteorder='big')
    return length_prefix + bytes(slice_data)

def Extract(salt, ikm):
    """
    Extract is used in KDF.

    Positional arguments:
    ikm -- input keyeing material.
    salt -- data used to enchance the security key derivation.
    """

    hash_algorithm = sha256
    salt_or_zero = salt if salt is not None else bytes([0] * hash_algorithm().digest_size)
    h = hmac.new(salt_or_zero, msg = ikm, digestmod = hash_algorithm)
    return h.digest()

def Expand(prk, info, out_len):
    """
    the key derivation part of cryptography.

    Positional arguments:
    prk -- derived at the extraction phase of KDF.
    info -- label used derive the specific key.
    out_len -- describes the length of the derived secret.
    """

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

def KeyID(suite, k):
    # to do change suite usage to k-usage if possible.

    """
    derived the keyID for the associated HPKE suite and public key.

    Positional arguments:
    suite -- HPKE Suite info.
    k -- public key
    """

    identifiers = struct.pack('>HHHH', k.KemID.value, k.KdfID.value, k.AeadID.value, len(k.PublicKeyBytes))
    config = identifiers + k.PublicKeyBytes
    return Expand(Extract(None, config), ODOH_LABEL_KEY_ID, suite.kdf._hash.digest_size)

def setup_query_context_and_decrypt_query_body(skR, Q_encrypted):
    # enc || ct = Q_encrypted
    # context = SetupBaseR(enc, skR, "odoh query")
    # return context

    # aad = 0x01 || len(key_id) || key_id()
    # enc_32 || ct_: = Q_encrypted
    # Q_plain, error = context.Open(aad, ct)
    # return Q_plain, error

    suite = hpke.CipherSuite.new(KEM_ID, KDF_ID, AEAD_ID)
    enc = bytes([185, 46, 17, 18, 250, 114, 197, 242, 103, 162, 108, 19, 198, 60, 27, 109, 217, 188, 162, 172, 51, 238, 166, 178, 244, 219, 225, 2, 92, 42, 229, 74])
    ct = bytes([25, 101, 45, 19, 59, 117, 84, 232, 226, 13, 20, 182, 224, 47, 17, 100, 78, 132, 198, 196, 33, 216, 130, 38, 72, 135, 97, 226, 100, 147, 27, 224, 0, 53, 207, 159, 8, 224, 252, 207, 111, 122, 189, 42, 171, 225, 201, 180, 26, 118, 88, 51, 64, 23, 209, 12, 185, 242, 104, 135, 160, 173, 88, 158, 192, 142, 163])

    skR = suite.kem.deserialize_private_key(skR)
    keyID = bytes([144, 226, 65, 36, 10, 25, 155, 155, 247, 46, 33, 148, 34, 218, 75, 234, 187, 234, 206, 177, 56, 132, 55, 87, 104, 149, 242, 144, 196, 228, 69, 142])

    context_R = suite.create_recipient_context(enc, skR, info=b"odoh query")
    aad = struct.pack('!BH', QueryType, len(keyID)) + keyID
    pt = context_R.open(ct=ct, aad=aad)

    #print(">>>BIGIP: DNS Query/ PT",pt)
    return pt, context_R

def derive_secrets(context_R, Q_plain, resp_nonce):
    # secret = context.Export("odoh response", Nk)
    # salt = Q_plain || len(resp_nonce) || resp_nonce
    # prk = Extract(salt, secret)
    # key = Expand(odoh_prk, "odoh key", Nk)
    # nonce = Expand(odoh_prk, "odoh nonce", Nn)
    # return key, nonce

    secret = context_R.export(bytes(ODOH_LABEL_RESPONSE), 16)
    #print(">>>BIGIP: secret",' '.join(str(byte) for byte in secret))
    salt = Q_plain + struct.pack('!H', len(resp_nonce)) + resp_nonce
    prk = Extract(salt, secret)
    key = Expand(prk, b"odoh key", 32)
    nonce = Expand(prk, b"odoh nonce", 16)
    return key, nonce

# def func (ctx *SenderContext) Seal(aad, pt []byte) []byte {
#     ct = ctx.aead.Seal(nil, ctx.computeNonce(), pt, aad)
#     ctx.incrementSeq()
#     return ct

def encrypt_response_body(R_plain, aead_key, aead_nonce, resp_nonce, context_R):
    # aad = 0x02 || len(resp_nonce) || resp_nonce
    # R_encrypted = Seal(aead_key, aead_nonce, aad, R_plain)
    # return R_encrypted

    aad = struct.pack('!BH', ResponseType, len(resp_nonce)) + resp_nonce
    cipher = AESGCM(aead_key)
    ct = cipher.encrypt(resp_nonce, R_plain, aad)
    return ct

def packet_parser(skR, Q_encrypted):
    pt, context_R = setup_query_context_and_decrypt_query_body(skR, Q_encrypted)

    resp_nonce = bytes([222, 51, 96, 30, 102, 20, 18, 29, 25, 120, 74, 38, 201, 43, 147, 144])
    key, nonce = derive_secrets(context_R, pt, resp_nonce)

    dns_resp_plain = "194 127 129 128 0 1 0 2 0 0 0 1 3 119 119 119 10 99 108 111 117 100 102 108 97 114 101 3 99 111 109 0 0 28 0 1 192 12 0 28 0 1 0 0 0 134 0 16 38 6 71 0 0 0 0 0 0 0 0 0 104 16 123 96 192 12 0 28 0 1 0 0 0 134 0 16 38 6 71 0 0 0 0 0 0 0 0 0 104 16 124 96 0 0 41 4 208 0 0 0 0 0 0"
    dns_resp_plain = dns_resp_plain.replace(" ", ",")
    dns_resp_plain = ast.literal_eval("[" + dns_resp_plain + "]")
    dns_resp_plain = bytes(dns_resp_plain)

    aead_key = key
    aead_nonce = 0
    R_encrypted = encrypt_response_body(dns_resp_plain, aead_key, aead_nonce, resp_nonce, context_R)
    return R_encrypted

def EncryptQuery(encoded_DNSmessage, target_key):
    """
    given a DNS query, and odoh target server's odoh config
    construct a encrypted DNS query.

    Positional arguments:
    encoded_DNSmessage -- the encoded DNS query.
    target_key -- the odoh target's odoh config.
    """

    kem_id = target_key.KemID
    kdf_id = target_key.KdfID
    aead_id = target_key.AeadID

    suite = hpke.CipherSuite.new(kem_id, kdf_id, aead_id)
    """
    no need to check if valid odoh config for, kem kdf aead.
    hpke suite validation already performed while parsing the ODoH Config.
    """

    keyID = KeyID(suite, target_key)
    public_key_bytes = target_key.PublicKeyBytes
    pkR = suite.kem.deserialize_public_key(public_key_bytes)

    """
    Custom ephemeral keys (self)
    pk = bytes([185, 46, 17, 18, 250, 114, 197, 242, 103, 162, 108, 19, 198, 60, 27, 109, 217, 188, 162, 172, 51, 238, 166, 178, 244, 219, 225, 2, 92, 42, 229, 74])
    sk = bytes([212, 46, 236, 37, 95, 134, 158, 162, 50, 42, 195, 28, 62, 55, 54, 1, 43, 144, 253, 36, 47, 149, 13, 43, 77, 127, 239, 70, 152, 51, 56, 224])
    pke = suite.kem.deserialize_public_key(pk)
    ske = suite.kem.deserialize_private_key(sk)
    eks = hpke.KEMKeyPair(ske, pke)
    enc, sender = suite.create_sender_context(pkR, info=ODOH_LABEL_QUERY, eks=eks)
    """

    enc, sender = suite.create_sender_context(pkR, info = ODOH_LABEL_QUERY)
    aad = struct.pack('!BH', QueryType, len(keyID)) + keyID
    ct = sender.seal(encoded_DNSmessage, aad)
    context_secret = sender.export(bytes(ODOH_LABEL_RESPONSE), suite.aead.key_size)

    query_context = QueryContext(
        secret=context_secret,
        suite=suite,
        query=encoded_DNSmessage,
        publicKey=target_key
    )
    odns_message = ObliviousDNSMessage(
        MessageType=QueryType.to_bytes(QueryType, byteorder='big'),
        KeyID=keyID,
        EncryptedMessage=[item for item in (enc + ct)]
    )
    return odns_message, query_context

def CreateOdohQuestion(dns_message, public_key):
    """
    given dns query to ask odoh target. construct
    the dns-odoh encrypted question.

    Positional arguments:
    dns_message -- dns query.
    public_key -- the odoh target's odoh_config.
    """

    encoded_DNSmessage = EncodeLengthPrefixedSlice(dns_message) + EncodeLengthPrefixedSlice(bytes(ODOH_PADDING_BYTE))
    return EncryptQuery(encoded_DNSmessage, public_key)

def PrepareHTTPrequest(Query, http_method, v, odoh_endpoint="https://odoh.cloudflare-dns.com/dns-query", headers=None, data=None):
    """
    construst the odoh request and send to the
    odoh target. returns the response from the odoh target.

    Positional arguments:
    Query -- encrypted odns query.
    http_method -- GET or POST method.
    odoh_endpoint -- where the odoh target's resolver endpoint is listening.
    """

    if headers is None:
        headers = {
            'accept': OBLIVIOUS_DOH_CONTENT_TYPE,
            'content-type': OBLIVIOUS_DOH_CONTENT_TYPE
        }
    serialized_odns_message = Query.MessageType + EncodeLengthPrefixedSlice(Query.KeyID) + EncodeLengthPrefixedSlice(Query.EncryptedMessage)

    if v:
        print("Warning: this is an Insecure HTTPS Request. Adding certificate verification is strongly advised for deployment.")

    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        if http_method.upper() == "POST":
            response = requests.post(odoh_endpoint, data=serialized_odns_message, headers=headers, verify=False, timeout=3)
        if http_method.upper() == "GET":
            response = requests.get(odoh_endpoint, data=serialized_odns_message, headers=headers, verify=False, timeout=3)
    except requests.RequestException as e:
        print(f"An error occurred during the ODOH HTTP request: {e}")
        return None

    # debug
    # skR = bytes([8, 120, 144, 255, 254, 254, 129, 120, 36, 39, 171, 179, 221, 119, 77, 215, 171, 236, 247, 81, 39, 186, 240, 59, 225, 108, 189, 81, 136, 60, 71, 133])
    # R_encrypted = packet_parser(skR, serialized_odns_message)

    # response = requests.post(odoh_endpoint, data=serialized_odns_message, headers=headers)
    return response

def DecryptResponse(response, query_context):
    """
    decrypt the odoh response from the odoh target.
    returns the plain text.

    Positional arguments:
    response -- response from the odoh target.
    query_context -- constructed while encrypting the query.
    """

    responseNonceSize = query_context.suite.aead.key_size
    if responseNonceSize < query_context.suite.aead.nonce_size:
        responseNonceSize = query_context.suite.aead.nonce_size

    if len(response.KeyID) != responseNonceSize:
        print("Invalid response key ID length")

    encoded_response_nonce = EncodeLengthPrefixedSlice(response.KeyID)
    salt = bytes(query_context.query) + encoded_response_nonce
    aad = bytes([ResponseType]) + encoded_response_nonce

    prk = query_context.suite.kdf.extract(salt, query_context.secret)
    key = query_context.suite.kdf.expand(prk, ODOH_LABEL_KEY, query_context.suite.aead.key_size)
    nonce = query_context.suite.kdf.expand(prk, ODOH_LABEL_NONCE, query_context.suite.aead.nonce_size)

    cipher = AESGCM(key)
    plaintext = cipher.decrypt(nonce, bytes(response.EncryptedMessage), aad)
    return plaintext

def UnmarshalMessageBody(data):
    """
    unmarhsal the dns message response.

    Positional arguments:
    data -- extracted plain text wire data from odoh target's encrypted response.
    """

    if len(data) < 2:
        raise ValueError("Invalid data length")

    message_length = struct.unpack(">H", data[:2])[0]
    if len(data) < 2 + message_length:
        raise ValueError("Invalid DNS message length")

    message = data[2:2 + message_length]

    if len(data) < 2 + message_length + 2:
        raise ValueError("Invalid data length")

    padding_length = struct.unpack(">H", data[2 + message_length:2 + message_length + 2])[0]
    if len(data) < 2 + message_length + 2 + padding_length:
        raise ValueError("Invalid DNS padding length")

    # 2bytes for len of message_length and
    # 2bytes for len of padding_length in message.
    # formatted for understanding the message parsing.
    padding = data[2 + message_length + 2:2 + message_length + 2 + padding_length]

    return message + padding

def OpenAnswer(response, query_context):
    """
    decrypt the encrypted odoh response using the query_context.

    Positional arguments:
    response -- odoh response from the odoh target.
    query_context -- constructed while making the encrypted query.
    """

    # try:
    if int.from_bytes(response.MessageType, byteorder='little') != ResponseType:
        print("message response type got %d expected %d" %(int.from_bytes(response.MessageType, byteorder='little'), ResponseType))
        return None

    decrypted_response_bytes = DecryptResponse(response, query_context)

    if decrypted_response_bytes is not None:
        decrypted_response = UnmarshalMessageBody(decrypted_response_bytes)
    else:
        print("packet marshalling gone wrong")

    # except Exception as err:

    return decrypted_response

def ParseDNSresponse(response):
    """
    parse the byte data as dns response.

    Positional arguments:
    response -- decrypted dns data from encrypted odoh response.
    """

    dns_message = dns.message.from_wire(response)
    return dns_message

def ValidateEncryptedResponse(byte_response, query_context):
    """
    validate the encrypted response recieved from the odoh target.

    Positional arguments:
    byte_response -- response from the odoh target.
    query_context -- computed while constructing odoh query.
    """

    # message_type is always 1 Byte.
    message_type = byte_response[0:1]

    # length of keyid is stored in 2 Bytes.
    len_keyid = int.from_bytes(byte_response[1:3], byteorder='big')
    key_id = byte_response[3:3+len_keyid]

    # length of encrypted message is stored in 2 Bytes.
    len_encMessage = int.from_bytes(byte_response[3+len_keyid:3+len_keyid+2], byteorder='big')
    encrypted_message = byte_response[3+len_keyid+2:3+len_keyid+2+len_encMessage]

    """
    for desired ODOH response, the custom way to
    parse the response. Please ensure you are
    using cusom ephemeral keys at EncryptQuery()
    OR if you have CT bytes, pass string below.

    odoh_response_string = "93 43 25 186 226 48 127 13 234 126 169 136 98 67 98 9] [252 78 107 222 175 15 149 246 237 93 237 253 82 207 183 68 28 107 204 219 99 69 21 147 135 158 207 168 230 252 81 182 2 58 158 250 152 136 45 62 215 69 53 211 28 65 12 62 16 38 144 164 144 204 203 232 114 29 67 149 63 231 61 76 177 87 217 180 152 142 156 218 27 118 215 205 75 213 69 9 99 46 163 9 201 103 239 232 228 52 86 85 11 4 79 31 63 216 244 232 178 114 207 30 170 58 194 124 138 144 235 42"

    lists = odoh_response_string.split("] [")
    modified_string = lists[0].replace(" ", ",")
    key_id = ast.literal_eval("[" + modified_string + "]")
    modified_string = lists[1].replace(" ", ",")
    encrypted_message = ast.literal_eval("[" + modified_string + "]")

    ct = "0 36 157 63 1 0 0 1 0 0 0 0 0 0 3 119 119 119 10 99 108 111 117 100 102 108 97 114 101 3 99 111 109 0 0 28 0 1 0 0"
    modified_string = ct.replace(" ", ",")
    query_context.query = ast.literal_eval("[" + modified_string + "]")
    """


    response = ObliviousDNSMessage(key_id, message_type, encrypted_message)
    decrypted_response = OpenAnswer(response, query_context)

    try:
        dns_bytes = ParseDNSresponse(decrypted_response)
    except Exception as err:
        print("unable to parse_dns_response")
        return err
    return dns_bytes


def print_pretty_dns(messages):
    for message in messages:
        print("msg ;; opcode: {}, status: {}, id: {}".format(message["opcode"], message["rcode"], message["id"]))
        print(";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}".format(
            message["flags"], len(message["QUESTION"]), len(message["ANSWER"]), 0, 0))

        print("\n;; QUESTION SECTION:")
        for q in message["QUESTION"]:
            print(q)

        print("\n;; ANSWER SECTION:")
        for a in message["ANSWER"]:
            print(a)

        print("\n>>>>> == dnsResponse is ;; opcode: {}, status: {}, id: {}".format(
            message["opcode"], message["rcode"], message["id"]))
        print(";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}".format(
            message["flags"], len(message["QUESTION"]), len(message["ANSWER"]), 0, 0))

        print("\n;; QUESTION SECTION:")
        for q in message["QUESTION"]:
            print(q)

        print("\n;; ANSWER SECTION:")
        for a in message["ANSWER"]:
            print(a)
        print()


def dns_answerParser(dns_message):
    dns_response_data = dns_message.to_wire()
    dns_response = dns.message.from_wire(dns_response_data)

    if not dns_message.answer:
        print("\n -- No RRSET in Encrypted DNS response from ODOH server - [EMPTY DNS RESPONSE]")

    print("\n;; ->>HEADER<<- opcode: opcode: QUERY, status: NOERROR, id:", dns_response.id)
    print(";; flags: qr rd ra; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}".format(
        len(dns_response.question), len(dns_response.answer), len(dns_response.authority), len(dns_response.additional)))

    print("\n;; QUESTION SECTION:")
    for question in dns_response.question:
        print(question)

    print("\n;; ANSWER SECTION:")
    for answer in dns_response.answer:
        print(answer)

    print("\n;; AUTHORITY SECTION:")
    for authority in dns_response.authority:
        print(authority)

    print("\n;; ADDITIONAL SECTION:")
    for additional in dns_response.additional:
        print(additional)
    print("\n")
    
    if not dns_message.answer:
        return None, rcode.to_text(dns_message.rcode())

    dns_answer = ((dns_message.answer)[0]).to_text().split("\n")
    return dns_answer[0], rcode.to_text(dns_message.rcode())

def dns_odoh(odoh_ddr, configFetch_method, ddrRType, resolver, odohhost, http_method, domain_name, rr_type, v, odohconfigF, dns_queryid=0, edns=False):
    """
    odoh_ddr: domain of odoh target.
    ddrRType: RR Type of the odoh target HTTPS/ SVCB.
    resolver: which resolver to ask for target's conf.
    http_method: POST/ GET
    domain_name: is the domain to locate.
    rr_type: domain RR type to lookup.

    returns,
    _odoh_ansIP: This is IP from SVCB Response.
    _svcb_ansIP: This is IP from  ODOH Response.
    """

    if odohhost and not validators.url(odohhost):
        print(f"{odohhost} is NOT in valid url format.")
        return 0

    # Step1 Service Discovery Method selection
    if configFetch_method.upper() == "URL":
        if not odoh_ddr:
            odoh_ddr = 'https://odoh.cloudflare-dns.com/.well-known/odohconfigs'
        response = Fetch_Configs(odoh_ddr, v)
        odohhost = 'https://odoh.cloudflare-dns.com/dns-query'

    elif configFetch_method.upper() == "DNS":
        response,  odohhost= SVCB_DNS_Request(odoh_ddr, resolver, ddrRType, v)
        if not response:
            print(" -- Unable to Fetch ODOH-Config via DNS Resolution.")
            return None, None, None, None, None
        if not (odohhost):
            print(" -- ODOH Host is UnKNOWN. Cannot Proceed for ODOH Resolution.")
            return None, None, None, None, None
    else:
        print("un-defined configFetch_method")

    if v:
        print(" -- Parsed odohconfigs.")

    if odohconfigF:
        print("odohConfig:", ' '.join(str(byte) for byte in response))
        return response

    # Step 2 parsing the ODoH Config
    try:
        odoh_configs = UnmarshalObliviousDoHConfigs(response)
        odoh_config = odoh_configs.Configs[0]
    except:
        return None, None, None, None, None

    # Step 3 Construct DNS Message
    if v:
        print(f" -- Constructing DNS Query for ODOH. [domain: {domain_name} RR-Type: {rr_type}]." +
          (f"QueryID: {dns_queryid}" if dns_queryid else "") +
          (f" EDNS: {edns}." if edns else ""))

    dns_query = dns.message.make_query(domain_name, rr_type, use_edns=edns)
    if dns_queryid:
        dns_query.id = dns_queryid

    query_data = dns_query.to_wire()

    # Step 4 Construct Oblivious DNS Message
    odohQuery, queryContext = CreateOdohQuestion(query_data, odoh_config.Contents)

    # Step 5 Sending ODNS Question
    if validators.url(odohhost):
        odoh_endpoint = odohhost

    else:
        ip_obj = ipaddress.ip_address(odohhost)
        if ip_obj.version == 4:
            odoh_endpoint = 'https://' + str(odohhost)
        elif ip_obj.version == 6:
            odoh_endpoint = 'https://[' + str(odohhost) + ']'

    if v:
        print(f" -- Sending ODOH request to: {odoh_endpoint}.")

    response = PrepareHTTPrequest(odohQuery, http_method, v, odoh_endpoint)

    if response is not None:
        headers_list = dict(response.headers)
        if v:
            print(" -- Recieved ODOH Response") #, headers_list, response.content)

        if response.status_code == 200:
            # Step 6 Parse/ Validated/ Decrypt the ODNS Response
            dns_message = ValidateEncryptedResponse(response.content, queryContext)

            # Step 7 parse dns answer
            _odoh_ansIP, dns_rcode = dns_answerParser(dns_message)
            return odohhost, _odoh_ansIP, response.status_code, dns_rcode, headers_list

        else:
            return odohhost, response, response.status_code, None, headers_list

    """
    In case of DNS NXDomain or ErrCode. All DNS Answers are in DNS wire format.
    The DNS Packet will be encoded in ODOH Response of 200 ok.
    DNS Response is not related to HTTP Response code.

    All HTTP Errors are related to HTTP Connections and Header faults and are
    not required to be validated.
    """

    print(" -- No response from ODOH Server")
    return odohhost, None, None, None, None


# def main():

#     # python3 query.py --odohconfig url --target www.google.com --dnstype a

#     # python3 query.py --odohconfig dns --ldns 10.0.0.4 --ddr odoh.f5-dns.com --ddrtype svcb --target dns.answer.com --dnstype a

#     parser = argparse.ArgumentParser(description='Process some commands.')

#     # Common arguments
#     parser.add_argument('--odohconfig', type=str.upper, choices=['URL', 'DNS'], help='Method to use', required=True)
#     parser.add_argument('--target', help='Target address', required=True)
#     parser.add_argument('--dnstype', type=str.upper, help='DNS Type', required=True)
#     parser.add_argument('--ddr', help='DDR: odoh.cloudflare-dns.com')
#     parser.add_argument('--httpmethod', type=str.upper, default='POST', help='DNS Type')
#     parser.add_argument('--odohhost', default=None, help='odohhost address')
#     parser.add_argument('--getconfig',  action=argparse.BooleanOptionalAction, help='log odohConfig')
#     parser.add_argument('-v', '--verbose',  action=argparse.BooleanOptionalAction, help='verbose')

#     # URL specific arguments
#     url_group = parser.add_argument_group('URL Specific Arguments')

#     # DNS specific arguments
#     dns_group = parser.add_argument_group('DNS Specific Arguments')

#     url_group.add_argument('--ddrtype', help='DDR RR Type: SVCB RR/ HTTPS RR')
#     dns_group.add_argument('--ldns', default='default', help='Local DNS server')

#     args = parser.parse_args()

#     if args.odohconfig == 'DNS':
#         if (args.odohhost):
#             print("Error ODOH-DNS method: Unsupported Arguments passed.")
#             sys.exit(1)

#         dns_response = dns_odoh(args.ddr, args.odohconfig, args.ddrtype, args.ldns, args.odohhost, args.httpmethod, args.target, args.dnstype, args.verbose, args.getconfig)

#     if args.odohconfig == 'URL':
#         if (args.ddr or args.ddrtype):
#             print("Error ODOH-URL method: Unsupported Arguments passed.")
#             sys.exit(1)

#         dns_response = dns_odoh(args.ddr, args.odohconfig, '', '', args.odohhost, args.httpmethod, args.target, args.dnstype, args.verbose, args.getconfig)


# if __name__ == "__main__":
#     main()



