import ast
import sys
import hmac
import base64
import struct
import requests
import dns
import pyhpke as hpke
from hashlib import sha256
import dns.rdtypes.svcbbase as svcb_helper
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
def Fetch_Configs(url= 'https://odoh.cloudflare-dns.com/.well-known/odohconfigs'):
    response = requests.get(url)

    if response.status_code == 200:
        byte_data = response.content
        byte_integers = [byte for byte in byte_data]
    else:
        print(f"Request failed with status code {response.status_code}")
    return response.content

# Method_2 to fetch odoh configs By DNS request over socket
def SVCB_DNS_bySocket(domain_name: str, resolver: str, RType: str):
    forward_addr = (resolver, 53) # dns and port
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    q = DNSRecord.question(domain_name, RType)
    client.sendto(bytes(q.pack()), forward_addr)
    data, _ = client.recvfrom(1024)
    return data[-46:]

# Method_3 to fetch odoh configs By DNS request
def SVCB_DNS_Request(domain_name: str, resolver: str, RType: dns.rdatatype):
    # Set the default resolver to the specified resolver
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = [resolver]

    # Create a DNS request for (SVCB/ HTTPS)
    qname = dns.name.from_text(domain_name)

    response = dns.resolver.resolve(qname, RType)
    answer = response.rrset

    # Parse the ANSWER Section and extract odohconfig value.
    # SvcParamKey is Key32769.
    # the config is parsed as a GenericParam of SVCB Class
    # from dnspython lib.
    # which escapes the byte-stream for formatting if it
    # receives non-printable ASCII characters.
    odoh_config = str(answer).split('key32769')[-1][2:-1]
    return(svcb_helper._unescape(odoh_config))

def Unmarshal(buffer):
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

    suite = hpke.CipherSuite.new(kemID, kdfID, aeadID)
    return ObliviousDoHConfigContents(kemID, kdfID, aeadID, publicKeyBytes)

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
        raise ValueError("Unsupported ODOH version: {version}")

    if len(buffer[4:]) < length:
        raise ValueError("Invalid serialized ObliviousDoHConfig")

    contents = Unmarshal(buffer[4:])
    return ObliviousDoHConfig(version, contents)

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

def EncodeLengthPrefixedSlice(slice_data):
    length_prefix = len(slice_data).to_bytes(2, byteorder='big')
    return length_prefix + bytes(slice_data)

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

def KeyID(suite, k):
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
    kem_id = target_key.KemID
    kdf_id = target_key.KdfID
    aead_id = target_key.AeadID

    suite = hpke.CipherSuite.new(kem_id, kdf_id, aead_id)
    # to check if valid kem kdf aead.
    # already tested when parsing the ODoH Config.

    keyID = KeyID(suite, target_key)
    public_key_bytes = target_key.PublicKeyBytes
    pkR = suite.kem.deserialize_public_key(public_key_bytes)

    # Custom ephemeral keys (self)
    # pk = bytes([185, 46, 17, 18, 250, 114, 197, 242, 103, 162, 108, 19, 198, 60, 27, 109, 217, 188, 162, 172, 51, 238, 166, 178, 244, 219, 225, 2, 92, 42, 229, 74])
    # sk = bytes([212, 46, 236, 37, 95, 134, 158, 162, 50, 42, 195, 28, 62, 55, 54, 1, 43, 144, 253, 36, 47, 149, 13, 43, 77, 127, 239, 70, 152, 51, 56, 224])
    # pke = suite.kem.deserialize_public_key(pk)
    # ske = suite.kem.deserialize_private_key(sk)
    # eks = hpke.KEMKeyPair(ske, pke)
    # enc, sender = suite.create_sender_context(pkR, info=ODOH_LABEL_QUERY, eks=eks)

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
    return odns_message, query_context, target_key

def CreateOdohQuestion(dns_message, public_key):
    encoded_DNSmessage = EncodeLengthPrefixedSlice(dns_message) + EncodeLengthPrefixedSlice(bytes(ODOH_PADDING_BYTE))
    return EncryptQuery(encoded_DNSmessage, public_key)

def PrepareHTTPrequest(Query, odoh_endpoint="https://odoh.cloudflare-dns.com/dns-query"):
    headers = {
        'accept': OBLIVIOUS_DOH_CONTENT_TYPE,
        'content-type': OBLIVIOUS_DOH_CONTENT_TYPE
    }
    serialized_odns_message = Query.MessageType + EncodeLengthPrefixedSlice(Query.KeyID) + EncodeLengthPrefixedSlice(Query.EncryptedMessage)

    ##### debug
    skR = bytes([8, 120, 144, 255, 254, 254, 129, 120, 36, 39, 171, 179, 221, 119, 77, 215, 171, 236, 247, 81, 39, 186, 240, 59, 225, 108, 189, 81, 136, 60, 71, 133])
    R_encrypted = packet_parser(skR, serialized_odns_message)

    response = requests.post(odoh_endpoint, data=serialized_odns_message, headers=headers)
    return response, R_encrypted

def DecryptResponse(response, query_context):
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
    if int.from_bytes(response.MessageType, byteorder='little') != ResponseType:
        print("message response type got %d expected %d" %(int.from_bytes(response.MessageType, byteorder='little'), ResponseType))
        return -1

    decrypted_response_bytes = DecryptResponse(response, query_context)

    if decrypted_response_bytes is not None:
        decrypted_response = UnmarshalMessageBody(decrypted_response_bytes)
    else:
        print("packet marshalling gone wrong")
        sys.exit(1)
    return decrypted_response

def ParseDNSresponse(response):
    dns_message = dns.message.from_wire(response)
    return dns_message

def ValidateEncryptedResponse(byte_response, query_context):
    # for desired ODOH response, the custom way to
    # parse the response. Please ensure you are
    # using cusom ephemeral keys at EncryptQuery()
    # OR if you have CT bytes, pass string below.

    # message_type = byte_response[0:1]
    # key_id = byte_response[3:19]
    # encrypted_message = byte_response[21:]

    # modified_string = "2 0 16 160 65 176 97 97 38 47 147 137 25 73 129 40 73 130 232 0 123 43 57 42 50 95 127 87 22 109 40 68 49 100 226 68 167 86 48 192 122 161 1 100 226 57 92 171 42 152 136 88 86 186 172 252 33 215 139 166 167 195 229 223 107 191 225 148 37 14 138 163 193 63 9 248 178 162 128 199 141 215 9 8 206 27 148 213 5 188 28 89 210 92 140 43 43 71 162 101 67 36 5 120 100 230 69 1 209 81 183 166 53 24 142 119 24 30 218 22 65 152 142 42 251 205 156 57 29 153 135 248 90 112 255 232 183 245 72 243 137 28 28 47"
    # modified_string = modified_string.replace(" ", ",")
    # byte_response = ast.literal_eval("[" + modified_string + "]")

    # modified_string = "0 47 92 240 1 0 0 1 0 0 0 0 0 1 3 119 119 119 10 99 108 111 117 100 102 108 97 114 101 3 99 111 109 0 0 28 0 1 0 0 41 4 208 0 1 0 0 0 0 0 0"
    # modified_string = modified_string.replace(" ", ",")
    # query_context.query = ast.literal_eval("[" + modified_string + "]")

    message_type = byte_response[0:1]
    key_id = byte_response[3:19]
    encrypted_message = byte_response[21:]

    response = ObliviousDNSMessage(key_id, message_type, encrypted_message)
    decrypted_response = OpenAnswer(response, query_context)

    try:
        dns_bytes = ParseDNSresponse(decrypted_response)
    except Exception as err:
        print("unable to parse_dns_response")
        return err
    return dns_bytes
