from ecdsa import SigningKey, SECP256k1
from subprocess import check_output, STDOUT
from pyasn1.codec.der import decoder
from binascii import a2b_hex, b2a_hex
from hashlib import new, sha256
from os import mkdir, path
from base58 import b58encode, b58decode
from bitcoin import sign


def change_endianness(x):
    # If there is an odd number of elements, we make it even by adding a 0
    if (len(x) % 2) == 1:
        x += "0"
    y = x.decode('hex')
    z = y[::-1]
    return z.encode('hex')


def decode_varint(varint):
    if len(varint) > 2:
        decoded_varint = int(change_endianness(varint[2:]), 16)
    else:
        decoded_varint = int(varint, 16)

    return decoded_varint


def int2bytes(a, b):
    return ('%0' + str(2 * b) + 'x') % a


class TX:

    def __init__(self, version=None, inputs=None, prev_tx_id=None, prev_out_index=None,
                 script_sig_len=None, script_sig=None,
                 n_sequence=None, outputs=None, value=None,
                 script_pub_key_len=None, script_pub_key=None,
                 n_lock_time=None):
        if prev_tx_id is None:
            prev_tx_id = []
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.nLockTime = n_lock_time

        if prev_tx_id is None:
            self.prev_tx_id = []
        else:
            self.prev_tx_id = prev_tx_id

        if prev_out_index is None:
            self.prev_out_index = []
        else:
            self.prev_out_index = prev_out_index

        if script_sig is None:
            self.scriptSig = []
        else:
            self.scriptSig = script_sig

        if script_sig_len is None:
            self.scriptSig_len = []
        else:
            self.scriptSig_len = script_sig_len

        if n_sequence is None:
            self.nSequence = []
        else:
            self.nSequence = n_sequence

        if value is None:
            self.value = []
        else:
            self.value = value

        if script_pub_key is None:
            self.scriptPubKey = []
        else:
            self.scriptPubKey = script_pub_key

        if script_pub_key_len is None:
            self.scriptPubKey_len = []
        else:
            self.scriptPubKey_len = script_pub_key_len

        self.hex = None
        self.offset = 0

    def to_hex(self):
        if self.hex is None:
            self.hex = self.version + self.inputs

            for i in range(len(self.prev_tx_id)):
                self.hex += self.prev_tx_id[i] + self.prev_out_index[i] + self.scriptSig_len[i] \
                            + self.scriptSig[i] + self.nSequence[i]

            self.hex += self.outputs

            for i in range(len(self.scriptPubKey)):
                self.hex += self.value[i] + self.scriptPubKey_len[i] + self.scriptPubKey[i]

            self.hex += self.nLockTime

        return self.hex

    def build_default_tx(self, prev_tx_id, prev_out_index, value, script_pub_key, script_sig=None):

        self.version = "01000000"

        n_inputs = len(prev_tx_id)
        self.inputs = int2bytes(n_inputs, 1)

        for i in range(n_inputs):
            self.prev_tx_id.append((prev_tx_id[i])[::-1])
            self.prev_out_index.append((int2bytes(prev_out_index[i], 4))[::-1])

        for i in range(n_inputs):
            if script_sig is None:
                self.scriptSig.append("0")
                self.scriptSig_len.append("0")

            else:
                self.scriptSig_len.append(int2bytes(len(script_sig[i]) / 2, 1))

            self.nSequence.append("ffffffff")

        n_outputs = len(script_pub_key)
        self.outputs = int2bytes(n_outputs, 1)

        for i in range(n_outputs):
            self.value.append((int2bytes(value[i], 8))[::-1])

            self.scriptPubKey_len.append(int2bytes(len(script_pub_key[i]) // 2, 1))
            self.scriptPubKey = script_pub_key

        self.nLockTime = "00000000"

        self.to_hex()


def hash_160(pk):
    """ Calculates the RIPEMD-160 hash of a given elliptic curve key.

    :param pk: elliptic curve public key (in hexadecimal format).
    :type pk: hex str
    :return: The RIPEMD-160 hash.
    :rtype: bytes
    """

    # Calculate the RIPEMD-160 hash of the given public key.
    md = new('ripemd160')
    h = sha256(a2b_hex(pk)).digest()
    md.update(h)
    h160 = md.digest()

    return h160


def hash_160_to_btc_address(h160, v):
    """ Calculates the Bitcoin address of a given RIPEMD-160 hash from an elliptic curve public key.

    :param h160: RIPEMD-160 hash.
    :type h160: bytes
    :param v: version (prefix) used to calculate the Bitcoin address.

     Possible values:

        - 0 for main network (PUBKEY_HASH).
        - 111 For testnet (TESTNET_PUBKEY_HASH).
    :type v: int
    :return: The corresponding Bitcoin address.
    :rtype: hex str
    """

    # Add the network version leading the previously calculated RIPEMD-160 hash.
    vh160 = chr(v).encode() + h160
    # Double sha256.
    h = sha256(sha256(vh160).digest()).digest()
    # Add the two first bytes of the result as a checksum tailing the RIPEMD-160 hash.
    addr = vh160 + h[0:4]
    # Obtain the Bitcoin address by Base58 encoding the result
    addr = b58encode(addr)

    return addr


def btc_address_to_hash_160(btc_addr):
    """ Calculates the RIPEMD-160 hash from a given Bitcoin address

    :param btc_addr: Bitcoin address.
    :type btc_addr: str
    :return: The corresponding RIPEMD-160 hash.
    :rtype: hex str
    """

    # Base 58 decode the Bitcoin address.
    decoded_addr = b58decode(btc_addr)
    # Covert the address from bytes to hex.
    decoded_addr_hex = b2a_hex(decoded_addr)
    # Obtain the RIPEMD-160 hash by removing the first and four last bytes of the decoded address, corresponding to
    # the network version and the checksum of the address.
    h160 = decoded_addr_hex[2:-8]

    return h160


def get_pub_key_hex(pk_der):
    """ Converts a public key in hexadecimal format from a DER encoded public key.

    :param pk_der: DER encoded public key
    :type pk_der: bytes
    :return: public key.
    :rtype: hex str
    """

    # Get the asn1 representation of the public key DER data.
    asn1_pk, _ = decoder.decode(pk_der)
    # Get the public key as a BitString. The public key corresponds to the second component
    # of the asn1 public key structure.
    pk_bit = asn1_pk.getComponentByPosition(1)

    # Convert the BitString into a String.
    pk_str = ""
    for i in range(len(pk_bit)):
        pk_str += str(pk_bit[i])
    # Parse the data to get it in the desired form.
    pk_hex = hex(int(pk_str, 2))[2:-1]

    return pk_hex


def public_key_to_btc_address(pk, v='main'):
    """ Calculates the Bitcoin address of a given elliptic curve public key.

    :param pk: elliptic curve public key.
    :type pk: hex str
    :param v: version used to calculate the Bitcoin address.
    :type v: str
    :return: The corresponding Bitcoin address.

        - main network address if v is 'main.
        - testnet address otherwise
    :rtype: hex str
    """

    PUBKEY_HASH = 0
    TESTNET_PUBKEY_HASH = 111

    # Choose the proper version depending on the provided 'v'.
    if v == 'main':
        v = PUBKEY_HASH
    elif v == 'test':
        v = TESTNET_PUBKEY_HASH
    else:
        raise Exception("Invalid version, use either 'main' or 'test'.")

    # Calculate the RIPEMD-160 hash of the given public key.
    h160 = hash_160(pk)
    # Calculate the Bitcoin address from the chosen network.
    btc_addr = hash_160_to_btc_address(h160, v)

    return btc_addr


def generate_btc_addr(pk, v='main'):
    """ Calculates Bitcoin address associated to a given elliptic curve public key and a given network.

    :param pk: elliptic curve public key (in hexadecimal format).
    :type pk: EC_pub
    :param v: version (prefix) used to calculate the WIF, it depends on the type of network.
    :type v: str
    :return: The Bitcoin address associated to the given public key and network.
    :rtype: str
    """

    # Get the hex representation of the provided EC_pub.
    public_key_hex = get_pub_key_hex(pk)
    # Generate the Bitcoin address of de desired network.
    btc_addr = public_key_to_btc_address(public_key_hex, v)

    return btc_addr


def generate_keys():
    """ Gets a new  elliptic curve key pair using the SECP256K1 elliptic curve (the one used by Bitcoin).

    :return: elliptic curve key pair.
    :rtype: list
    """

    # Generate the key pair from a SECP256K1 elliptic curve.
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.get_verifying_key()

    return sk, pk


def get_priv_key_hex(sk_file_path):
    """ Gets the EC private key in hexadecimal format from a key file.

    :param sk_file_path: system path where the EC private key is found.
    :type sk_file_path: str
    :return: private key.
    :rtype: hex str
    """

    # Obtain the private key using an OpenSSL system call.
    cmd = ['openssl', 'ec', '-in', sk_file_path, '-text', '-noout']
    response = check_output(cmd, stderr=STDOUT)

    # Parse the result to remove all the undesired spacing characters.
    raw_key = response[response.find(b'priv:') + 8: response.find(b'pub:')]
    raw_key = raw_key.replace(b":", b"")
    raw_key = raw_key.replace(b" ", b"")
    raw_key = raw_key.replace(b"\n", b"")

    # If the key starts with 00, the two first characters are removed.
    if raw_key[:2] == '00':
        sk_hex = raw_key[2:]
    else:
        sk_hex = raw_key

    return sk_hex


def generate_std_scriptpubkey(target_btc_addr):
    """ Generates a standard Bitcoin ScriptPubKey (AKA P2PKH) bound to a target Bitcoin address. A signature from
    the later will be mandatory to redeem the funds locked by the script.

    :param target_btc_addr: A target Bitcoin address necessary to redeem the funds.
    :type target_btc_addr: str
    :return: A hex representation of the desired script.
    :rtype: hex str
    """

    OP_DUP = 118
    OP_HASH_160 = 169
    OP_EQUALVERIFY = 136
    OP_CHECKSIG = 172

    # Obtain the RIPEMD-160 hash of the target Bitcoin address
    h160 = btc_address_to_hash_160(target_btc_addr)
    # Encode the obtained RIPEMD-160 hash in the P2PKH script
    #scriptpubkey = format(OP_DUP, 'x') + format(OP_HASH_160, 'x') + format(len(h160) // 2, 'x') + h160 + \
    #               format(OP_EQUALVERIFY, 'x') + format(OP_CHECKSIG, 'x')
    f'{OP_DUP:x}{OP_HASH_160:x}{len(h160) // 2:x}{h160}{OP_EQUALVERIFY:x}{OP_CHECKSIG:x}'
    return f'{OP_DUP:x}{OP_HASH_160:x}{len(h160) // 2:x}{h160.decode()}{OP_EQUALVERIFY:x}{OP_CHECKSIG:x}'


def build_raw_tx(prev_tx_id, prev_out_index, value, src_btc_addr, dest_btc_addr):
    assert len(prev_tx_id) == len(prev_out_index) == len(src_btc_addr)

    scriptPubKey = []
    for i in range(len(dest_btc_addr)):
        scriptPubKey.append(generate_std_scriptpubkey(dest_btc_addr[i]))

    tx = TX()
    tx.build_default_tx(prev_tx_id, prev_out_index, value, scriptPubKey)

    signed_tx = ""
    for i in range(len(src_btc_addr)):
        pirv_key = src_btc_addr[i] + "/sk.pem"
        priv_key_hex = get_priv_key_hex(pirv_key)
        signed_tx = sign(tx.hex, 0, priv_key_hex)

    return signed_tx


def broadcast_raw_tx(rawTx):
    # Set RPC configuration
    rpc_user = "user"
    rpc_password = "pass"
    rpc_server = "157.159.103.161"
    rpc_port = 8332

    # Test connection
    # rpc_connection = AuthServiceProxy("http://%s:%s@%s:%s" % (rpc_user, rpc_password, rpc_server, rpc_port))

    # get_info = rpc_connection.getinfo()
    # get_info = rpc_connection.getinfo()
    # print get_info

    # Send transaction

    # print rawTx
    # rpc_connection.sendrawtransaction(rawTx)
    # rpc_connection.sendrawtransaction(rawTx)

    return


''' Step 1 '''

# First of all the elliptic curve keys are generated.
sk, pk = generate_keys()
# The Bitcoin address is derived from the public key created above.
btc_addr = generate_btc_addr(pk.to_der(), v='test')

print(btc_addr)


# Both the public and private key are stored in disk. The Bitcoin
# address is used as an identifier in the name
# of the file.

def store_keys(sk, pk, btc_addr):
    """ Stores an elliptic curve key pair in PEM format into disk.
    :param sk: PEM encoded elliptic curve private key.
    :type sk: str
    :param pk: PEM encoded elliptic curve public key.
    :type pk: str
    :param btc_addr: Bitcoin address associated to the public key of the key  pair.
    :type btc_addr: str
    :return: None.
    :rtype: None
    """
    if not path.exists(btc_addr):
        mkdir(btc_addr)
    # Save both keys into disk using the Bitcoin address as an identifier.
    with open(btc_addr.decode() + '/sk.pem', 'wb') as f:
        f.write(sk)
    with open(btc_addr.decode() + '/pk.pem', 'wb') as f:
        f.write(pk)


#store_keys(sk.to_pem(), pk.to_pem(), btc_addr)

''' Step 2

# Reference to the previous transaction where the funds will be redeemed and spent. Consists in an id an an output.
prev_tx_id = ['fca89836ce8d36b0266021b21a57545f62b06ef682ff77b1c245a4997635785e']
prev_out_index = [1]

# Amount to be spent, in Satoshis.
value = [999000]

# Bitcoin address where the bitcoins come from. It should match with the address referenced by the prev_tx_id.
# The address will be used as an identifier to choose the proper keys when signing the transaction.
src_btc_addr = ['mgcKD4Zd9p5qaHKo6Dn2ExxhVSiyRD3hEb']

# Destination Bitcoin address, where the value in bitcoins will be sent, and lock until the owner redeems it.
destination_btc_addr = ["moe6aoVjwzJzb2VNijmL1atRK9ToHpFvhM"]

# Build the raw transaction using all the provided inputs.
signed_tx = build_raw_tx(prev_tx_id, prev_out_index, value, src_btc_addr, destination_btc_addr)

# Display the transaction
#print(signed_tx)

broadcast_raw_tx(signed_tx)
'''