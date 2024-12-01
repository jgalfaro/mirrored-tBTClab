import codecs
from ecdsa import SigningKey, SECP256k1
from subprocess import check_output, STDOUT
from pyasn1.codec.der import decoder
from binascii import a2b_hex, b2a_hex
from hashlib import new, sha256
from os import mkdir, path
from base58 import b58encode, b58decode
from bitcoin import sign

#####################################################################
#### we define a bitcoin transaction class for the lab as follows
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
            self.prev_tx_id.append(change_endianness(prev_tx_id[i]))
            self.prev_out_index.append(change_endianness(int2bytes(prev_out_index[i], 4)))


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
            self.value.append(change_endianness(int2bytes(value[i], 8)))

            self.scriptPubKey_len.append(int2bytes(len(script_pub_key[i]) // 2, 1))
            self.scriptPubKey = script_pub_key

        self.nLockTime = "00000000"

        self.to_hex()
#### bitcoin transaction class ends here
###########################################################


###########################################################
#### some additional functions follow ...

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
    rpc_user = "" #e.g., user
    rpc_password = "" #e.g., pass
    rpc_server = "" #e.g., 157.159.103.161
    rpc_port = 8332 #e.g., 8332

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

def int2bytes(a, b):
    return ('%0' + str(2 * b) + 'x') % a


def change_endianness(x):
    decoder = codecs.getdecoder("hex_codec")
    encoder = codecs.getencoder('hex')

    # If there is an odd number of elements, we make it even by adding a 0
    if (len(x) % 2) == 1:
        x += "0"
    y = decoder(x)[0]
    aux = y[::-1]
    z = encoder(aux)
    return z[0].decode('utf-8')


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

#### additional functions end here
###########################################################


''' Lab Step 3, create a transaction to move some satoshis from address A to address B '''

# Reference to the previous transaction where the funds will be redeemed and spent. Consists in an id of an output.
prev_tx_id = ['e88bf38f0b7d2fb0a0530755675a70a60aecf7eac84ccf3b84db0f96934767bc']
prev_out_index = [1]

# Amount to be spent, in Satoshis.
value = [99990]

# Bitcoin address where satoshis come from. It should match with the address referenced by the prev_tx_id.
# This address will also be used as an identifier to choose the proper keys when signing the transaction.
src_btc_addr = ['mnbfqHxUoARr4Ucu3agEs3bGpT9EFsygFQ']

# Destination Bitcoin address, where the value in satoshis will be sent, and lock until the owner redeems them.
destination_btc_addr = ['mriUTYm51KBK7PdB1WQZTN92RXNvSnkAuE']

# Build the raw transaction using all the provided inputs.
signed_tx = build_raw_tx(prev_tx_id, prev_out_index, value, src_btc_addr, destination_btc_addr)
# Display the transaction as a serialized object
print(signed_tx)

