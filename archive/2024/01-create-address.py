from ecdsa import SigningKey, SECP256k1
from subprocess import check_output, STDOUT
from pyasn1.codec.der import decoder
from binascii import a2b_hex, b2a_hex
from hashlib import new, sha256
from os import mkdir, path
from base58 import b58encode, b58decode
from bitcoin import sign

###########################################################
#### some additional functions follow ...

def generate_keys():
    """ Gets a new  elliptic curve key pair using the SECP256K1 elliptic curve (the one used by Bitcoin).

    :return: elliptic curve key pair.
    :rtype: list
    """

    # Generate the key pair from a SECP256K1 elliptic curve.
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.get_verifying_key()

    return sk, pk


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
    """ Compute the bitcoin address of a given elliptic curve public key.

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

#### additional functions end here
###########################################################


''' Step 1: Create a bitcoin address and store the key pair in a folder labelled with the same address '''

# 1.1. Let's generate the key pair (secret and public keys)
sk, pk = generate_keys()
# Now, the bitcoin address gets derived from the public key created above.
# parameter 'test' means that we will be using the bitcoin testing network
btc_addr = generate_btc_addr(pk.to_der(), v='test')

# 1.2. Now, let's store the public and private keys in your filesystem.
# We will use the bitcoin address as the identifier of the folder where
# we store both keys

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


# 1.3. Finally, we print out the bitcoin address (i.e., folder identifier)

print(f"1.3. Creating folder {btc_addr} and storing keys ... OK!")
store_keys(sk.to_pem(), pk.to_pem(), btc_addr)

print("Use the following two commands to verify each file:")
print("  openssl ec -in sk.pem -text")
print("  openssl ec -pubin -in pk.pem -text")
