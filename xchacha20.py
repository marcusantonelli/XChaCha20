from secrets import randbits
from struct import pack, unpack
from typing import Iterable, overload
from itertools import chain


# Constants
XCHACHA20_MSTR_KEY_SIZE = 256
XCHACHA20_SUB_KEY_SIZE = 0
XCHACHA20_NONCE_SIZE = 192
XCHACHA20_CTR_SIZE = 64


# Rotates an integer value `b` by rotation `rot` bits.
rotl = lambda b, rot: ((b << rot) & 0xFFFFFFFF) | (b >> (32 - rot))

# Clamps a number (Poly1305 key) in the range ____
clamp = lambda r: (
    r[0] & 0x0ffffffc, r[1] & 0x0ffffffc, 
    r[2] & 0x0ffffffc, r[3] & 0x0fffffff,
)

clmp = lambda r: (
    r[3] & 15, r[7] & 15, r[11] & 15, r[15] & 15, 
    r[4] & 252, r[8] & 252, r[12] & 252
)

class ChaCha20:
    """ ChaCha20 block encryption, used for HChaCha20 key derivation and XChaCha20 encryption.
    
    The algorithm is composed of 80 quarter rounds (20 rounds)
    """

    def __init__(self, key: Iterable[int] = None, nonce: Iterable[int] = None, state: Iterable[int] = None):
        self.key = key
        self.nonce = nonce
        self.state = state


    def encrypt(self, plaintext, key: Iterable[int]=None, nonce: Iterable[int]=None):
        key = key or self.key
        nonce = nonce or self.nonce
        counter = 0
        ciphertext = bytearray()

        for j in range((len(plaintext) // 64) - 1):
            keystream = self.block(state=chain(key, (counter+j), nonce))
            block = plaintext[j*64:(j*64)+63]
            ciphertext.extend((a ^ b for a, b in zip(keystream, block)))
        
        if len(plaintext) % 64 != 0:
            j = len(plaintext) // 64
            keystream = self.block(key, (counter+j), nonce)
            block = plaintext[j*64:len(plaintext)-1]
            ciphertext.extend()
        return ciphertext

 
    def block(self, state: Iterable[int] = None, carryless_addition = True):

        state = state or self.state
        ws = list(state)

        # Perform 20 rounds
        for i in range(10):
            # Columns
            (ws[0], ws[4], 
            ws[8], ws[12]) = ChaCha20.quarter_round(ws[0], ws[4], ws[8], ws[12])

            (ws[1], ws[5], 
            ws[9], ws[13]) = ChaCha20.quarter_round(ws[1], ws[5], ws[9], ws[13])

            (ws[2], ws[6], 
            ws[10], ws[14]) = ChaCha20.quarter_round(ws[2], ws[6], ws[10], ws[14])

            (ws[3], ws[7], 
            ws[11], ws[15]) = ChaCha20.quarter_round(ws[3], ws[7], ws[11], ws[15])

            # Diagonals
            (ws[0], ws[5], 
            ws[10], ws[15]) = ChaCha20.quarter_round(ws[0], ws[5], ws[10], ws[15])

            (ws[1], ws[6], 
            ws[11], ws[12]) = ChaCha20.quarter_round(ws[1], ws[6], ws[11], ws[12])

            (ws[2], ws[7], 
            ws[8], ws[13]) = ChaCha20.quarter_round(ws[2], ws[7], ws[8], ws[13])

            (ws[3], ws[4], 
            ws[9], ws[14]) = ChaCha20.quarter_round(ws[3], ws[4], ws[9], ws[14])

        # Perform carryless addition of the state and working state words, return result
        if carryless_addition:
            result = tuple(sum(pair) % 0x100000000 for pair in zip(state, ws)) 
        else: 
            result = tuple(ws)
        ws = None
        return result


    @staticmethod
    def quarter_round(a: int, b: int, c: int, d: int):
        a = (a + b) & 0xFFFFFFFF
        d = rotl(d ^ a, 16)
        c = (c + d) & 0xFFFFFFFF
        b = rotl(b ^ c, 12)
        a = (a + b) & 0xFFFFFFFF
        d = rotl(d ^ a, 8)
        c = (c + d) & 0xFFFFFFFF
        b = rotl(b ^ c, 7)
        return (a, b, c, d)


class HChaCha20:

    # Arbitrary HChaCha20 constant, 'expand 32-byte k'
    CONST = (
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    )

    def __init__(self, key: Iterable[int]):
        self.initial_state = list(HChaCha20.CONST)
        self.initial_state.extend(key)


    def derive_key(self, nonce: Iterable[int]) -> tuple[int]:
        """ Derives a subkey for XChaCha20 encryption using HChaCha20 with a masterkey. """
        state = self.initial_state
        state.extend(nonce)
        state = ChaCha20(state=state).block(carryless_addition=False)

        # Convert the little-endian words to big-endian words, and return resultant subkey
        return tuple(unpack('>I', pack('<I', x))[0] for x in state[:4] + state[12:])
    

class XChaCha20_Poly1305:

    def __init__(self, key=tuple(randbits(32) for _ in range(XCHACHA20_MSTR_KEY_SIZE//32))):
        self.key = key
        self.hchacha20 = HChaCha20(key)
        self.state = []
        self.accumulator = 0


    def encrypt(self):
        """ Encrypts plaintext with XChaCha20 using a Poly1305 AAD tag. """
        self.__xchacha20_encrypt()
        self.__poly1305_compute()


    def decrypt(self):
        self.__xchacha20_decrypt()
        self.__poly1305_verify()


    def __xchacha20_encrypt(self, m: Iterable[int]):
        """ Encrypts plaintext using XChaCha20 """
        nonce = tuple(randbits(32) for _ in range(XCHACHA20_NONCE_SIZE//32))
        subkey = self.hchacha20.derive_key(nonce[0:15])
        keystream = ChaCha20(subkey + nonce[16:23]).block()
        c = bytearray()
        for block in m:
            c.append(block ^ keystream)
        return c


  ############################# UNIMPLEMENTED ###################################


    def __poly1305_key_gen(self, nonce):
        pass

    
    def __poly1305_mac(self, key, nonce, m):
        """ Computes a MAC/AAD using the Poly1305 algorithm. """
        r = __clamp(key[:4])
        s = key[5:8]
        accumulator = 0
        p = (1 << 130) - 5
        for i in range(1, len(m) // 16):
            pass


    def __xchacha20_decrypt(self):
        pass


    def __poly1305_verify(self):
        pass
