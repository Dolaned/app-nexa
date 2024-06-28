"""Bitcoin Object Python Serializations.

Copyright (c) 2010 ArtForz -- public domain half-a-node
Copyright (c) 2012 Jeff Garzik
Copyright (c) 2010-2016 The Bitcoin Core developers

Distributed under the MIT software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php.

Modified from the test/test_framework/mininode.py file from the
Bitcoin repository

CTransaction,CTxIn, CTxOut, etc....:
    data structures that should map to corresponding structures in
    bitcoin/primitives for transactions only
ser_*, deser_*: functions that handle serialization/deserialization

"""

import struct
import binascii
import hashlib
import copy
import base64
from io import BytesIO
from typing import (
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Callable
)
from typing_extensions import Protocol

SER_DEFAULT = 0
SER_ID = 0
SER_IDEM = 1


class Readable(Protocol):
    def read(self, n: int = -1) -> bytes:
        ...


class Deserializable(Protocol):
    def deserialize(self, f: Readable) -> None:
        ...


class Serializable(Protocol):
    def serialize(self) -> bytes:
        ...


def sha256(s: bytes) -> bytes:
    return hashlib.new('sha256', s).digest()


def ripemd160(s: bytes) -> bytes:
    return hashlib.new('ripemd160', s).digest()


def hash256(s: bytes) -> bytes:
    return sha256(sha256(s))


def hash160(s: bytes) -> bytes:
    return ripemd160(sha256(s))


# Serialization/deserialization tools
def ser_compact_size(size: int) -> bytes:
    r: bytes
    if size < 253:
        r = struct.pack("B", size)
    elif size < 0x10000:
        r = struct.pack("<BH", 253, size)
    elif size < 0x100000000:
        r = struct.pack("<BI", 254, size)
    else:
        r = struct.pack("<BQ", 255, size)
    return r


def deser_compact_size(f: Readable) -> int:
    nit: int = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit


def deser_string(f: Readable) -> bytes:
    nit = deser_compact_size(f)
    return f.read(nit)


def ser_string(s: bytes) -> bytes:
    return ser_compact_size(len(s)) + s


def deser_uint256(f: Readable) -> int:
    r = 0
    for i in range(8):
        t = struct.unpack("<I", f.read(4))[0]
        r += t << (i * 32)
    return r


def ser_uint256(u: int) -> bytes:
    rs = b""
    for _ in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


def uint256_from_str(s: bytes) -> int:
    r = 0
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


D = TypeVar("D", bound=Deserializable)


def deser_vector(f: Readable, c: Callable[[], D]) -> List[D]:
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = c()
        t.deserialize(f)
        r.append(t)
    return r


def ser_vector(l, stype=SER_ID):
    r = b""
    if len(l) < 253:
        r = struct.pack("B", len(l))
    elif len(l) < 0x10000:
        r = struct.pack("<BH", 253, len(l))
    elif len(l) < 0x100000000:
        r = struct.pack("<BI", 254, len(l))
    else:
        r = struct.pack("<BQ", 255, len(l))
    for i in l:
        r += i.serialize(stype)
    return r


def deser_string_vector(f: Readable) -> List[bytes]:
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(v: List[bytes]) -> bytes:
    r = ser_compact_size(len(v))
    for sv in v:
        r += ser_string(sv)
    return r


def hex_to_base64(s: str) -> bytes:
    return base64.b64encode(binascii.unhexlify(s))


def ser_sig_der(r: bytes, s: bytes) -> bytes:
    sig = b"\x30"

    # Make r and s as short as possible
    ri = 0
    for b in r:
        if b == 0:
            ri += 1
        else:
            break
    r = r[ri:]
    si = 0
    for b in s:
        if b == 0:
            si += 1
        else:
            break
    s = s[si:]

    # Make positive of neg
    first = r[0]
    if first & (1 << 7) != 0:
        r = b"\x00" + r
    first = s[0]
    if first & (1 << 7) != 0:
        s = b"\x00" + s

    # Write total length
    total_len = len(r) + len(s) + 4
    sig += struct.pack("B", total_len)

    # write r
    sig += b"\x02"
    sig += struct.pack("B", len(r))
    sig += r

    # write s
    sig += b"\x02"
    sig += struct.pack("B", len(s))
    sig += s

    sig += b"\x01"
    return sig


def ser_sig_compact(r: bytes, s: bytes, recid: bytes) -> bytes:
    rec = struct.unpack("B", recid)[0]
    prefix = struct.pack("B", 27 + 4 + rec)

    sig = b""
    sig += prefix
    sig += r + s

    return sig

# Objects that map to bitcoind objects, which can be serialized/deserialized


MSG_WITNESS_FLAG = 1 << 30


class COutPoint(object):
    def __init__(self, h: int = 0):
        self.hash = h

    def deserialize(self, f: Readable) -> None:
        self.hash = deser_uint256(f)

    def serialize(self) -> bytes:
        r = b""
        if isinstance(self.hash, bytes):
            self.hash = int.from_bytes(self.hash, 'little')
        r += ser_uint256(self.hash)
        return r

    def __repr__(self) -> str:
        # assert isinstance(self.hash, int)
        if isinstance(self.hash, bytes):
            self.hash = int.from_bytes(self.hash, 'little')
        return "COutPoint(hash=%064x)" % (self.hash)


class CTxIn(object):
    def __init__(
        self,
        inputType: int = 0,
        outpoint: Optional[COutPoint] = None,
        scriptSig: bytes = b"",
        nSequence: int = 0,
        amount: int = 0
    ):
        self.inputType = inputType
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence
        self.amount = amount

    def deserialize(self, f: Readable) -> None:
        self.inputType = struct.unpack("B", f.read(1))[0]
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = struct.unpack("<I", f.read(4))[0]
        self.amount = struct.unpack("<q", f.read(8))[0]

    def serialize(self, stype):
            r = b""
            r += struct.pack("<B", self.inputType)
            r += self.prevout.serialize()
            if stype != SER_IDEM:
                r += ser_string(self.scriptSig)
            r += struct.pack("<I", self.nSequence)
            r += struct.pack("<q", int(self.amount))
            return r

    def __repr__(self) -> str:
        return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" \
            % (repr(self.prevout), self.scriptSig.hex(),
               self.nSequence)


def is_p2sh(script: bytes) -> bool:
    return len(script) == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87

def is_p2st(script: bytes) -> bool:
    return len(script) == 32 and script[0] == 0x00 and script[1] == 0x51 and script[2] == 0x14

def is_p2pkh(script: bytes) -> bool:
    return (len(script) == 25 and
            script[0] == 0x76 and
            script[1] == 0xa9 and
            script[2] == 0x14 and
            script[23] == 0x88 and
            script[24] == 0xac)


def is_p2pk(script: bytes) -> bool:
    return ((len(script) == 35 or len(script) == 67) and
            (script[0] == 0x21 or script[0] == 0x41) and
            script[-1] == 0xac)


def is_witness(script: bytes) -> Tuple[bool, int, bytes]:
    if len(script) < 4 or len(script) > 42:
        return False, 0, b""

    if script[0] != 0 and (script[0] < 81 or script[0] > 96):
        return False, 0, b""

    if script[1] + 2 == len(script):
        return True, script[0] - 0x50 if script[0] else 0, script[2:]

    return False, 0, b""


def is_p2wpkh(script: bytes) -> bool:
    is_wit, wit_ver, wit_prog = is_witness(script)
    if not is_wit:
        return False
    elif wit_ver != 0:
        return False
    return len(wit_prog) == 20


def is_p2wsh(script: bytes) -> bool:
    is_wit, wit_ver, wit_prog = is_witness(script)
    if not is_wit:
        return False
    elif wit_ver != 0:
        return False
    return len(wit_prog) == 32


class CTxOut(object):
    def __init__(self,nType: int = 1, nValue: int = 0, scriptPubKey: bytes = b""):
        self.nType = nType
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def deserialize(self, f: Readable) -> None:
        self.nType  = struct.unpack("B", f.read(1))[0]
        self.nValue = struct.unpack("<q", f.read(8))[0]
        self.scriptPubKey = deser_string(f)

    def serialize(self, serType=SER_DEFAULT):
            r =  struct.pack("<B", self.nType)
            r += struct.pack("<q", int(self.nValue))
            r += ser_string(self.scriptPubKey)
            return r

    def is_p2sh(self) -> bool:
        return is_p2sh(self.scriptPubKey)

    def is_p2pkh(self) -> bool:
        return is_p2pkh(self.scriptPubKey)
    
    def is_p2st(self) -> bool:
        return is_p2st(self.scriptPubKey)

    def is_p2pk(self) -> bool:
        return is_p2pk(self.scriptPubKey)

    def is_witness(self) -> Tuple[bool, int, bytes]:
        return is_witness(self.scriptPubKey)

    def __repr__(self) -> str:
        return "CTxOut(nType=%i nValue=%i scriptPubKey=%s)" \
            % (self.nType, self.nValue, self.scriptPubKey.hex())

class CTransaction(object):
    def __init__(self, tx: Optional['CTransaction'] = None) -> None:
        if tx is None:
            self.nVersion = 0
            self.vin: List[CTxIn] = []
            self.vout: List[CTxOut] = []
            self.nLockTime = 0
            self.sha256: Optional[int] = None
            self.hash: Optional[str] = None
        else:
            self.nVersion = tx.nVersion
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.sha256 = tx.sha256
            self.hash = tx.hash

    def deserialize(self, f: Readable) -> None:
        self.nVersion = struct.unpack("B", f.read(1))[0]
        self.vin = deser_vector(f, CTxIn)
        self.vout = deser_vector(f, CTxOut)
        self.nLockTime = struct.unpack("<I", f.read(4))[0]
        self.sha256 = None
        self.hash = None

    # Regular serialization is without witness -- must explicitly
    # call serialize_with_witness to include witness data.
    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<B", self.nVersion)
        r += ser_vector(self.vin, stype)
        r += ser_vector(self.vout, stype)
        r += struct.pack("<I", self.nLockTime)
        return r

    # Recalculate the txid (transaction hash without witness)
    def rehash(self) -> None:
        self.sha256 = None
        self.calc_sha256()
        self.calcIdem()

    # We will only cache the serialization without witness in
    # self.sha256 and self.hash -- those are expected to be the txid.
    def calc_sha256(self) -> Optional[int]:
        if self.sha256 is None:
            self.sha256 = uint256_from_str(hash256(self.serialize()))
        self.hash = hash256(self.serialize())[::-1].hex()
        return None
    
    def calcIdem(self):
        self.idem = hash256(self.serialize(SER_IDEM))
        return self.idem

    def is_null(self) -> bool:
        return len(self.vin) == 0 and len(self.vout) == 0

    @classmethod
    def from_bytes(cls, b: bytes):
        tx = cls()
        tx.deserialize(BytesIO(b))

        return tx

    def __repr__(self) -> str:
        return "CTransaction(nVersion=%i vin=%s vout=%s nLockTime=%i)" \
            % (self.nVersion, repr(self.vin), repr(self.vout), self.nLockTime)
