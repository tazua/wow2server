"""The bd wire codec: bit- and byte-mode readers and writers with 5-bit type
tags, connection framing, and the blind typed-field walk. Ported from the
reference open-bitdemon-emulator and pinned to this 2007 title by capture.
"""
from __future__ import annotations

import struct

# ---- bd data type tags (5-bit in bit mode, 1 byte in byte mode) ----
BD_NOTYPE = 0x0
BD_BOOL = 0x1
BD_SINT8 = 0x2
BD_UINT8 = 0x3
BD_WCHAR16 = 0x4
BD_SINT16 = 0x5
BD_UINT16 = 0x6
BD_SINT32 = 0x7
BD_UINT32 = 0x8
BD_SINT64 = 0x9
BD_UINT64 = 0xA
BD_RANGED_SINT32 = 0xB
BD_RANGED_UINT32 = 0xC
BD_F32 = 0xD
BD_F64 = 0xE
BD_RANGED_F32 = 0xF
BD_STR = 0x10
BD_USTR = 0x11
BD_MBSTR = 0x12
BD_BLOB = 0x13
BD_ARRAY_OFFSET = 100

TYPE_NAMES = {
    BD_BOOL: "bool", BD_SINT8: "i8", BD_UINT8: "u8", BD_SINT16: "i16",
    BD_UINT16: "u16", BD_SINT32: "i32", BD_UINT32: "u32", BD_SINT64: "i64",
    BD_UINT64: "u64", BD_F32: "f32", BD_F64: "f64", BD_STR: "str", BD_BLOB: "blob",
}


class BdReader:
    """LSB-first bit reader matching bd_reader.rs exactly."""

    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0
        self.bit_offset = 8    # 8 = byte-aligned, take a fresh byte next
        self.last_byte = 0
        self.bitmode = False
        self.type_checked = False

    def _rd(self, n: int) -> bytes:
        b = self.buf[self.pos:self.pos + n]
        if len(b) != n:
            raise EOFError(f"want {n} at {self.pos}, have {len(b)}")
        self.pos += n
        return b

    def read_bits(self, count: int) -> bytes:
        assert self.bitmode
        out = bytearray()
        bits_left = count
        while bits_left > 0:
            in_byte = self.last_byte
            if bits_left > 8 - self.bit_offset:
                in_byte2 = self._rd(1)[0]
                shifted = (in_byte >> self.bit_offset) if self.bit_offset < 8 else 0
                out_byte = (shifted | (in_byte2 << (8 - self.bit_offset))) & 0xFF
                self.last_byte = in_byte2
                max_read = 8
            else:
                out_byte = (in_byte >> self.bit_offset) & 0xFF
                max_read = 8 - self.bit_offset
            if bits_left >= 8:
                bits_left -= max_read
            else:
                read_bits = min(bits_left, max_read)
                self.bit_offset += read_bits
                if self.bit_offset > 8:
                    self.bit_offset -= 8
                out_byte &= 0xFF >> (8 - read_bits)
                bits_left -= read_bits
            out.append(out_byte)
        return bytes(out)

    def read_type_checked_bit(self):
        self.type_checked = self.read_bits(1)[0] > 0
        return self.type_checked

    def _read_data_type(self) -> int:
        if not self.bitmode:
            return self._rd(1)[0]
        return self.read_bits(5)[0]

    def _int(self, nbytes: int, signed: bool, want_type: int) -> int:
        if self.type_checked:
            t = self._read_data_type()
        if not self.bitmode:
            raw = self._rd(nbytes)
        else:
            raw = self.read_bits(nbytes * 8)[:nbytes]
        return int.from_bytes(raw, "little", signed=signed)

    def u8(self):  return self._int(1, False, BD_UINT8)
    def u16(self): return self._int(2, False, BD_UINT16)
    def u32(self): return self._int(4, False, BD_UINT32)
    def u64(self): return self._int(8, False, BD_UINT64)
    def i32(self): return self._int(4, True, BD_SINT32)
    def i64(self): return self._int(8, True, BD_SINT64)

    def bool_(self) -> bool:
        """BD_BOOL: a type tag then ONE bit, mirroring BdWriter.bool_."""
        if self.type_checked:
            self._read_data_type()
        return bool(self.read_bits(1)[0] & 1)

    def f64(self) -> float:
        """BD_F64: a type tag then 64 bits of little-endian IEEE double."""
        if self.type_checked:
            self._read_data_type()
        raw = self.read_bits(64)[:8] if self.bitmode else self._rd(8)
        return struct.unpack("<d", bytes(raw))[0]

    def str_(self, maxlen: int = 512) -> str:
        """BD_STR: a type tag then 8-bit chars up to a NUL. No length prefix."""
        if self.type_checked:
            self._read_data_type()
        out = bytearray()
        while len(out) < maxlen:
            c = self.read_bits(8)[0] if self.bitmode else self._rd(1)[0]
            if c == 0:
                break
            out.append(c)
        return out.decode("latin1")

    def blob(self) -> bytes:
        """BD_BLOB: a blob tag, then a NESTED TYPED u32 byte count, then the bytes."""
        if self.type_checked:
            self._read_data_type()
        n = self.u32()
        return self.bytes_raw(n)

    def bytes_raw(self, n: int) -> bytes:
        if self.bitmode:
            return self.read_bits(n * 8)[:n]
        return self._rd(n)

    def remaining(self) -> bytes:
        return self.buf[self.pos:]


class BdWriter:
    """LSB-first bit writer matching bd_writer.rs. Byte mode by default."""

    def __init__(self):
        self.out = bytearray()
        self.bit_offset = 8
        self.last_byte = 0
        self.bitmode = False
        self.type_checked = False

    def flush(self):
        if self.bit_offset < 8:
            self.out.append(self.last_byte)
            self.bit_offset = 8
            self.last_byte = 0

    def write_bits(self, buf: bytes, count: int):
        assert self.bitmode
        bits_left = count
        i = 0
        while bits_left > 0:
            in_bits = 8
            in_byte = buf[i]
            i += 1
            if bits_left < 8:
                in_bits = bits_left
                in_byte &= 0xFF >> (8 - bits_left)
            if self.bit_offset < 8:
                self.last_byte = (self.last_byte | (in_byte << self.bit_offset)) & 0xFF
                s = self.bit_offset + in_bits
                if s > 8:
                    used = 8 - self.bit_offset
                    self.out.append(self.last_byte)
                    self.bit_offset = self.bit_offset + (in_bits - 8)
                    self.last_byte = (in_byte >> used) & 0xFF
                elif s == 8:
                    self.out.append(self.last_byte)
                    self.last_byte = 0
                    self.bit_offset = 8
                else:
                    self.bit_offset += in_bits
            elif in_bits == 8:
                self.out.append(in_byte & 0xFF)
            else:
                self.last_byte = in_byte & 0xFF
                self.bit_offset = in_bits
            bits_left -= in_bits

    def _dt(self, t: int):
        if self.bitmode:
            self.write_bits(bytes([t]), 5)
        else:
            self.out.append(t)

    def u8(self, v, typed=None):
        if (self.type_checked if typed is None else typed): self._dt(BD_UINT8)
        self._emit(v.to_bytes(1, "little"))
    def bool_(self, v):
        """BD_BOOL: a type tag then ONE bit (bddump FIXED[BD_BOOL] = 1), not a byte.
        Only meaningful in bitmode -- byte mode has no sub-byte field.
        """
        if self.type_checked: self._dt(BD_BOOL)
        self.write_bits(b"\x01" if v else b"\x00", 1)

    def u16(self, v):
        if self.type_checked: self._dt(BD_UINT16)
        self._emit((v & 0xFFFF).to_bytes(2, "little"))
    def u32(self, v):
        if self.type_checked: self._dt(BD_UINT32)
        self._emit((v & 0xFFFFFFFF).to_bytes(4, "little"))
    def u64(self, v):
        if self.type_checked: self._dt(BD_UINT64)
        self._emit((v & (2**64-1)).to_bytes(8, "little"))
    def i32(self, v):
        if self.type_checked: self._dt(BD_SINT32)
        self._emit((v & 0xFFFFFFFF).to_bytes(4, "little"))
    def i64(self, v):
        if self.type_checked: self._dt(BD_SINT64)
        self._emit((v & (2**64-1)).to_bytes(8, "little"))
    def f64(self, v):
        """BD_F64: a type tag then 64 bits of little-endian IEEE double."""
        if self.type_checked: self._dt(BD_F64)
        self._emit(struct.pack("<d", float(v)))
    def str_(self, v, maxlen=64):
        """BD_STR: a type tag then raw 8-bit chars terminated by NUL."""
        if self.type_checked: self._dt(BD_STR)
        b = v.encode("latin1") if isinstance(v, str) else bytes(v)
        b = b[:maxlen - 1].replace(b"\x00", b"")
        self._emit(b + b"\x00")

    def blob(self, b: bytes):
        """BD_BLOB, mirroring BdReader.blob: tag, typed u32 length, raw bytes."""
        if self.type_checked:
            self._dt(BD_BLOB)
        self.u32(len(b))
        self._emit(bytes(b))

    def _emit(self, raw: bytes):
        if self.bitmode:
            self.write_bits(raw, len(raw) * 8)
        else:
            self.out += raw

    def raw(self, b: bytes):
        self._emit(b)

    def getvalue(self) -> bytes:
        self.flush()
        return bytes(self.out)


# ---- connection framing (bd_socket.rs / bd_response.rs) ----
def frame_unencrypted(payload: bytes) -> bytes:
    """[u32 le len][0x00 enc-flag][payload]. len counts flag+payload."""
    body = b"\x00" + payload
    return len(body).to_bytes(4, "little") + body


BUFSIZE_ANNOUNCE = 180    # this 2007 SDK's value; the reference emulator's is 200


MAX_FRAME = 0x10000


AUTH_TYPES = (0x00, 0x0a, 0x0b)


def _frames_here(buf: bytes, j: int) -> bool:
    """Does a REAL frame start at j?"""
    if j + 6 > len(buf):
        return False
    ln = int.from_bytes(buf[j:j+4], "little")
    if ln == BUFSIZE_ANNOUNCE:
        return j + 8 <= len(buf)
    if not (8 <= ln <= MAX_FRAME) or j + 4 + ln > len(buf):
        return False
    enc = buf[j + 4]
    if enc not in (0, 1):
        return False
    return enc == 1 or buf[j + 5] in AUTH_TYPES


def _chains_to_end(buf: bytes, j: int) -> bool:
    """Do frames from j consume the rest of the buffer (a trailing partial
    frame is fine)? One lucky length is a coincidence; a clean chain is not.
    """
    i = j
    seen = 0
    while i + 4 <= len(buf):
        ln = int.from_bytes(buf[i:i+4], "little")
        if ln == 0:
            i += 4; seen += 1; continue
        if ln == BUFSIZE_ANNOUNCE:
            if i + 8 > len(buf): return seen > 0
            i += 8; seen += 1; continue
        if not (2 <= ln <= MAX_FRAME):
            return False
        if i + 4 + ln > len(buf):
            return seen > 0
        i += 4 + ln; seen += 1
    return seen > 0


def parse_frame(buf: bytes):
    """Yield (kind, data). kind in {'ping','bufsize','msg'}."""
    out = []
    skipped = b""
    i = 0
    while i + 4 <= len(buf):
        ln = int.from_bytes(buf[i:i+4], "little")
        if ln == 0:
            out.append(("ping", b"")); i += 4; continue
        if ln == BUFSIZE_ANNOUNCE:
            if i + 8 > len(buf): break
            out.append(("bufsize", buf[i+4:i+8])); i += 8; continue
        if ln > MAX_FRAME:
            j = i + 1
            while j + 4 <= len(buf) and not (_frames_here(buf, j)
                                             and _chains_to_end(buf, j)):
                j += 1
            if j + 4 > len(buf):
                break
            skipped += buf[i:j]
            i = j
            continue
        if i + 4 + ln > len(buf):
            break
        out.append(("msg", buf[i+4:i+4+ln])); i += 4 + ln
    return out, buf[i:], skipped


def unwrap_message(msg: bytes):
    """msg[0]=enc flag. Return (encrypted, payload_after_flag)."""
    return msg[0], msg[1:]


# --------------------------------------------------------- generic field walk
_FIELD_BITS = {BD_BOOL: 1, BD_SINT8: 8, BD_UINT8: 8, BD_WCHAR16: 16,
               BD_SINT16: 16, BD_UINT16: 16, BD_SINT32: 32, BD_UINT32: 32,
               BD_F32: 32, BD_SINT64: 64, BD_UINT64: 64, BD_F64: 64}
_FIELD_SIGNED = {BD_SINT8, BD_SINT16, BD_SINT32, BD_SINT64}
_FIELD_FLOAT = {BD_F32: "<f", BD_F64: "<d"}
_FIELD_UNWALKABLE = {BD_RANGED_SINT32, BD_RANGED_UINT32, BD_RANGED_F32}


def bits_left(r: "BdReader") -> int:
    return (len(r.buf) - r.pos) * 8 + (8 - r.bit_offset if r.bit_offset < 8 else 0)


def read_field(r: "BdReader"):
    """(type tag, value) for the next typed field. Raises at the end of data."""
    import struct
    t = r._read_data_type()
    if t in _FIELD_BITS:
        n = _FIELD_BITS[t]
        raw = r.read_bits(n)[: max(1, n // 8)]
        if t == BD_BOOL:
            return t, bool(raw[0] & 1)
        if t in _FIELD_FLOAT:
            return t, struct.unpack(_FIELD_FLOAT[t], raw)[0]
        return t, int.from_bytes(raw, "little", signed=t in _FIELD_SIGNED)
    if t in (BD_STR, BD_MBSTR):
        out = bytearray()
        while len(out) < 512:
            c = r.read_bits(8)[0]
            if c == 0:
                break
            out.append(c)
        return t, out.decode("latin1")
    if t == BD_USTR:
        out = []
        while len(out) < 512:
            c = int.from_bytes(r.read_bits(16)[:2], "little")
            if c == 0:
                break
            out.append(chr(c))
        return t, "".join(out)
    if t == BD_BLOB:
        lt = r._read_data_type()
        if lt != BD_UINT32:
            raise ValueError(f"blob length has type {lt}, expected u32")
        n = int.from_bytes(r.read_bits(32)[:4], "little")
        if n > bits_left(r) // 8:
            raise ValueError(f"blob length {n} exceeds the buffer")
        return t, bytes(r.read_bits(n * 8)[:n])
    if t in _FIELD_UNWALKABLE:
        raise ValueError(f"data type {t} is ranged -- cannot walk blind")
    raise ValueError(f"unknown data type {t}")


def read_fields(r: "BdReader", limit: int = 4096):
    """Every typed field until the buffer runs out. Stops cleanly on the zero
    padding that follows the last field (type 0 is not a real type).
    """
    out = []
    while len(out) < limit and bits_left(r) >= 5:
        try:
            out.append(read_field(r))
        except Exception:
            break
    return out


def write_field(w: "BdWriter", t: int, v):
    """Re-emit one (type, value) pair read by read_field."""
    import struct
    if t in _FIELD_BITS:
        if w.type_checked:
            w._dt(t)
        n = _FIELD_BITS[t]
        if t == BD_BOOL:
            w.write_bits(bytes([1 if v else 0]), 1)
            return
        if t in _FIELD_FLOAT:
            w._emit(struct.pack(_FIELD_FLOAT[t], v))
            return
        w._emit(int(v).to_bytes(n // 8, "little", signed=t in _FIELD_SIGNED)
                if t in _FIELD_SIGNED else
                (int(v) & ((1 << n) - 1)).to_bytes(n // 8, "little"))
        return
    if t in (BD_STR, BD_MBSTR):
        w.str_(v, maxlen=513)
        return
    if t == BD_USTR:
        if w.type_checked:
            w._dt(BD_USTR)
        for ch in v:
            w._emit(ord(ch).to_bytes(2, "little"))
        w._emit(b"\x00\x00")
        return
    if t == BD_BLOB:
        w.blob(v)
        return
    raise ValueError(f"cannot re-emit data type {t}")


def write_fields(w: "BdWriter", fields):
    for t, v in fields:
        write_field(w, t, v)
