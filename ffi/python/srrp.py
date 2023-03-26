import ctypes
from ctypes.util import find_library

lib = ctypes.CDLL(find_library("apix"))

class __Srrp():
    def __init__(self, pac):
        self.pac = pac

    def __del__(self):
        func = lib.srrp_free
        func.argtypes = [ctypes.c_void_p]
        func(self.pac)

    def is_null(self):
        if self.pac is None:
            return True
        else:
            return False

    def leader(self):
        func = lib.srrp_get_leader
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_char
        return func(self.pac)

    def packet_len(self):
        func = lib.srrp_get_packet_len
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_uint16
        return func(self.pac)

    def payload_fin(self):
        func = lib.srrp_get_payload_fin
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_uint32
        return func(self.pac)

    def payload_len(self):
        func = lib.srrp_get_payload_len
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_uint32
        return func(self.pac)

    def srcid(self):
        func = lib.srrp_get_srcid
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_uint32
        return func(self.pac)

    def dstid(self):
        func = lib.srrp_get_dstid
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_uint32
        return func(self.pac)

    def anchor(self):
        func = lib.srrp_get_anchor
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_char_p
        return func(self.pac).decode("utf-8")

    def payload(self):
        func = lib.srrp_get_payload
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_char_p
        return func(self.pac).decode("utf-8")

    def crc16(self):
        func = lib.srrp_get_crc16
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_uint16
        return func(self.pac)

    def raw(self):
        func = lib.srrp_get_raw
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.POINTER(ctypes.c_ubyte * self.packet_len())
        return bytes(func(self.pac).contents)

class SrrpCtrl(__Srrp):
    def __init__(self, srcid, anchor, payload):
        func = lib.srrp_new_ctrl
        func.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p]
        func.restype = ctypes.c_void_p
        pac = func(srcid, ctypes.c_char_p(anchor.encode('utf-8')),
                   ctypes.c_char_p(payload.encode('utf-8')))
        assert(pac != 0)
        super().__init__(pac)

class SrrpRequest(__Srrp):
    def __init__(self, srcid, dstid, anchor, payload):
        func = lib.srrp_new_request
        func.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                         ctypes.c_char_p, ctypes.c_char_p]
        func.restype = ctypes.c_void_p
        pac = func(srcid, dstid, ctypes.c_char_p(anchor.encode('utf-8')),
                   ctypes.c_char_p(payload.encode('utf-8')))
        assert(pac != 0)
        super().__init__(pac)

class SrrpResponse(__Srrp):
    def __init__(self, srcid, dstid, anchor, payload):
        func = lib.srrp_new_response
        func.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                         ctypes.c_char_p, ctypes.c_char_p]
        func.restype = ctypes.c_void_p
        pac = func(srcid, dstid, ctypes.c_char_p(anchor.encode('utf-8')),
                   ctypes.c_char_p(payload.encode('utf-8')))
        assert(pac != 0)
        super().__init__(pac)

class SrrpSubscribe(__Srrp):
    def __init__(self, anchor, payload):
        func = lib.srrp_new_subscribe
        func.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        func.restype = ctypes.c_void_p
        pac = func(ctypes.c_char_p(anchor.encode('utf-8')),
                   ctypes.c_char_p(payload.encode('utf-8')))
        assert(pac != 0)
        super().__init__(pac)

class SrrpUnSubscribe(__Srrp):
    def __init__(self, anchor, payload):
        func = lib.srrp_new_unsubscribe
        func.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        func.restype = ctypes.c_void_p
        pac = func(ctypes.c_char_p(anchor.encode('utf-8')),
                   ctypes.c_char_p(payload.encode('utf-8')))
        assert(pac != 0)
        super().__init__(pac)

class SrrpPublish(__Srrp):
    def __init__(self, anchor, payload):
        func = lib.srrp_new_publish
        func.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        func.restype = ctypes.c_void_p
        pac = func(ctypes.c_char_p(anchor.encode('utf-8')),
                   ctypes.c_char_p(payload.encode('utf-8')))
        assert(pac != 0)
        super().__init__(pac)

def srrp_next_packet_offset(buf):
    func = lib.srrp_next_packet_offset
    func.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    func.restype = ctypes.c_uint32
    return func(ctypes.cast(buf, ctypes.c_void_p), len(buf))

def srrp_parse(buf):
    func = lib.srrp_parse
    func.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    func.restype = ctypes.c_void_p
    pac = func(ctypes.cast(buf, ctypes.c_void_p), len(buf))
    if pac is None:
        return None
    return __Srrp(pac)
