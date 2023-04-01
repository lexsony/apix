import ctypes
from ctypes.util import find_library
import srrp

lib = ctypes.CDLL(find_library("apix"))

LOG_LEVEL_TRACE = 1
LOG_LEVEL_DEBUG = 2
LOG_LEVEL_INFO = 3
LOG_LEVEL_NOTICE = 4
LOG_LEVEL_WARN = 5
LOG_LEVEL_ERROR = 6
LOG_LEVEL_FATAL = 7

def log_set_level(level):
    func = lib.log_set_level
    func.argtypes = [ctypes.c_int32]
    func(level)

class Apix():
    def __init__(self):
        func = lib.apix_new
        func.restype = ctypes.c_void_p
        self.ctx = func()

    def __del__(self):
        func = lib.apix_drop
        func.argtypes = [ctypes.c_void_p]
        func(self.ctx)

    def close(self, fd):
        func = lib.apix_close
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32]
        func(self.ctx, fd)

    def accept(self, fd):
        func = lib.apix_accept
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32]
        func(self.ctx, fd)

    def send(self, fd, buf):
        func = lib.apix_send
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        assert(type(buf) == bytes)
        return func(self.ctx, fd, ctypes.cast(buf, ctypes.c_void_p), len(buf))

    def send_str(self, fd, s):
        func = lib.apix_send
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        assert(type(s) == str)
        return func(self.ctx, fd, ctypes.c_char_p(s.encode('utf-8')), len(s))

    def recv(self, fd):
        func = lib.apix_recv
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        buf = ctypes.create_string_buffer(1024)
        nr = func(self.ctx, fd, ctypes.cast(buf, ctypes.c_void_p), len(buf))
        return ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte * nr)).contents

    def send_to_buffer(self, fd, buf):
        func = lib.apix_send
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        assert(type(buf) == bytes)
        return func(self.ctx, fd, ctypes.cast(buf, ctypes.c_void_p), len(buf))

    def read_from_buffer(self, fd):
        func = lib.apix_read_from_buffer
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        buf = ctypes.create_string_buffer(1024)
        nr = func(self.ctx, fd, ctypes.cast(buf, ctypes.c_void_p), len(buf))
        return ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte * nr)).contents

    def waiting(self, usec):
        func = lib.apix_waiting
        func.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        func.restype = ctypes.c_int32
        return func(self.ctx, usec)

    def next_event(self, fd):
        func = lib.apix_next_event
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32]
        func.restype = ctypes.c_uint32
        return func(self.ctx, fd)

    def next_srrp_packet(self, fd):
        func = lib.apix_next_srrp_packet
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32]
        func.restype = ctypes.c_void_p
        return srrp.Srrp(func(self.ctx, fd), False)

    def upgrade_to_srrp(self, fd, nodeid):
        func = lib.apix_upgrade_to_srrp
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        return func(self.ctx, fd, nodeid)

    def srrp_forward(self, fd, pac):
        func = lib.apix_srrp_forward
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p]
        return func(self.ctx, fd, pac.pac)

    def srrp_send(self, fd, pac):
        func = lib.apix_srrp_send
        func.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p]
        func.restype = ctypes.c_int32
        return func(self.ctx, fd, pac.pac)

    def enable_posix(self):
        func = lib.apix_enable_posix
        func.argtypes = [ctypes.c_void_p]
        func(self.ctx)

    def disable_posix(self):
        func = lib.apix_disable_posix
        func.argtypes = [ctypes.c_void_p]
        func(self.ctx)

    def open(self, sinkid, addr):
        func = lib.apix_open
        func.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        func.restype = ctypes.c_int32
        return func(self.ctx, ctypes.c_char_p(sinkid.encode('utf-8')),
             ctypes.c_char_p(addr.encode('utf-8')))

    def open_unix_server(self, addr):
        return self.open("apisink_unix_s", addr)

    def open_unix_client(self, addr):
        return self.open("apisink_unix_c", addr)

    def open_tcp_server(self, addr):
        return self.open("apisink_tcp_s", addr)

    def open_tcp_client(self, addr):
        return self.open("apisink_tcp_c", addr)

    def open_com(self, addr):
        return self.open("apisink_com", addr)

    def open_can(self, addr):
        return self.open("apisink_can", addr)
