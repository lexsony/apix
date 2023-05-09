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

class ApixStream():
    def __init__(self, stream):
        self.stream = stream
        self.fd = self.__raw_fd() if stream is not None else -1

    def __raw_fd(self):
        func = lib.apix_get_raw_fd
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_int32
        return func(self.stream)

    def is_null(self):
        if self.stream == None:
            return True
        else:
            return False

    def close(self):
        func = lib.apix_close
        func.argtypes = [ctypes.c_void_p]
        func(self.stream)

    def accept(self):
        func = lib.apix_accept
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_void_p
        return ApixStream(func(self.stream))

    def send(self, buf):
        func = lib.apix_send
        func.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        assert(type(buf) == bytes)
        return func(self.stream, ctypes.cast(buf, ctypes.c_void_p), len(buf))

    def send_str(self, s):
        func = lib.apix_send
        func.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        assert(type(s) == str)
        return func(self.stream, ctypes.c_char_p(s.encode('utf-8')), len(s))

    def recv(self):
        func = lib.apix_recv
        func.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        buf = ctypes.create_string_buffer(1024)
        nr = func(self.stream, ctypes.cast(buf, ctypes.c_void_p), len(buf))
        return ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte * nr)).contents

    def send_to_buffer(self, buf):
        func = lib.apix_send
        func.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        assert(type(buf) == bytes)
        return func(self.stream, ctypes.cast(buf, ctypes.c_void_p), len(buf))

    def read_from_buffer(self):
        func = lib.apix_read_from_buffer
        func.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        func.restype = ctypes.c_int32
        buf = ctypes.create_string_buffer(1024)
        nr = func(self.stream, ctypes.cast(buf, ctypes.c_void_p), len(buf))
        return ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte * nr)).contents

    def wait_event(self):
        func = lib.apix_wait_event
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_uint32
        return func(self.stream)

    def wait_srrp_packet(self):
        func = lib.apix_wait_srrp_packet
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_void_p
        return srrp.Srrp(func(self.stream), False)

    def upgrade_to_srrp(self, nodeid):
        func = lib.apix_upgrade_to_srrp
        func.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        func.restype = ctypes.c_int32
        return func(self.stream, ctypes.cast(nodeid, ctypes.c_char_p))

    def srrp_forward(self, pac):
        func = lib.apix_srrp_forward
        func.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        return func(self.stream, pac.pac)

    def srrp_send(self, pac):
        func = lib.apix_srrp_send
        func.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        func.restype = ctypes.c_int32
        return func(self.stream, pac.pac)

class Apix():
    def __init__(self):
        func = lib.apix_new
        func.restype = ctypes.c_void_p
        self.ctx = func()

    def __del__(self):
        func = lib.apix_drop
        func.argtypes = [ctypes.c_void_p]
        func(self.ctx)

    def set_wait_timeout(self, usec):
        func = lib.apix_set_wait_timeout
        func.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        func(self.ctx, usec)

    def wait_stream(self):
        func = lib.apix_wait_stream
        func.argtypes = [ctypes.c_void_p]
        func.restype = ctypes.c_void_p
        return ApixStream(func(self.ctx))

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
        func.restype = ctypes.c_void_p
        return ApixStream(func(self.ctx, ctypes.c_char_p(sinkid.encode('utf-8')),
             ctypes.c_char_p(addr.encode('utf-8'))))

    def open_unix_server(self, addr):
        return self.open("sink_unix_s", addr)

    def open_unix_client(self, addr):
        return self.open("sink_unix_c", addr)

    def open_tcp_server(self, addr):
        return self.open("sink_tcp_s", addr)

    def open_tcp_client(self, addr):
        return self.open("sink_tcp_c", addr)

    def open_com(self, addr):
        return self.open("sink_com", addr)

    def open_can(self, addr):
        return self.open("sink_can", addr)
