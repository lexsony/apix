import ctypes
from ctypes.util import find_library

lib = ctypes.CDLL(find_library("apix"))

def log_set_debug():
    func = lib.log_set_level
    func.argtypes = [ctypes.c_int32]
    func(1)

class Apix():
    def __init__(self):
        func = lib.apix_new
        func.restype = ctypes.c_void_p
        self.ctx = func()

    def __del__(self):
        func = lib.apix_destroy
        func.argtypes = [ctypes.c_void_p]
        func(self.ctx)

    def close(self, fd):
        func = lib.apix_close
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

    def poll(self, usec):
        func = lib.apix_poll
        func.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        func.restype = ctypes.c_int32
        return func(self.ctx, usec)

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
