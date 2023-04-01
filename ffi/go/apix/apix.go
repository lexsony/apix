package apix

// #cgo CFLAGS:
// #cgo LDFLAGS: -lapix
// #include <apix/apix.h>
// #include <apix/srrp.h>
// #include <apix/log.h>
import "C"
import "unsafe"

const (
    EventNone uint = 0
    EventOpen uint = 1
    EventClose uint = 2
    EventAccept uint = 3
    EventPollin uint = 4
)

type ApixStream struct {
    stream *C.struct_stream
    fd int
}

func (self *ApixStream) IsNull() (bool) {
    if self.stream == nil {
        return true
    } else {
        return false
    }
}

func (self *ApixStream) Close() (int) {
    return int(C.apix_close(self.stream))
}

func (self *ApixStream) Accept() (ApixStream) {
    new_stream := C.apix_accept(self.stream)
    return ApixStream {
        stream: new_stream,
            fd: int(C.apix_raw_fd(new_stream)),
    }
}

func (self *ApixStream) Send(buf []byte) (int) {
    return int(C.apix_send(self.stream,
        (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf))))
}

func (self *ApixStream) Recv(buf []byte) (int) {
    return int(C.apix_recv(self.stream,
        (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf))))
}

func (self *ApixStream) SendToBuffer(buf []byte) (int) {
    return int(C.apix_send_to_buffer(self.stream,
        (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf))))
}

func (self *ApixStream) ReadFromBuffer(buf []byte) (int) {
    return int(C.apix_read_from_buffer(self.stream,
        (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf))))
}

func (self *ApixStream) NextEvent() (uint) {
    return uint(C.apix_next_event(self.stream))
}

type Apix struct {
    ctx *C.struct_apix
}

func New() (Apix) {
    return Apix{ ctx: C.apix_new() }
}

func (self *Apix) Drop() {
    C.apix_drop(self.ctx)
}

func (self *Apix) Waiting(usec uint64) (ApixStream) {
    stream := C.apix_waiting(self.ctx, C.ulong(usec))
    if stream == nil {
        return ApixStream{nil, -1}
    } else {
        return ApixStream{stream, int(C.apix_raw_fd(stream))}
    }
}

func (self *Apix) EnablePosix() {
    C.apix_enable_posix(self.ctx)
}

func (self *Apix) DisablePosix() {
    C.apix_disable_posix(self.ctx)
}

func (self *Apix) Open(sinkid string, addr string) (ApixStream) {
    stream := C.apix_open(self.ctx, C.CString(sinkid), C.CString(addr))
    return ApixStream {
        stream: stream,
            fd: int(C.apix_raw_fd(stream)),
    }
}

func (self *Apix) OpenUnixServer(addr string) (ApixStream) {
    return self.Open(C.SINK_UNIX_S, addr)
}

func (self *Apix) OpenUnixClient(addr string) (ApixStream) {
    return self.Open(C.SINK_UNIX_C, addr)
}

func (self *Apix) OpenTcpServer(addr string) (ApixStream) {
    return self.Open(C.SINK_TCP_S, addr)
}

func (self *Apix) OpenTcpClient(addr string) (ApixStream) {
    return self.Open(C.SINK_TCP_C, addr)
}

func (self *Apix) OpenCom(addr string) (ApixStream) {
    return self.Open(C.SINK_COM, addr)
}

func (self *Apix) OpenCan(addr string) (ApixStream) {
    return self.Open(C.SINK_CAN, addr)
}
