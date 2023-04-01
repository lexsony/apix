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

type Apix struct {
    ctx *C.struct_apix
}

func New() (Apix) {
    ctx := C.apix_new()
    return Apix{ctx: ctx}
}

func (self *Apix) Drop() {
    C.apix_drop(self.ctx)
}

func (self *Apix) Close(fd int) (int) {
    return int(C.apix_close(self.ctx, C.int(fd)))
}

func (self *Apix) Accept(fd int) (int) {
    return int(C.apix_accept(self.ctx, C.int(fd)))
}

func (self *Apix) Send(fd int, buf []byte) (int) {
    return int(C.apix_send(self.ctx, C.int(fd),
        (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf))))
}

func (self *Apix) Recv(fd int, buf []byte) (int) {
    return int(C.apix_recv(self.ctx, C.int(fd),
        (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf))))
}

func (self *Apix) SendToBuffer(fd int, buf []byte) (int) {
    return int(C.apix_send_to_buffer(self.ctx, C.int(fd),
        (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf))))
}

func (self *Apix) ReadFromBuffer(fd int, buf []byte) (int) {
    return int(C.apix_read_from_buffer(self.ctx, C.int(fd),
        (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf))))
}

func (self *Apix) Waiting(usec uint64) (int) {
    return int(C.apix_waiting(self.ctx, C.ulong(usec)))
}

func (self *Apix) NextEvent(fd int) (uint) {
    return uint(C.apix_next_event(self.ctx, C.int(fd)))
}

func (self *Apix) EnablePosix() {
    C.apix_enable_posix(self.ctx)
}

func (self *Apix) DisablePosix() {
    C.apix_disable_posix(self.ctx)
}

func (self *Apix) OpenUnixServer(addr string) (int) {
    return int(C.apix_open(self.ctx, C.CString(C.APISINK_UNIX_S), C.CString(addr)))
}

func (self *Apix) OpenUnixClient(addr string) (int) {
    return int(C.apix_open(self.ctx, C.CString(C.APISINK_UNIX_C), C.CString(addr)))
}

func (self *Apix) OpenTcpServer(addr string) (int) {
    return int(C.apix_open(self.ctx, C.CString(C.APISINK_TCP_S), C.CString(addr)))
}

func (self *Apix) OpenTcpClient(addr string) (int) {
    return int(C.apix_open(self.ctx, C.CString(C.APISINK_TCP_C), C.CString(addr)))
}

func (self *Apix) OpenCom(addr string) (int) {
    return int(C.apix_open(self.ctx, C.CString(C.APISINK_COM), C.CString(addr)))
}

func (self *Apix) OpenCan(addr string) (int) {
    return int(C.apix_open(self.ctx, C.CString(C.APISINK_CAN), C.CString(addr)))
}
