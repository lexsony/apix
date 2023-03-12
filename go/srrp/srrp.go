package srrp

// #include <apix/srrp.h>
import "C"
import "unsafe"
import "errors"

type SrrpPacket struct {
    Leader int8
    Seat int8
    Seqno uint16
    Len uint16
    Srcid uint16
    Dstid uint16
    Reqcrc16 uint16
    Crc16 uint16
    Header string
    Data string
    Payload []byte
}

type Srrp struct {}

func from_raw_packet(pac *C.struct_srrp_packet) (SrrpPacket) {
    if pac == nil {
        panic("raw point of srrp_packet is null")
    }
    return SrrpPacket {
        Leader: int8(pac.leader),
        Seat: int8(pac.seat),
        Seqno: uint16(pac.seqno),
        Len: uint16(pac.len),
        Srcid: uint16(pac.srcid),
        Dstid: uint16(pac.dstid),
        Reqcrc16: uint16(pac.reqcrc16),
        Crc16: uint16(pac.crc16),
        Header: C.GoString(pac.header),
        Data: C.GoString(pac.data),
        Payload: C.GoBytes(C.vraw(pac.payload), (C.int)(C.vsize(pac.payload))),
    }
}

func NextPacketOffset(buf []byte) (uint) {
    return uint(C.srrp_next_packet_offset(
        (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf))))
}

func Parse(buf []byte) (SrrpPacket, error) {
    pac := C.srrp_parse((*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf)))

    if pac == nil {
        return SrrpPacket {}, errors.New("srrp parse failed")
    } else {
        return from_raw_packet(pac), nil
    }
}

func NewCtrl(srcid uint16, header string) (SrrpPacket, error) {
    pac := C.srrp_new_ctrl(C.ushort(srcid), C.CString(header))

    if pac == nil {
        return SrrpPacket {}, errors.New("srrp parse failed")
    } else {
        return from_raw_packet(pac), nil
    }
}

func NewRequest(srcid uint16, dstid uint16,
    header string, data string) (SrrpPacket, error) {
    pac := C.srrp_new_request(C.ushort(srcid), C.ushort(dstid),
        C.CString(header), C.CString(data))

    if pac == nil {
        return SrrpPacket {}, errors.New("srrp parse failed")
    } else {
        return from_raw_packet(pac), nil
    }
}

func NewResponse(srcid uint16, dstid uint16, reqcrc16 uint16,
    header string, data string) (SrrpPacket, error) {
    pac := C.srrp_new_response(C.ushort(srcid), C.ushort(dstid),
        C.ushort(reqcrc16), C.CString(header), C.CString(data))

    if pac == nil {
        return SrrpPacket {}, errors.New("srrp parse failed")
    } else {
        return from_raw_packet(pac), nil
    }
}
