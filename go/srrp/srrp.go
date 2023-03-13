package srrp

// #include <apix/srrp.h>
import "C"
import "unsafe"
import "errors"

type SrrpPacket struct {
    Leader int8
    PacketLen uint16
    PayloadOffset uint32
    PayloadLen uint32
    Srcid uint32
    Dstid uint32
    Anchor string
    Payload string
    Reqcrc16 uint16
    Crc16 uint16
    Raw []byte
}

type Srrp struct {}

func from_raw_packet(pac *C.struct_srrp_packet) (SrrpPacket) {
    if pac == nil {
        panic("raw point of srrp_packet is null")
    }

    return SrrpPacket {
        Leader: int8(pac.leader),
        PacketLen: uint16(pac.packet_len),
        PayloadOffset: uint32(pac.payload_offset),
        PayloadLen: uint32(pac.payload_len),
        Srcid: uint32(pac.srcid),
        Dstid: uint32(pac.dstid),
        Anchor: C.GoString(C.sget(pac.anchor)),
        Payload: C.GoString((*C.char)(unsafe.Pointer(pac.payload))),
        Reqcrc16: uint16(pac.reqcrc16),
        Crc16: uint16(pac.crc16),
        Raw: C.GoBytes(C.vraw(pac.raw), (C.int)(C.vsize(pac.raw))),
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

func NewCtrl(srcid uint32, anchor string, payload string) (SrrpPacket, error) {
    pac := C.srrp_new_ctrl(C.uint(srcid), C.CString(anchor), C.CString(payload))

    if pac == nil {
        return SrrpPacket {}, errors.New("srrp parse failed")
    } else {
        return from_raw_packet(pac), nil
    }
}

func NewRequest(srcid uint32, dstid uint32,
    anchor string, payload string) (SrrpPacket, error) {
    pac := C.srrp_new_request(C.uint(srcid), C.uint(dstid),
        C.CString(anchor), C.CString(payload))

    if pac == nil {
        return SrrpPacket {}, errors.New("srrp parse failed")
    } else {
        return from_raw_packet(pac), nil
    }
}

func NewResponse(srcid uint32, dstid uint32,
        anchor string, payload string, reqcrc16 uint16) (SrrpPacket, error) {
    pac := C.srrp_new_response(C.uint(srcid), C.uint(dstid),
        C.CString(anchor), C.CString(payload), C.ushort(reqcrc16))

    if pac == nil {
        return SrrpPacket {}, errors.New("srrp parse failed")
    } else {
        return from_raw_packet(pac), nil
    }
}
