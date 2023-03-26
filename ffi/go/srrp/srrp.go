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
        Leader: int8(C.srrp_get_leader(pac)),
        PacketLen: uint16(C.srrp_get_packet_len(pac)),
        PayloadOffset: uint32(C.srrp_get_payload_offset(pac)),
        PayloadLen: uint32(C.srrp_get_payload_len(pac)),
        Srcid: uint32(C.srrp_get_srcid(pac)),
        Dstid: uint32(C.srrp_get_dstid(pac)),
        Anchor: C.GoString(C.srrp_get_anchor(pac)),
        Payload: C.GoString((*C.char)(unsafe.Pointer(C.srrp_get_payload(pac)))),
        Reqcrc16: uint16(C.srrp_get_reqcrc16(pac)),
        Crc16: uint16(C.srrp_get_crc16(pac)),
        Raw: C.GoBytes(unsafe.Pointer(C.srrp_get_raw(pac)),
            (C.int)(C.srrp_get_packet_len(pac))),
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
        ret := from_raw_packet(pac)
        C.srrp_free(pac)
        return ret, nil;
    }
}

func NewCtrl(srcid uint32, anchor string, payload string) (SrrpPacket, error) {
    pac := C.srrp_new_ctrl(C.uint(srcid), C.CString(anchor), C.CString(payload))

    if pac == nil {
        return SrrpPacket {}, errors.New("srrp parse failed")
    } else {
        ret := from_raw_packet(pac)
        C.srrp_free(pac)
        return ret, nil;
    }
}

func NewRequest(srcid uint32, dstid uint32,
    anchor string, payload string) (SrrpPacket, error) {
    pac := C.srrp_new_request(C.uint(srcid), C.uint(dstid),
        C.CString(anchor), C.CString(payload))

    if pac == nil {
        return SrrpPacket {}, errors.New("srrp parse failed")
    } else {
        ret := from_raw_packet(pac)
        C.srrp_free(pac)
        return ret, nil;
    }
}

func NewResponse(srcid uint32, dstid uint32,
        anchor string, payload string, reqcrc16 uint16) (SrrpPacket, error) {
    pac := C.srrp_new_response(C.uint(srcid), C.uint(dstid),
        C.CString(anchor), C.CString(payload), C.ushort(reqcrc16))

    if pac == nil {
        return SrrpPacket {}, errors.New("srrp parse failed")
    } else {
        ret := from_raw_packet(pac)
        C.srrp_free(pac)
        return ret, nil;
    }
}
