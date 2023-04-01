/**
 * Currently struct Apix & Srrp in this file
 */

use std::io::Error;

pub enum LogLevel {
    None = 0,
    Trace,
    Debug,
    Info,
    Notice,
    Warn,
    Error,
    Fatal,
}

pub fn log_set_level(level: LogLevel) {
    unsafe {
        apix_sys::log_set_level(level as i32);
    }
}

pub enum ApixEvent {
    None = 0,
    Open,
    Close,
    Accept,
    Pollin,
    SrrpPacket,
}

pub struct ApixStream {
    pub stream: *mut apix_sys::stream,
    pub fd: i32,
}

impl ApixStream {
    pub fn close(&self) {
        unsafe {
            apix_sys::apix_close(self.stream);
        }
    }

    pub fn accept(&self) -> Result<ApixStream, Error> {
        unsafe {
            let new_stream = apix_sys::apix_accept(self.stream);
            if new_stream.is_null() {
                Err(Error::last_os_error())
            } else {
                Ok(ApixStream {
                    stream: new_stream,
                    fd: apix_sys::apix_get_raw_fd(new_stream),
                })
            }
        }
    }

    pub fn send(&self, buf: &[u8]) {
        unsafe {
            apix_sys::apix_send(
                self.stream, buf.as_ptr() as *const u8, buf.len() as u32);
        }
    }

    pub fn recv(&self, buf: &mut [u8]) {
        unsafe {
            apix_sys::apix_recv(
                self.stream, buf.as_ptr() as *mut u8, buf.len() as u32);
        }
    }

    pub fn send_to_buffer(&self, buf: &mut [u8]) {
        unsafe {
            apix_sys::apix_send_to_buffer(
                self.stream, buf.as_ptr() as *mut u8, buf.len() as u32);
        }
    }

    pub fn read_from_buffer(&self, buf: &mut [u8]) {
        unsafe {
            apix_sys::apix_read_from_buffer(
                self.stream, buf.as_ptr() as *mut u8, buf.len() as u32);
        }
    }

    pub fn wait_event(&self) -> u8 {
        unsafe {
            return apix_sys::apix_wait_event(self.stream);
        }
    }

    pub fn wait_srrp_packet(&self) -> Option<SrrpPacket> {
        unsafe {
            let pac = apix_sys::apix_wait_srrp_packet(self.stream);
            if pac.is_null() {
                None
            } else {
                Some(Srrp::from_raw_packet(pac))
            }
        }
    }

    pub fn upgrade_to_srrp(&self, nodeid: u32) {
        unsafe {
            apix_sys::apix_upgrade_to_srrp(self.stream, nodeid);
        }
    }

    pub fn srrp_forward(&self, pac: &SrrpPacket) {
        unsafe {
            apix_sys::apix_srrp_forward(self.stream, pac.pac);
        }
    }

    pub fn srrp_send(&self, pac: &SrrpPacket) {
        unsafe {
            apix_sys::apix_srrp_send(self.stream, pac.pac);
        }
    }
}

pub struct Apix {
    pub ctx: *mut apix_sys::apix,
}

impl Drop for Apix {
    fn drop(&mut self) {
        unsafe {
            apix_sys::apix_drop(self.ctx);
        }
    }
}

impl Apix {
    pub fn new() -> Result<Apix, Error> {
        unsafe {
            let ctx = apix_sys::apix_new();
            if ctx.is_null() {
                Err(Error::last_os_error())
            } else {
                Ok(Apix { ctx: ctx })
            }
        }
    }

    pub fn set_wait_timeout(&self, usec: u64) {
        unsafe {
            apix_sys::apix_set_wait_timeout(self.ctx, usec);
        }
    }

    pub fn wait_stream(&self) -> Option<ApixStream> {
        unsafe {
            let stream = apix_sys::apix_wait_stream(self.ctx);
            if stream.is_null() {
                None
            } else {
                Some(ApixStream {
                    stream: stream,
                    fd: apix_sys::apix_get_raw_fd(stream),
                })
            }
        }
    }

    pub fn enable_posix(&self) {
        unsafe {
            apix_sys::apix_enable_posix(self.ctx);
        }
    }

    pub fn disable_posix(&self) {
        unsafe {
            apix_sys::apix_disable_posix(self.ctx);
        }
    }

    fn open(&self, sinkid: &[u8], addr: &str) -> Result<ApixStream, Error> {
        unsafe {
            let addr = std::ffi::CString::new(addr).unwrap();
            let stream = apix_sys::apix_open(
                self.ctx, sinkid.as_ptr() as *const i8, addr.as_ptr());
            if stream.is_null() {
                Err(Error::last_os_error())
            } else {
                Ok(ApixStream {
                    stream: stream,
                    fd: apix_sys::apix_get_raw_fd(stream),
                })
            }
        }
    }

    pub fn open_unix_server(&self, addr: &str) -> Result<ApixStream, Error> {
        return self.open(apix_sys::SINK_UNIX_S, addr)
    }

    pub fn open_unix_client(&self, addr: &str) -> Result<ApixStream, Error> {
        return self.open(apix_sys::SINK_UNIX_C, addr)
    }

    pub fn open_tcp_server(&self, addr: &str) -> Result<ApixStream, Error> {
        return self.open(apix_sys::SINK_TCP_S, addr)
    }

    pub fn open_tcp_client(&self, addr: &str) -> Result<ApixStream, Error> {
        return self.open(apix_sys::SINK_TCP_C, addr)
    }

    pub fn open_com(&self, addr: &str) -> Result<ApixStream, Error> {
        return self.open(apix_sys::SINK_COM, addr)
    }

    pub fn open_can(&self, addr: &str) -> Result<ApixStream, Error> {
        return self.open(apix_sys::SINK_CAN, addr)
    }
}

pub struct SrrpPacket {
    pub leader: i8,
    pub fin: u8,
    pub ver: u16,
    pub packet_len: u16,
    pub payload_len: u32,
    pub srcid: u32,
    pub dstid: u32,
    pub anchor: String,
    pub payload: String,
    pub crc16: u16,
    pub raw: Vec<u8>,
    pub pac: *mut apix_sys::srrp_packet,
    pub owned: bool,
}

impl Drop for SrrpPacket {
    fn drop(&mut self) {
        unsafe {
            if self.owned {
                apix_sys::srrp_free(self.pac);
            }
        }
    }
}

pub struct Srrp {}

impl Srrp {
    fn from_raw_packet(pac: *mut apix_sys::srrp_packet) -> SrrpPacket {
        unsafe {
            let packet_len = apix_sys::srrp_get_packet_len(pac);
            let anchor = apix_sys::srrp_get_anchor(pac);
            let payload = apix_sys::srrp_get_payload(pac);
            let raw = apix_sys::srrp_get_raw(pac);
            SrrpPacket {
                leader: apix_sys::srrp_get_leader(pac),
                fin: apix_sys::srrp_get_fin(pac),
                ver: apix_sys::srrp_get_ver(pac),
                packet_len: packet_len,
                payload_len: apix_sys::srrp_get_payload_len(pac),
                srcid: apix_sys::srrp_get_srcid(pac),
                dstid: apix_sys::srrp_get_dstid(pac),
                anchor: std::ffi::CStr::from_ptr(anchor).to_str().unwrap().to_owned(),
                payload: match payload.is_null() {
                    true => String::from(""),
                    _ => std::ffi::CStr::from_ptr(payload as *const i8)
                        .to_str().unwrap().to_owned(),
                },
                crc16: apix_sys::srrp_get_crc16(pac),
                raw: {
                    let mut v: Vec<u8> = Vec::new();
                    for i in 0..packet_len {
                        v.push(*(raw).offset(i as isize));
                    }
                    v
                },
                pac: pac,
                owned: false,
            }
        }
    }

    pub fn next_packet_offset(buf: &[u8]) -> u32 {
        unsafe {
            apix_sys::srrp_next_packet_offset(
                buf.as_ptr() as *const u8, buf.len() as u32)
        }
    }

    pub fn parse(buf: &[u8]) -> Option<SrrpPacket> {
        unsafe {
            let pac = apix_sys::srrp_parse(buf.as_ptr() as *const u8, buf.len() as u32);
            if pac.is_null() {
                None
            } else {
                Some(Srrp::from_raw_packet(pac))
            }
        }
    }

    pub fn new(leader: char, fin: u8, srcid: u32, dstid: u32, anchor: &str, payload: &str)
               -> Option<SrrpPacket> {
        unsafe {
            let anchor = std::ffi::CString::new(anchor).unwrap();
            let pac = apix_sys::srrp_new(
                leader as i8, fin, srcid, dstid,
                anchor.as_ptr() as *const i8,
                payload.as_ptr() as *const u8,
                payload.len() as u32,
            );
            if pac.is_null() {
                None
            } else {
                let mut tmp = Srrp::from_raw_packet(pac);
                tmp.owned = true;
                Some(tmp)
            }
        }
    }

    pub fn new_ctrl(srcid: u32, anchor: &str, payload: &str) -> Option<SrrpPacket> {
        return Self::new('=', 1, srcid, 0, anchor, payload);
    }

    pub fn new_request(srcid: u32, dstid: u32, anchor: &str, payload: &str) -> Option<SrrpPacket> {
        return Self::new('>', 1, srcid, dstid, anchor, payload);
    }

    pub fn new_response(srcid: u32, dstid: u32, anchor: &str, payload: &str) -> Option<SrrpPacket> {
        return Self::new('<', 1, srcid, dstid, anchor, payload);
    }

    pub fn new_subscribe(anchor: &str, payload: &str) -> Option<SrrpPacket> {
        return Self::new('+', 1, 0, 0, anchor, payload);
    }

    pub fn new_unsubscribe(anchor: &str, payload: &str) -> Option<SrrpPacket> {
        return Self::new('-', 1, 0, 0, anchor, payload);
    }

    pub fn new_publish(anchor: &str, payload: &str) -> Option<SrrpPacket> {
        return Self::new('@', 1, 0, 0, anchor, payload);
    }
}
