/**
 * Currently struct Apix & Srrp in this file
 */

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
    pub fn new() -> Result<Apix, std::io::Error> {
        unsafe {
            let ctx = apix_sys::apix_new();
            if ctx.is_null() {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(Apix { ctx: ctx })
            }
        }
    }

    pub fn close(&self, fd: i32) {
        unsafe {
            apix_sys::apix_close(self.ctx, fd);
        }
    }

    pub fn send(&self, fd: i32, buf: &[u8]) {
        unsafe {
            apix_sys::apix_send(
                self.ctx, fd, buf.as_ptr() as *const u8, buf.len() as u32);
        }
    }

    pub fn recv(&self, fd: i32, buf: &mut [u8]) {
        unsafe {
            apix_sys::apix_recv(
                self.ctx, fd, buf.as_ptr() as *mut u8, buf.len() as u32);
        }
    }

    pub fn send_to_buffer(&self, fd: i32, buf: &mut [u8]) {
        unsafe {
            apix_sys::apix_send_to_buffer(
                self.ctx, fd, buf.as_ptr() as *mut u8, buf.len() as u32);
        }
    }

    pub fn read_from_buffer(&self, fd: i32, buf: &mut [u8]) {
        unsafe {
            apix_sys::apix_read_from_buffer(
                self.ctx, fd, buf.as_ptr() as *mut u8, buf.len() as u32);
        }
    }

    pub fn waiting(&self, usec: u64) -> i32 {
        unsafe {
            return apix_sys::apix_waiting(self.ctx, usec);
        }
    }

    pub fn next_event(&self, fd: i32) -> u8 {
        unsafe {
            return apix_sys::apix_next_event(self.ctx, fd);
        }
    }

    pub fn next_srrp_packet(&self, fd: i32) -> Option<SrrpPacket> {
        unsafe {
            let pac = apix_sys::apix_next_srrp_packet(self.ctx, fd);
            if pac.is_null() {
                None
            } else {
                Some(Srrp::from_raw_packet(pac))
            }
        }
    }

    pub fn upgrade_to_srrp(&self, fd: i32, nodeid: u32) {
        unsafe {
            apix_sys::apix_upgrade_to_srrp(self.ctx, fd, nodeid);
        }
    }

    pub fn srrp_forward(&self, fd: i32, pac: &SrrpPacket) {
        unsafe {
            apix_sys::apix_srrp_forward(self.ctx, fd, pac.pac);
        }
    }

    pub fn srrp_send(&self, fd: i32, pac: &SrrpPacket) {
        unsafe {
            apix_sys::apix_srrp_send(self.ctx, fd, pac.pac);
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

    pub fn open_unix_server(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match apix_sys::apix_open(
                self.ctx, apix_sys::APISINK_UNIX_S.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }

    pub fn open_unix_client(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match apix_sys::apix_open(
                self.ctx, apix_sys::APISINK_UNIX_C.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }

    pub fn open_tcp_server(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match apix_sys::apix_open(
                self.ctx, apix_sys::APISINK_TCP_S.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }

    pub fn open_tcp_client(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match apix_sys::apix_open(
                self.ctx, apix_sys::APISINK_TCP_C.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }

    pub fn open_com(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match apix_sys::apix_open(
                self.ctx, apix_sys::APISINK_COM.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }

    pub fn open_can(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match apix_sys::apix_open(
                self.ctx, apix_sys::APISINK_CAN.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
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
