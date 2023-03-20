/**
 * Currently struct Apix & Srrp in this file
 */

pub struct Apix {
    pub ctx: *mut apix_sys::apix,
}

impl Apix {
    pub fn log_set_debug() {
        unsafe {
            apix_sys::log_set_level(apix_sys::LOG_LV_DEBUG as i32);
        }
    }

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

    pub fn destroy(&self) {
        unsafe {
            apix_sys::apix_destroy(self.ctx);
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

    pub fn read_from_buffer(&self, fd: i32, buf: &mut [u8]) {
        unsafe {
            apix_sys::apix_read_from_buffer(
                self.ctx, fd, buf.as_ptr() as *mut u8, buf.len() as u32);
        }
    }

    pub fn poll(&self, usec: u64) -> Result<(), std::io::Error> {
        unsafe {
            match apix_sys::apix_poll(self.ctx, usec) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        }
    }

    extern "C" fn __on_fd_close(_: *mut apix_sys::apix, _: i32,
                                priv_data: *mut std::ffi::c_void) {
        let closure: &mut Box<dyn FnMut()> = unsafe {
            std::mem::transmute(priv_data)
        };
        closure();
    }

    pub fn on_fd_close<F>(&self, fd: i32, func: F)
    where F: FnMut(),
          F: 'static
    {
        let obj: Box<Box<dyn FnMut()>> = Box::new(Box::new(func));
        unsafe {
            apix_sys::apix_on_fd_close(
                self.ctx, fd, Some(Apix::__on_fd_close),
                Box::into_raw(obj) as *mut std::ffi::c_void);
        }
    }

    extern "C" fn __on_fd_accept(_: *mut apix_sys::apix, _: i32, newfd: i32,
                                 priv_data: *mut std::ffi::c_void) {
        let closure: &mut Box<dyn FnMut(i32)> = unsafe {
            std::mem::transmute(priv_data)
        };
        closure(newfd);
    }

    pub fn on_fd_accept<F>(&self, fd: i32, func: F)
    where F: FnMut(i32),
          F: 'static
    {
        let obj: Box<Box<dyn FnMut(i32)>> = Box::new(Box::new(func));
        unsafe {
            apix_sys::apix_on_fd_accept(
                self.ctx, fd, Some(Apix::__on_fd_accept),
                Box::into_raw(obj) as *mut std::ffi::c_void);
        }
    }

    extern "C" fn __on_fd_pollin(
        _: *mut apix_sys::apix, _: i32,
        buf: *const u8, len: u32, priv_data: *mut std::ffi::c_void) -> i32 {
        let closure: &mut Box<dyn FnMut(&[u8]) -> i32> = unsafe {
            std::mem::transmute(priv_data)
        };
        unsafe {
            closure(std::slice::from_raw_parts(buf as *const u8, len as usize))
        }
    }

    pub fn on_fd_pollin<F>(&self, fd: i32, func: F)
        where F: FnMut(&[u8]) -> i32,
              F: 'static
    {
        let obj: Box<Box<dyn FnMut(&[u8]) -> i32>> = Box::new(Box::new(func));
        unsafe {
            apix_sys::apix_on_fd_pollin(
                self.ctx, fd, Some(Apix::__on_fd_pollin),
                Box::into_raw(obj) as *mut std::ffi::c_void);
        }
    }

    pub fn enable_srrp_mode(&self, fd: i32, nodeid: u32) {
        unsafe {
            apix_sys::apix_enable_srrp_mode(self.ctx, fd, nodeid);
        }
    }

    pub fn disable_srrp_mode(&self, fd: i32) {
        unsafe {
            apix_sys::apix_disable_srrp_mode(self.ctx, fd);
        }
    }

    pub fn srrp_online(&self, fd: i32) {
        unsafe {
            apix_sys::apix_srrp_online(self.ctx, fd);
        }
    }

    pub fn srrp_offline(&self, fd: i32) {
        unsafe {
            apix_sys::apix_srrp_offline(self.ctx, fd);
        }
    }

    extern "C" fn __on_srrp_request(
        _: *mut apix_sys::apix, _: i32,
        req: *mut apix_sys::srrp_packet,
        resp: *mut apix_sys::srrp_packet,
        priv_data: *mut std::ffi::c_void) {
        let closure: &mut Box<dyn FnMut(&SrrpPacket) -> Option<SrrpPacket>> = unsafe {
            std::mem::transmute(priv_data)
        };
        let new_req = Srrp::from_raw_packet(req);
        match closure(&new_req) {
            Some(new_resp) => {
                unsafe {
                    let anchor = std::ffi::CString::new(new_resp.anchor).unwrap();
                    let payload = std::ffi::CString::new(new_resp.payload).unwrap();
                    let tmp = apix_sys::srrp_new_response(
                        new_resp.srcid,
                        new_resp.dstid,
                        anchor.as_ptr() as *const i8,
                        payload.as_ptr() as *const i8,
                        new_resp.reqcrc16,
                    );
                    apix_sys::srrp_move(tmp, resp);
                }
                true
            },
            None => false
        };
    }

    pub fn on_srrp_request<F>(&self, fd: i32, func: F)
    where F: FnMut(&SrrpPacket) -> Option<SrrpPacket>,
          F: 'static
    {
        let obj: Box<Box<dyn FnMut(&SrrpPacket) -> Option<SrrpPacket>>> =
            Box::new(Box::new(func));
        unsafe {
            apix_sys::apix_on_srrp_request(
                self.ctx, fd, Some(Apix::__on_srrp_request),
                Box::into_raw(obj) as *mut std::ffi::c_void);
        }
    }

    extern "C" fn __on_srrp_response(
        _: *mut apix_sys::apix, _: i32,
        resp: *mut apix_sys::srrp_packet,
        priv_data: *mut std::ffi::c_void) {
        let closure: &mut Box<dyn FnMut(&SrrpPacket)> = unsafe {
            std::mem::transmute(priv_data)
        };
        let resp = Srrp::from_raw_packet(resp);
        closure(&resp);
    }

    pub fn on_srrp_response<F>(&self, fd: i32, func: F)
    where F: FnMut(&SrrpPacket)
    {
        let obj: Box<Box<dyn FnMut(&SrrpPacket)>> = Box::new(Box::new(func));
        unsafe {
            apix_sys::apix_on_srrp_response(self.ctx, fd, Some(Apix::__on_srrp_response),
                                            Box::into_raw(obj) as *mut std::ffi::c_void);
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

#[derive(Default)]
pub struct SrrpPacket {
    pub leader: i8,
    pub packet_len: u16,
    pub payload_offset: u32,
    pub payload_len: u32,
    pub srcid: u32,
    pub dstid: u32,
    pub anchor: String,
    pub payload: String,
    pub reqcrc16: u16,
    pub crc16: u16,
    pub raw: Vec<u8>,
}

pub struct Srrp {}

impl Srrp {
    fn from_raw_packet(pac: *const apix_sys::srrp_packet) -> SrrpPacket {
        unsafe {
            let packet_len = apix_sys::srrp_get_packet_len(pac);
            let anchor = apix_sys::srrp_get_anchor(pac);
            let payload = apix_sys::srrp_get_payload(pac);
            let raw = apix_sys::srrp_get_raw(pac);
            SrrpPacket {
                leader: apix_sys::srrp_get_leader(pac),
                packet_len: packet_len,
                payload_offset: apix_sys::srrp_get_payload_offset(pac),
                payload_len: apix_sys::srrp_get_payload_len(pac),
                srcid: apix_sys::srrp_get_srcid(pac),
                dstid: apix_sys::srrp_get_dstid(pac),
                anchor: std::ffi::CStr::from_ptr(anchor).to_str().unwrap().to_owned(),
                payload: match payload.is_null() {
                    true => String::from(""),
                    _ => std::ffi::CStr::from_ptr(payload as *const i8)
                        .to_str().unwrap().to_owned(),
                },
                reqcrc16: apix_sys::srrp_get_reqcrc16(pac),
                crc16: apix_sys::srrp_get_crc16(pac),
                raw: {
                    let mut v: Vec<u8> = Vec::new();
                    for i in 0..packet_len {
                        v.push(*(raw).offset(i as isize));
                    }
                    v
                }
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
                let sp = Srrp::from_raw_packet(pac);
                apix_sys::srrp_free(pac);
                Some(sp)
            }
        }
    }

    pub fn new_ctrl(srcid: u32, anchor: &str, payload: &str) -> Option<SrrpPacket> {
        unsafe {
            let anchor = std::ffi::CString::new(anchor).unwrap();
            let pac = apix_sys::srrp_new_ctrl(
                srcid, anchor.as_ptr() as *const i8, payload.as_ptr() as *const i8);
            if pac.is_null() {
                None
            } else {
                let sp = Srrp::from_raw_packet(pac);
                apix_sys::srrp_free(pac);
                Some(sp)
            }
        }
    }

    pub fn new_request(srcid: u32, dstid: u32,
                       anchor: &str, payload: &str) -> Option<SrrpPacket> {
        unsafe {
            let anchor = std::ffi::CString::new(anchor).unwrap();
            let payload = std::ffi::CString::new(payload).unwrap();
            let pac = apix_sys::srrp_new_request(
                srcid, dstid,
                anchor.as_ptr() as *const i8,
                payload.as_ptr() as *const i8);
            if pac.is_null() {
                None
            } else {
                let sp = Srrp::from_raw_packet(pac);
                apix_sys::srrp_free(pac);
                Some(sp)
            }
        }
    }

    pub fn new_response(srcid: u32, dstid: u32, anchor: &str, payload: &str,
                        reqcrc16: u16) -> Option<SrrpPacket> {
        unsafe {
            let anchor = std::ffi::CString::new(anchor).unwrap();
            let payload = std::ffi::CString::new(payload).unwrap();
            let pac = apix_sys::srrp_new_response(
                srcid, dstid,
                anchor.as_ptr() as *const i8,
                payload.as_ptr() as *const i8,
                reqcrc16,
            );
            if pac.is_null() {
                None
            } else {
                let sp = Srrp::from_raw_packet(pac);
                apix_sys::srrp_free(pac);
                Some(sp)
            }
        }
    }
}
