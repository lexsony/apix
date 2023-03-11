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
                self.ctx, fd, buf.as_ptr() as *const std::ffi::c_void, buf.len() as u64);
        }
    }

    pub fn recv(&self, fd: i32, buf: &mut [u8]) {
        unsafe {
            apix_sys::apix_recv(
                self.ctx, fd, buf.as_ptr() as *mut std::ffi::c_void, buf.len() as u64);
        }
    }

    pub fn poll(&self) -> Result<(), std::io::Error> {
        unsafe {
            match apix_sys::apix_poll(self.ctx) {
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
            apix_sys::apix_on_fd_close(self.ctx, fd, Some(Apix::__on_fd_close),
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
            apix_sys::apix_on_fd_accept(self.ctx, fd, Some(Apix::__on_fd_accept),
                                        Box::into_raw(obj) as *mut std::ffi::c_void);
        }
    }

    extern "C" fn __on_fd_pollin(
        _: *mut apix_sys::apix, _: i32,
        buf: *const std::ffi::c_void, len: u64,
        priv_data: *mut std::ffi::c_void) -> i32 {
        let closure: &mut Box<dyn FnMut(&[u8]) -> i32> = unsafe {
            std::mem::transmute(priv_data)
        };
        unsafe {
            return closure(std::slice::from_raw_parts(buf as *const u8, len as usize));
        }
    }

    pub fn on_fd_pollin<F>(&self, fd: i32, func: F)
        where F: FnMut(&[u8]) -> i32,
              F: 'static
    {
        let obj: Box<Box<dyn FnMut(&[u8]) -> i32>> = Box::new(Box::new(func));
        unsafe {
            apix_sys::apix_on_fd_pollin(self.ctx, fd, Some(Apix::__on_fd_pollin),
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
        let closure: &mut Box<dyn FnMut(&SrrpPacket) -> SrrpPacket> = unsafe {
            std::mem::transmute(priv_data)
        };
        let new_req = Srrp::from_raw_packet(req);
        let new_resp = closure(&new_req);
        unsafe {
            let tmp = apix_sys::srrp_new_response(
                new_resp.srcid,
                new_resp.dstid,
                new_resp.reqcrc16,
                new_resp.header.as_ptr() as *const i8,
                new_resp.data.as_ptr() as *const i8,
            );
            apix_sys::srrp_move(tmp, resp);
        }
    }

    pub fn on_srrp_request<F>(&self, fd: i32, func: F)
    where F: FnMut(&SrrpPacket) -> SrrpPacket,
          F: 'static
    {
        let obj: Box<Box<dyn FnMut(&SrrpPacket) -> SrrpPacket>> = Box::new(Box::new(func));
        unsafe {
            apix_sys::apix_on_srrp_request(self.ctx, fd, Some(Apix::__on_srrp_request),
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

pub struct SrrpPacket {
    pub leader: i8,
    pub seat: i8,
    pub seqno: u16,
    pub len: u16,
    pub srcid: u16,
    pub dstid: u16,
    pub reqcrc16: u16,
    pub crc16: u16,
    pub header: String,
    pub header_len: u32,
    pub data: String,
    pub data_len: u32,
    pub payload: Vec<u8>,
}

pub struct Srrp {
}

impl Srrp {
    pub fn from_raw_packet(pac: *const apix_sys::srrp_packet) -> SrrpPacket {
        unsafe {
            return SrrpPacket {
                leader: (*pac).leader,
                seat: (*pac).seat,
                seqno: (*pac).seqno,
                len: (*pac).len,
                srcid: (*pac).srcid,
                dstid: (*pac).dstid,
                reqcrc16: (*pac).reqcrc16,
                crc16: (*pac).crc16,
                header: std::ffi::CStr::from_ptr((*pac).header).to_str().unwrap().to_owned(),
                header_len: (*pac).header_len,
                data: match (*pac).data.is_null() {
                    true => String::from(""),
                    _ => std::ffi::CStr::from_ptr((*pac).data).to_str().unwrap().to_owned(),
                },
                data_len: (*pac).data_len,
                payload: {
                    let mut v: Vec<u8> = Vec::new();
                    for i in 0..(*pac).len {
                        v.push(*(apix_sys::vraw((*pac).payload)).offset(i as isize) as u8);
                    }
                    v
                }
            };
        }
    }

    pub fn new_ctrl(srcid: u16, header: &str) -> SrrpPacket {
        unsafe {
            let header = std::ffi::CString::new(header).unwrap();
            let pac = apix_sys::srrp_new_ctrl(srcid, header.as_ptr() as *const i8);
            let sp = Srrp::from_raw_packet(pac);
            apix_sys::srrp_free(pac);
            return sp;
        }
    }

    pub fn new_request(srcid: u16, dstid: u16, header: &str, data: &str) -> SrrpPacket {
        unsafe {
            let header = std::ffi::CString::new(header).unwrap();
            let data = std::ffi::CString::new(data).unwrap();
            let pac = apix_sys::srrp_new_request(
                srcid, dstid,
                header.as_ptr() as *const i8,
                data.as_ptr() as *const i8);
            let sp = Srrp::from_raw_packet(pac);
            apix_sys::srrp_free(pac);
            return sp;
        }
    }

    pub fn new_response(srcid: u16, dstid: u16, reqcrc16: u16,
                        header: &str, data: &str) -> SrrpPacket {
        unsafe {
            let header = std::ffi::CString::new(header).unwrap();
            let data = std::ffi::CString::new(data).unwrap();
            let pac = apix_sys::srrp_new_response(
                srcid, dstid, reqcrc16,
                header.as_ptr() as *const i8,
                data.as_ptr() as *const i8);
            let sp = Srrp::from_raw_packet(pac);
            apix_sys::srrp_free(pac);
            return sp;
        }
    }
}
