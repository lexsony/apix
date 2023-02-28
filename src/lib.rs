use apix_sys as ffi;

pub struct Apix {
    pub ctx: *mut ffi::apix,
}

impl Apix {
    pub fn log_set_debug() {
        unsafe {
            ffi::log_set_level(ffi::LOG_LV_DEBUG as i32);
        }
    }

    pub fn new() -> Result<Apix, std::io::Error> {
        unsafe {
            let ctx = ffi::apix_new();
            if ctx.is_null() {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(Apix { ctx: ctx })
            }
        }
    }

    pub fn destroy(&self) {
        unsafe {
            ffi::apix_destroy(self.ctx);
        }
    }

    pub fn close(&self, fd: i32) {
        unsafe {
            ffi::apix_close(self.ctx, fd);
        }
    }

    pub fn send(&self, fd: i32, buf: &[u8]) {
        unsafe {
            ffi::apix_send(self.ctx, fd, buf.as_ptr() as *const std::ffi::c_void, buf.len() as u64);
        }
    }

    pub fn recv(&self, fd: i32, buf: &mut [u8]) {
        unsafe {
            ffi::apix_recv(self.ctx, fd, buf.as_ptr() as *mut std::ffi::c_void, buf.len() as u64);
        }
    }

    pub fn poll(&self) -> Result<(), std::io::Error> {
        unsafe {
            match ffi::apix_poll(self.ctx) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        }
    }

    pub fn on_fd_close(&self, fd: i32, func: unsafe extern "C" fn(i32)) {
        unsafe {
            ffi::apix_on_fd_close(self.ctx, fd, Some(func));
        }
    }

    pub fn on_fd_accept(&self, fd: i32, func: unsafe extern "C" fn(i32, i32)) {
        unsafe {
            ffi::apix_on_fd_accept(self.ctx, fd, Some(func));
        }
    }

    pub fn on_fd_pollin(&self, fd: i32, func: unsafe extern "C" fn(i32, *const i8, u64) -> i32) {
        unsafe {
            ffi::apix_on_fd_pollin(self.ctx, fd, Some(func));
        }
    }

    pub fn on_fd_pollout(&self, fd: i32, func: unsafe extern "C" fn(i32, *const i8, u64) -> i32) {
        unsafe {
            ffi::apix_on_fd_pollout(self.ctx, fd, Some(func));
        }
    }

    pub fn enable_srrp_mode(&self, fd: i32, nodeid: u32) {
        unsafe {
            ffi::apix_enable_srrp_mode(self.ctx, fd, nodeid);
        }
    }

    pub fn disable_srrp_mode(&self, fd: i32) {
        unsafe {
            ffi::apix_disable_srrp_mode(self.ctx, fd);
        }
    }

    pub fn on_srrp_request(&self, fd: i32, func: unsafe extern "C" fn(
        i32, *mut ffi::srrp_packet, *mut *mut ffi::srrp_packet)) {
        unsafe {
            ffi::apix_on_srrp_request(self.ctx, fd, Some(func));
        }
    }

    pub fn on_srrp_response(&self, fd: i32, func: unsafe extern "C" fn(
        i32, *mut ffi::srrp_packet)) {
        unsafe {
            ffi::apix_on_srrp_response(self.ctx, fd, Some(func));
        }
    }

    pub fn enable_posix(&self) {
        unsafe {
            ffi::apix_enable_posix(self.ctx);
        }
    }

    pub fn disable_posix(&self) {
        unsafe {
            ffi::apix_disable_posix(self.ctx);
        }
    }

    pub fn open_unix_server(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match ffi::apix_open(
                self.ctx, ffi::APISINK_UNIX_S.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }

    pub fn open_unix_client(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match ffi::apix_open(
                self.ctx, ffi::APISINK_UNIX_C.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }

    pub fn open_tcp_server(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match ffi::apix_open(
                self.ctx, ffi::APISINK_TCP_S.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }

    pub fn open_tcp_client(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match ffi::apix_open(
                self.ctx, ffi::APISINK_TCP_C.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }

    pub fn open_com(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match ffi::apix_open(
                self.ctx, ffi::APISINK_COM.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }

    pub fn open_can(&self, addr: &str) -> Result<i32, std::io::Error> {
        unsafe {
            let _addr = std::ffi::CString::new(addr).unwrap();
            match ffi::apix_open(
                self.ctx, ffi::APISINK_CAN.as_ptr() as *const i8, _addr.as_ptr()) {
                -1 => Err(std::io::Error::last_os_error()),
                fd => Ok(fd),
            }
        }
    }
}
