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

    pub fn close(&self, fd: i32) {
        unsafe {
            ffi::apix_close(self.ctx, fd);
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

    pub fn poll(&self) -> Result<(), std::io::Error> {
        unsafe {
            match ffi::apix_poll(self.ctx) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        }
    }
}
