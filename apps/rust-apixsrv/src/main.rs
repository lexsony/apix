use std::sync::Mutex;
use std::rc::Rc;
use log::{info, error};
use simple_logger;
use apix;
use ctrlc;

static RUN_FLAG: Mutex<i32> = Mutex::new(1);

fn init_fd(ctx: &Rc<apix::Apix>, fd: i32) {
    info!("open #{}", fd);
    ctx.on_fd_close(fd, move || {
        info!("close #{}", fd);
    });

    let tmp = Rc::clone(ctx);
    ctx.on_fd_accept(fd, move |newfd| {
        info!("accept #{} from {}", newfd, fd);
        tmp.on_fd_close(newfd, move || {
            info!("close #{}", newfd);
        });
        let tmp2 = Rc::clone(&tmp);
        tmp.on_srrp_packet(newfd, move |pac| {
            info!("srrp_packet #{}: {}?{}", newfd, pac.anchor, pac.payload);
            tmp2.srrp_forward(pac)
        })
    });

    let tmp = Rc::clone(ctx);
    ctx.on_srrp_packet(fd, move |pac| {
        info!("srrp_packet #{} pac: srcid:{}, dstid:{}, {}?{}",
              fd, pac.srcid, pac.dstid, pac.anchor, pac.payload);
        let resp = apix::Srrp::new_response(
            pac.dstid, pac.srcid, &pac.anchor,
            "j:{\"err\":404,\"msg\":\"Service not found\"}",
            pac.crc16).unwrap();
        info!("srrp_packet #{} resp: srcid:{}, dstid:{}, {}?{}",
              fd, resp.srcid, resp.dstid, resp.anchor, resp.payload);
        tmp.srrp_send(&resp);
    });
}

fn main() {
    simple_logger::SimpleLogger::new().env().init().unwrap();

    apix::Apix::log_set_debug();

    let ctx = Rc::new(apix::Apix::new().unwrap());
    ctx.enable_posix();

    // fd_unix init
    let fd_unix = match ctx.open_unix_server("/tmp/apix") {
        Ok(x) => x,
        Err(e) => panic!("{}", e),
    };
    ctx.enable_srrp_mode(fd_unix, 0x1);
    init_fd(&ctx, fd_unix);

    // fd_tcp init
    let fd_tcp = match ctx.open_tcp_server("127.0.0.1:3824") {
        Ok(x) => x,
        Err(e) => panic!("{}", e),
    };
    ctx.enable_srrp_mode(fd_tcp, 0x2);
    init_fd(&ctx, fd_tcp);

    // signal
    ctrlc::set_handler(move || {
        *RUN_FLAG.lock().unwrap() = 0;
    }).expect("Error setting Ctrl-C handler");

    // main loop
    while *RUN_FLAG.lock().unwrap() == 1 {
        if let Err(ref err) = ctx.poll(1 * 1000) {
            error!("Error: {}", err);
            *RUN_FLAG.lock().unwrap() = 0;
        }
    }

    ctx.close(fd_unix);
    ctx.close(fd_tcp);
}
