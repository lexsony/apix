use std::sync::Mutex;
use log::{info, debug};
use simple_logger;
use apix;
use ctrlc;
use clap::Parser;

static EXIT_FLANG: Mutex<i32> = Mutex::new(0);

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,
}

fn main() {
    // parse args
    let args = Args::parse();
    match args.debug {
        0 => {
            std::env::set_var("RUST_LOG", "info");
            apix::log_set_level(apix::LogLevel::Info);
            println!("Debug mode is off");
        }
        1 => {
            std::env::set_var("RUST_LOG", "debug");
            apix::log_set_level(apix::LogLevel::Debug);
            println!("Debug mode is on");
        }
        2 => {
            std::env::set_var("RUST_LOG", "trace");
            apix::log_set_level(apix::LogLevel::Trace);
            println!("Trace mode is on");
        }
        _ => println!("Don't be crazy"),
    }

    // logger init
    simple_logger::SimpleLogger::new().env().init().unwrap();

    // apix init
    let ctx = apix::Apix::new().unwrap();
    ctx.enable_posix();

    // fd_unix init
    let fd_unix = match ctx.open_unix_server("/tmp/apix") {
        Ok(x) => x,
        Err(e) => panic!("{}", e),
    };
    ctx.upgrade_to_srrp(fd_unix, 0x1);

    // fd_tcp init
    let fd_tcp = match ctx.open_tcp_server("127.0.0.1:3824") {
        Ok(x) => x,
        Err(e) => panic!("{}", e),
    };
    ctx.upgrade_to_srrp(fd_tcp, 0x2);

    // signal
    ctrlc::set_handler(move || {
        *EXIT_FLANG.lock().unwrap() = 1;
    }).expect("Error setting Ctrl-C handler");

    // main loop
    loop {
        if *EXIT_FLANG.lock().unwrap() == 1 {
            break;
        }

        let fd = ctx.waiting(10 * 1000);
        if fd == 0 {
            continue;
        }

        match ctx.next_event(fd) {
            x if x == apix::ApixEvent::Open as u8 => {
                info!("#{} open", fd);
            },
            x if x == apix::ApixEvent::Close as u8 => {
                info!("#{} close", fd);
            },
            x if x == apix::ApixEvent::Accept as u8 => {
                ctx.accept(fd);
                info!("#{} accept", fd);
            },
            x if x == apix::ApixEvent::Pollin as u8 => {
                debug!("#{} pollin", fd);
            },
            x if x == apix::ApixEvent::SrrpPacket as u8 => {
                let pac = ctx.next_srrp_packet(fd).unwrap();
                if fd == fd_unix || fd == fd_tcp {
                    debug!("#{} srrp_packet: srcid:{}, dstid:{}, {}?{}",
                          fd, pac.srcid, pac.dstid, pac.anchor, pac.payload);
                    let resp = apix::Srrp::new_response(
                        pac.dstid, pac.srcid, &pac.anchor,
                        "j:{\"err\":404,\"msg\":\"Service not found\"}")
                        .unwrap();
                    debug!("#{} resp: srcid:{}, dstid:{}, {}?{}",
                          fd, resp.srcid, resp.dstid, resp.anchor, resp.payload);
                    ctx.srrp_send(fd, &resp);
                } else {
                    debug!("#{} srrp_packet: {}?{}", fd, pac.anchor, pac.payload);
                    ctx.srrp_forward(fd, &pac)
                }
            },
            _ => {}
        }
    }

    ctx.close(fd_unix);
    ctx.close(fd_tcp);
}
