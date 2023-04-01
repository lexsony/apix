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
    ctx.set_wait_timeout(10 * 1000);

    // server_unix init
    let server_unix = match ctx.open_unix_server("/tmp/apix") {
        Ok(x) => x,
        Err(e) => panic!("{}", e),
    };
    server_unix.upgrade_to_srrp(0x1);

    // server_tcp init
    let server_tcp = match ctx.open_tcp_server("127.0.0.1:3824") {
        Ok(x) => x,
        Err(e) => panic!("{}", e),
    };
    server_tcp.upgrade_to_srrp(0x2);

    // signal
    ctrlc::set_handler(move || {
        *EXIT_FLANG.lock().unwrap() = 1;
    }).expect("Error setting Ctrl-C handler");

    // main loop
    loop {
        if *EXIT_FLANG.lock().unwrap() == 1 {
            break;
        }

        let stream = ctx.wait_stream();
        match stream {
            Some(s) => {
                match s.wait_event() {
                    x if x == apix::ApixEvent::Open as u8 => {
                        info!("#{} open", s.fd);
                    },
                    x if x == apix::ApixEvent::Close as u8 => {
                        info!("#{} close", s.fd);
                    },
                    x if x == apix::ApixEvent::Accept as u8 => {
                        let new_stream = s.accept().unwrap();
                        info!("#{} accept", new_stream.fd);
                    },
                    x if x == apix::ApixEvent::Pollin as u8 => {
                        debug!("#{} pollin", s.fd);
                    },
                    x if x == apix::ApixEvent::SrrpPacket as u8 => {
                        let pac = s.wait_srrp_packet().unwrap();
                        if s.fd == server_unix.fd || s.fd == server_tcp.fd {
                            debug!("#{} srrp_packet: srcid:{}, dstid:{}, {}?{}",
                                s.fd, pac.srcid, pac.dstid, pac.anchor, pac.payload);
                            let resp = apix::Srrp::new_response(
                                pac.dstid, pac.srcid, &pac.anchor,
                                "j:{\"err\":404,\"msg\":\"Service not found\"}")
                                .unwrap();
                            debug!("#{} resp: srcid:{}, dstid:{}, {}?{}",
                                s.fd, resp.srcid, resp.dstid, resp.anchor, resp.payload);
                            s.srrp_send(&resp);
                        } else {
                            debug!("#{} srrp_packet: {}?{}", s.fd, pac.anchor, pac.payload);
                            s.srrp_forward(&pac)
                        }
                    },
                    _ => {}
                }
            }
            _ => (),
        }
    }

    server_unix.close();
    server_tcp.close();
}
