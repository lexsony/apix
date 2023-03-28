use std::sync::Mutex;
use log::{debug, info};
use simple_logger;
use apix;
use json;
use ctrlc;
use std::net::TcpListener;
use std::thread::spawn;
use tungstenite::accept;
use tungstenite::{Message};

static EXIT_FLAG: Mutex<i32> = Mutex::new(0);

fn main() {
    // log init
    simple_logger::SimpleLogger::new().env().init().unwrap();
    apix::log_set_level(apix::LogLevel::Info);

    // signal init
    ctrlc::set_handler(move || {
        *EXIT_FLAG.lock().unwrap() = 1;
    }).expect("Error setting Ctrl-C handler");

    // apix ctx & websocket init
    let server = TcpListener::bind("0.0.0.0:3825").unwrap();
    for stream in server.incoming() {
        spawn (move || {
            let mut ws = accept(stream.unwrap()).unwrap();

            let ctx = apix::Apix::new().unwrap();
            ctx.enable_posix();
            let fd = match ctx.open_tcp_client("127.0.0.1:3824") {
                Ok(x) => x,
                Err(e) => panic!("{}", e),
            };
            ctx.upgrade_to_srrp(fd, 0x2222);

            loop {
                if *EXIT_FLAG.lock().unwrap() == 1 {
                    break;
                }

                // apix
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
                        info!("#{} accept", fd);
                    },
                    x if x == apix::ApixEvent::Pollin as u8 => {
                        debug!("#{} pollin", fd);
                    },
                    x if x == apix::ApixEvent::SrrpPacket as u8 => {
                        let pac = ctx.next_srrp_packet(fd).unwrap();
                        debug!("recv srrp packet #{}: {}", fd, std::str::from_utf8(&pac.raw).unwrap());
                        if pac.leader == '<' as i8 || pac.leader == '@' as i8 {
                            ws.write_message(Message::text(&pac.payload[2..])).unwrap();
                        }
                    },
                    _ => {}
                }

                // websocket
                let msg = ws.read_message().unwrap();

                // We do not want to send back ping/pong messages.
                if msg.is_binary() || msg.is_text() {
                    debug!("recv websocket packet: {}", msg);
                    if let Ok(jdata) = json::parse(&msg.into_text().unwrap()) {
                        let req = apix::Srrp::new_request(
                            0x2222,
                            jdata["dstid"].as_u32().unwrap(),
                            jdata["anchor"].as_str().unwrap(),
                            &format!("j:{}", jdata["payload"].as_str().unwrap()));
                        ctx.srrp_send(fd, &req.unwrap());
                    }
                }
            }

            ctx.close(fd);
        });
    }
}
