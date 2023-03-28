import apix
import srrp

run_flag = 1

ctx = apix.Apix()
ctx.enable_posix()

fd = ctx.open_unix_client("/tmp/apix")
pac = srrp.srrp_new_ctrl(0xff01, "/sync", "")
ctx.send(fd, pac.raw())

while run_flag:
    fd = ctx.waiting(10 * 1000)
    if fd == 0: continue

    match ctx.next_event(fd):
        case 1:
            print("open")
        case 2:
            print("close")
        case 3:
            print("accept")
        case 4:
            data = ctx.read_from_buffer(fd)
            if len(data):
                pac = srrp.srrp_parse(data)
                if pac.is_null():
                    print(data)
                    if data.decode('utf-8') == 'exit':
                        run_flag = 0
                else:
                    print(pac.raw())

ctx.close(fd)
