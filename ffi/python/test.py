import apix
import srrp

run_flag = 1

ctx = apix.Apix()
ctx.enable_posix()

fd = ctx.open_tcp_client("127.0.0.1:8080")
pac = srrp.SrrpCtrl(0x3333, "/sync", "")
ctx.send(fd, pac.raw())

while run_flag:
    ctx.poll(0)
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
