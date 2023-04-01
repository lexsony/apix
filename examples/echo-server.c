#include <stdio.h>
#include <stdlib.h>
#include <apix/apix.h>
#include <apix/srrp.h>

int main(int argc, char *argv[])
{
    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    apix_set_wait_timeout(ctx, 100 * 1000);

    struct stream *stream = apix_open_tcp_server(ctx, "127.0.0.1:8888");
    if (!stream) {
        perror("open tcp as 127.0.0.1:8888 failed");
        exit(-1);
    }

    apix_upgrade_to_srrp(stream, 0x10086);

    for (;;) {
        struct stream *stream = apix_wait_stream(ctx);
        if (!stream) continue;

        switch (apix_wait_event(stream)) {
        case AEC_OPEN:
            printf("#%d open\n", apix_get_raw_fd(stream));
            break;
        case AEC_CLOSE:
            printf("#%d close\n", apix_get_raw_fd(stream));
            break;
        case AEC_ACCEPT: {
            struct stream *new_stream = apix_accept(stream);
            printf("#%d accept #%d", apix_get_raw_fd(stream), apix_get_raw_fd(new_stream));
            break;
        }
        case AEC_SRRP_PACKET: {
            struct srrp_packet *pac = apix_wait_srrp_packet(stream);
            if (srrp_get_leader(pac) == SRRP_REQUEST_LEADER) {
                struct srrp_packet *resp = srrp_new_response(
                    srrp_get_dstid(pac),
                    srrp_get_srcid(pac),
                    srrp_get_anchor(pac),
                    (const char *)srrp_get_payload(pac));
                apix_srrp_send(stream, resp);
                srrp_free(resp);
            }
            printf("#%d forward packet: %s", apix_get_raw_fd(stream), srrp_get_raw(pac));
            break;
        }
        default:
            break;
        }
    }

    apix_close(stream);
    apix_drop(ctx); // auto close all fds
    return 0;
}
