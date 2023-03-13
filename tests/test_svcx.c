#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include "svcx.h"
#include "srrp.h"
#include "crc16.h"

typedef int (*srrp_request_handle_func_t)(
    struct srrp_packet *req, struct srrp_packet *resp);

int on_echo(struct srrp_packet *req, struct srrp_packet *resp, void *private_data)
{
    struct srrp_packet *tmp = srrp_new_response(
        req->dstid, req->srcid, sget(req->anchor), "t:{msg:'world'}", req->reqcrc16);
    srrp_move(tmp, resp);
    return 0;
}

static void test_svc(void **status)
{
    struct svcx *svcx = svcx_new();
    svcx_add_service(svcx, "8888:/echo", on_echo);

    struct srrp_packet *req = srrp_new_request(3333, 8888, "/echo", "{msg:'hello'}");
    struct srrp_packet *resp = srrp_new_response(0, 0, "", "", 0);
    ((srrp_request_handle_func_t)(svcx_get_service_private(svcx, "8888:/echo")))(req, resp);
    assert_true(strcmp((char *)resp->payload, "t:{msg:'world'}") == 0);
    srrp_free(req);
    if (resp) srrp_free(resp);

    svcx_del_service(svcx, "8888:/echo");
    svcx_destroy(svcx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_svc),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
