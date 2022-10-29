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

int on_echo(struct srrp_packet *req, struct srrp_packet **resp)
{
    uint16_t crc = crc16(req->header, req->header_len);
    crc = crc16_crc(crc, req->data, req->data_len);
    *resp = srrp_new_response(req->srcid, crc, req->header, "{msg:'world'}");
    return 0;
}

static void test_svc(void **status)
{
    struct svchub *hub = svchub_new();
    svchub_add_service(hub, "/0007/echo", on_echo);

    struct srrp_packet *req, *resp = NULL;
    req = srrp_new_request(0x8888, "/0007/echo", "{msg:'hello'}");
    svchub_deal(hub, req, &resp);
    assert_true(strcmp(resp->data, "{msg:'world'}") == 0);
    srrp_free(req);
    if (resp) srrp_free(resp);

    svchub_del_service(hub, "/0007/echo");
    svchub_destroy(hub);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_svc),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
