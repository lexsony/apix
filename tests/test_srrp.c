#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>
#include "srrp.h"
#include "crc16.h"

#define UNIX_ADDR "test_apisink_unix"

static void test_srrp_request_reponse(void **status)
{
    struct srrp_packet *txpac = NULL;
    struct srrp_packet *rxpac = NULL;
    char buf[1024] = {0};
    size_t buf_idx = 0;

    // 1
    txpac = srrp_new_request(0x3333, 0x8888, "/hello/x",
                             "j:{name:'yon',age:'18',equip:['hat','shoes']}");
    assert_true(txpac);
    rxpac = srrp_parse(vraw(txpac->payload));
    assert_true(rxpac);
    assert_true(rxpac->len == txpac->len);
    assert_true(rxpac->leader == '>');
    assert_true(rxpac->seat == '$');
    assert_true(rxpac->srcid == 0x3333);
    assert_true(rxpac->dstid == 0x8888);
    assert_true(memcmp(rxpac->header, "/hello/x", rxpac->header_len) == 0);
    uint16_t crc = rxpac->crc16;
    memcpy(buf, vraw(txpac->payload), txpac->len);
    buf_idx = txpac->len;
    srrp_free(txpac);
    srrp_free(rxpac);

    // 2
    txpac = srrp_new_response(
        0x8888, 0x3333, crc, "/hello/x", "j:{err:0,errmsg:'succ',data:{msg:'world'}}");
    rxpac = srrp_parse(vraw(txpac->payload));
    assert_true(rxpac);
    assert_true(rxpac->len == txpac->len);
    assert_true(rxpac->leader == '<');
    assert_true(rxpac->seat == '$');
    assert_true(rxpac->srcid == 0x8888);
    assert_true(rxpac->dstid == 0x3333);
    assert_true(rxpac->reqcrc16 == crc);
    assert_true(memcmp(rxpac->header, "/hello/x", rxpac->header_len) == 0);
    memcpy(buf + buf_idx, vraw(txpac->payload), txpac->len);
    srrp_free(txpac);
    srrp_free(rxpac);

    // 3
    rxpac = srrp_parse(buf);
    assert_true(rxpac);
    assert_true(rxpac->leader == '>');
    assert_true(rxpac->seat == '$');
    assert_true(rxpac->srcid == 0x3333);
    assert_true(rxpac->dstid == 0x8888);
    assert_true(memcmp(rxpac->header, "/hello/x", rxpac->header_len) == 0);
    int len = rxpac->len;
    srrp_free(rxpac);

    rxpac = srrp_parse(buf + len);
    assert_true(rxpac);
    assert_true(rxpac->leader == '<');
    assert_true(rxpac->seat == '$');
    assert_true(rxpac->srcid == 0x8888);
    assert_true(rxpac->dstid == 0x3333);
    assert_true(rxpac->reqcrc16 == crc);
    assert_true(memcmp(rxpac->header, "/hello/x", rxpac->header_len) == 0);
    srrp_free(rxpac);
}

static void test_srrp_subscribe_publish(void **status)
{
    struct srrp_packet *sub = NULL;
    struct srrp_packet *unsub = NULL;
    struct srrp_packet *pub = NULL;
    struct srrp_packet *pac = NULL;

    sub = srrp_new_subscribe("/motor/speed", "j:{ack:0,cache:100}");
    unsub = srrp_new_unsubscribe("/motor/speed", "j:{}");
    pub = srrp_new_publish("/motor/speed", "j:{speed:12,voltage:24}");
    assert_true(sub);
    assert_true(unsub);
    assert_true(pub);

    pac = srrp_parse(vraw(sub->payload));
    assert_true(pac);
    assert_true(pac->len == sub->len);
    assert_true(pac->leader == '#');
    assert_true(pac->seat == '$');
    assert_true(memcmp(pac->header, "/motor/speed", pac->header_len) == 0);
    srrp_free(pac);

    pac = srrp_parse(vraw(unsub->payload));
    assert_true(pac);
    assert_true(pac->len == unsub->len);
    assert_true(pac->leader == '%');
    assert_true(pac->seat == '$');
    assert_true(memcmp(pac->header, "/motor/speed", pac->header_len) == 0);
    srrp_free(pac);

    pac = srrp_parse(vraw(pub->payload));
    assert_true(pac);
    assert_true(pac->len == pub->len);
    assert_true(pac->leader == '@');
    assert_true(pac->seat == '$');
    assert_true(memcmp(pac->header, "/motor/speed", pac->header_len) == 0);

    int buf_len = sub->len + pub->len;
    char *buf = malloc(buf_len);
    memset(buf, 0, buf_len);
    memcpy(buf, vraw(sub->payload), sub->len);
    memcpy(buf + sub->len, vraw(pub->payload), pub->len);
    srrp_free(pac);

    pac = srrp_parse(buf);
    assert_true(pac);
    assert_true(pac->len == sub->len);
    assert_true(pac->leader == '#');
    assert_true(pac->seat == '$');
    assert_true(memcmp(pac->header, "/motor/speed", pac->header_len) == 0);
    int len = pac->len;
    srrp_free(pac);

    pac = srrp_parse(buf + len);
    assert_true(pac);
    assert_true(pac->len == pub->len);
    assert_true(pac->leader == '@');
    assert_true(pac->seat == '$');
    assert_true(memcmp(pac->header, "/motor/speed", pac->header_len) == 0);
    srrp_free(pac);
    free(buf);

    srrp_free(sub);
    srrp_free(unsub);
    srrp_free(pub);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_srrp_request_reponse),
        cmocka_unit_test(test_srrp_subscribe_publish),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
