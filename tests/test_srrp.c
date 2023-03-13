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
    uint8_t buf[1024] = {0};
    uint32_t buf_idx = 0;

    // 1
    txpac = srrp_new_request(0x3333, 0x8888, "/hello/x",
                             "j:{name:'yon',age:'18',equip:['hat','shoes']}");
    assert_true(txpac);
    rxpac = srrp_parse(vraw(txpac->raw), vsize(txpac->raw));
    assert_true(rxpac);
    assert_true(rxpac->packet_len == txpac->packet_len);
    assert_true(rxpac->leader == '>');
    assert_true(rxpac->srcid == 0x3333);
    assert_true(rxpac->dstid == 0x8888);
    assert_true(strcmp(sget(rxpac->anchor), "/hello/x") == 0);
    uint16_t crc = rxpac->crc16;
    memcpy(buf, vraw(txpac->raw), txpac->packet_len);
    buf_idx = txpac->packet_len;
    srrp_free(txpac);
    srrp_free(rxpac);

    // 2
    txpac = srrp_new_response(
        0x8888, 0x3333, "/hello/x", "j:{err:0,errmsg:'succ',data:{msg:'world'}}", crc);
    rxpac = srrp_parse(vraw(txpac->raw), vsize(txpac->raw));
    assert_true(rxpac);
    assert_true(rxpac->packet_len == txpac->packet_len);
    assert_true(rxpac->leader == '<');
    assert_true(rxpac->srcid == 0x8888);
    assert_true(rxpac->dstid == 0x3333);
    assert_true(rxpac->reqcrc16 == crc);
    assert_true(strcmp(sget(rxpac->anchor), "/hello/x") == 0);
    memcpy(buf + buf_idx, vraw(txpac->raw), txpac->packet_len);
    srrp_free(txpac);
    srrp_free(rxpac);

    // 3
    rxpac = srrp_parse(buf, sizeof(buf));
    assert_true(rxpac);
    assert_true(rxpac->leader == '>');
    assert_true(rxpac->srcid == 0x3333);
    assert_true(rxpac->dstid == 0x8888);
    assert_true(strcmp(sget(rxpac->anchor), "/hello/x") == 0);
    int len = rxpac->packet_len;
    srrp_free(rxpac);

    rxpac = srrp_parse(buf + len, sizeof(buf) - len);
    assert_true(rxpac);
    assert_true(rxpac->leader == '<');
    assert_true(rxpac->srcid == 0x8888);
    assert_true(rxpac->dstid == 0x3333);
    assert_true(rxpac->reqcrc16 == crc);
    assert_true(strcmp(sget(rxpac->anchor), "/hello/x") == 0);
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

    pac = srrp_parse(vraw(sub->raw), vsize(sub->raw));
    assert_true(pac);
    assert_true(pac->packet_len == sub->packet_len);
    assert_true(pac->leader == '#');
    assert_true(strcmp(sget(pac->anchor), "/motor/speed") == 0);
    srrp_free(pac);

    pac = srrp_parse(vraw(unsub->raw), vsize(unsub->raw));
    assert_true(pac);
    assert_true(pac->packet_len == unsub->packet_len);
    assert_true(pac->leader == '%');
    assert_true(strcmp(sget(pac->anchor), "/motor/speed") == 0);
    srrp_free(pac);

    pac = srrp_parse(vraw(pub->raw), vsize(pub->raw));
    assert_true(pac);
    assert_true(pac->packet_len == pub->packet_len);
    assert_true(pac->leader == '@');
    assert_true(strcmp(sget(pac->anchor), "/motor/speed") == 0);

    int buf_len = sub->packet_len + pub->packet_len;
    uint8_t *buf = malloc(buf_len);
    memset(buf, 0, buf_len);
    memcpy(buf, vraw(sub->raw), sub->packet_len);
    memcpy(buf + sub->packet_len, vraw(pub->raw), pub->packet_len);
    srrp_free(pac);

    pac = srrp_parse(buf, buf_len);
    assert_true(pac);
    assert_true(pac->packet_len == sub->packet_len);
    assert_true(pac->leader == '#');
    assert_true(strcmp(sget(pac->anchor), "/motor/speed") == 0);
    int len = pac->packet_len;
    srrp_free(pac);

    pac = srrp_parse(buf + len, buf_len - len);
    assert_true(pac);
    assert_true(pac->packet_len == pub->packet_len);
    assert_true(pac->leader == '@');
    assert_true(strcmp(sget(pac->anchor), "/motor/speed") == 0);
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
