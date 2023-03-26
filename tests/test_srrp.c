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
    rxpac = srrp_parse(srrp_get_raw(txpac), srrp_get_packet_len(txpac));
    assert_true(rxpac);
    assert_true(srrp_get_packet_len(rxpac) == srrp_get_packet_len(txpac));
    assert_true(srrp_get_leader(rxpac) == SRRP_REQUEST_LEADER);
    assert_true(srrp_get_srcid(rxpac) == 0x3333);
    assert_true(srrp_get_dstid(rxpac) == 0x8888);
    assert_true(strcmp(srrp_get_anchor(rxpac), "/hello/x") == 0);
    uint16_t crc = srrp_get_crc16(rxpac);
    memcpy(buf, srrp_get_raw(txpac), srrp_get_packet_len(txpac));
    buf_idx = srrp_get_packet_len(txpac);
    srrp_free(txpac);
    srrp_free(rxpac);

    // 2
    txpac = srrp_new_response(
        0x8888, 0x3333, "/hello/x", "j:{err:0,errmsg:'succ',data:{msg:'world'}}", crc);
    rxpac = srrp_parse(srrp_get_raw(txpac), srrp_get_packet_len(txpac));
    assert_true(rxpac);
    assert_true(srrp_get_packet_len(rxpac) == srrp_get_packet_len(txpac));
    assert_true(srrp_get_leader(rxpac) == SRRP_RESPONSE_LEADER);
    assert_true(srrp_get_srcid(rxpac) == 0x8888);
    assert_true(srrp_get_dstid(rxpac) == 0x3333);
    assert_true(srrp_get_reqcrc16(rxpac) == crc);
    assert_true(strcmp(srrp_get_anchor(rxpac), "/hello/x") == 0);
    memcpy(buf + buf_idx, srrp_get_raw(txpac), srrp_get_packet_len(txpac));
    srrp_free(txpac);
    srrp_free(rxpac);

    // 3
    rxpac = srrp_parse(buf, sizeof(buf));
    assert_true(rxpac);
    assert_true(srrp_get_leader(rxpac) == SRRP_REQUEST_LEADER);
    assert_true(srrp_get_srcid(rxpac) == 0x3333);
    assert_true(srrp_get_dstid(rxpac) == 0x8888);
    assert_true(strcmp(srrp_get_anchor(rxpac), "/hello/x") == 0);
    int len = srrp_get_packet_len(rxpac);
    srrp_free(rxpac);

    rxpac = srrp_parse(buf + len, sizeof(buf) - len);
    assert_true(rxpac);
    assert_true(srrp_get_leader(rxpac) == SRRP_RESPONSE_LEADER);
    assert_true(srrp_get_srcid(rxpac) == 0x8888);
    assert_true(srrp_get_dstid(rxpac) == 0x3333);
    assert_true(srrp_get_reqcrc16(rxpac) == crc);
    assert_true(strcmp(srrp_get_anchor(rxpac), "/hello/x") == 0);
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

    pac = srrp_parse(srrp_get_raw(sub), srrp_get_packet_len(sub));
    assert_true(pac);
    assert_true(srrp_get_packet_len(pac) == srrp_get_packet_len(sub));
    assert_true(srrp_get_leader(pac) == SRRP_SUBSCRIBE_LEADER);
    assert_true(strcmp(srrp_get_anchor(pac), "/motor/speed") == 0);
    srrp_free(pac);

    pac = srrp_parse(srrp_get_raw(unsub), srrp_get_packet_len(unsub));
    assert_true(pac);
    assert_true(srrp_get_packet_len(pac) == srrp_get_packet_len(unsub));
    assert_true(srrp_get_leader(pac) == SRRP_UNSUBSCRIBE_LEADER);
    assert_true(strcmp(srrp_get_anchor(pac), "/motor/speed") == 0);
    srrp_free(pac);

    pac = srrp_parse(srrp_get_raw(pub), srrp_get_packet_len(pub));
    assert_true(pac);
    assert_true(srrp_get_packet_len(pac) == srrp_get_packet_len(pub));
    assert_true(srrp_get_leader(pac) == SRRP_PUBLISH_LEADER);
    assert_true(strcmp(srrp_get_anchor(pac), "/motor/speed") == 0);

    int buf_len = srrp_get_packet_len(sub) + srrp_get_packet_len(pub);
    uint8_t *buf = malloc(buf_len);
    memset(buf, 0, buf_len);
    memcpy(buf, srrp_get_raw(sub), srrp_get_packet_len(sub));
    memcpy(buf + srrp_get_packet_len(sub), srrp_get_raw(pub), srrp_get_packet_len(pub));
    srrp_free(pac);

    pac = srrp_parse(buf, buf_len);
    assert_true(pac);
    assert_true(srrp_get_packet_len(pac) == srrp_get_packet_len(sub));
    assert_true(srrp_get_leader(pac) == SRRP_SUBSCRIBE_LEADER);
    assert_true(strcmp(srrp_get_anchor(pac), "/motor/speed") == 0);
    int len = srrp_get_packet_len(pac);
    srrp_free(pac);

    pac = srrp_parse(buf + len, buf_len - len);
    assert_true(pac);
    assert_true(srrp_get_packet_len(pac) == srrp_get_packet_len(pub));
    assert_true(srrp_get_leader(pac) == SRRP_PUBLISH_LEADER);
    assert_true(strcmp(srrp_get_anchor(pac), "/motor/speed") == 0);
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
