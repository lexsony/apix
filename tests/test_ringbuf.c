#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include "ringbuf.h"

static void test_ringbuf(void **status)
{
    ringbuf_t *buf = ringbuf_new(4096);
    assert_true(ringbuf_size(buf) == 4096);

    char *msg_hello = "hello world";
    size_t nr_hello = ringbuf_write(buf, msg_hello, strlen(msg_hello));
    assert_true(nr_hello == strlen(msg_hello));
    assert_true(ringbuf_used(buf) == strlen(msg_hello));
    assert_true(ringbuf_spare(buf) == ringbuf_size(buf) - strlen(msg_hello));

    char msg_large[1024 * 3] = {0};
    memset(msg_large, 0x7c, sizeof(msg_large));
    size_t nr_large = ringbuf_write(buf, msg_large, sizeof(msg_large));
    assert_true(nr_large == sizeof(msg_large));
    assert_true(ringbuf_used(buf) == nr_hello + sizeof(msg_large));
    assert_true(ringbuf_spare(buf) == ringbuf_size(buf) - nr_hello - nr_large);

    char buf_hello[256] = {0};
    size_t nr_read_hello = ringbuf_read(buf, buf_hello, nr_hello);
    assert_true(nr_read_hello == nr_hello);
    assert_true(strcmp(msg_hello, buf_hello) == 0);
    assert_true(ringbuf_used(buf) == sizeof(msg_large));
    assert_true(ringbuf_spare(buf) == ringbuf_size(buf) - nr_large);

    char buf_large[1024] = {0};
    size_t nr_read_large = ringbuf_read(buf, buf_large, sizeof(buf_large));
    assert_true(nr_read_large == sizeof(buf_large));
    assert_true(memcmp(buf_large, msg_large, sizeof(buf_large)) == 0);
    assert_true(ringbuf_used(buf) == sizeof(msg_large) - sizeof(buf_large));
    assert_true(ringbuf_spare(buf) == ringbuf_size(buf) - nr_large + sizeof(buf_large));

    char msg_last[1024] = {0};
    memset(msg_last, 0x3f, sizeof(msg_last));
    size_t nr_last = ringbuf_write(buf, msg_last, sizeof(msg_last));
    assert_true(nr_last == sizeof(msg_last));
    assert_true(ringbuf_used(buf) == sizeof(msg_large) -
                sizeof(buf_large) + sizeof(msg_last));
    assert_true(ringbuf_spare(buf) == ringbuf_size(buf) -
                nr_large + sizeof(buf_large) - sizeof(msg_last));

    char buf_last[4096] = {0};
    size_t nr_read_last = ringbuf_read(buf, buf_last, sizeof(buf_last));
    assert_true(nr_read_last == sizeof(msg_large) -
                sizeof(buf_large) + sizeof(msg_last));

    ringbuf_delete(buf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ringbuf),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
