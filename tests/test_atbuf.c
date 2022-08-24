#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include "atbuf.h"

static void test_atbuf(void **status)
{
    atbuf_t *buf;
    char msg[1024];
    size_t nread;
    char hello_msg[] = "hello buffer";
    int write_time = ATBUF_DEFAULT_SIZE / sizeof(hello_msg) / 3 * 2;
    int read_time = write_time / 2;

    buf = atbuf_new(ATBUF_DEFAULT_SIZE);
    assert_true(atbuf_size(buf) == ATBUF_DEFAULT_SIZE);
    assert_true(atbuf_garbage(buf) == 0);
    assert_true(atbuf_used(buf) == 0);
    assert_true(atbuf_spare(buf) == ATBUF_DEFAULT_SIZE);

    for (int i = 0; i < write_time; i++)
        atbuf_write(buf, (void*)hello_msg, sizeof(hello_msg));
    assert_true(atbuf_size(buf) == ATBUF_DEFAULT_SIZE);
    assert_true(atbuf_garbage(buf) == 0);
    assert_true(atbuf_used(buf) == sizeof(hello_msg)*write_time);
    assert_true(atbuf_spare(buf) == ATBUF_DEFAULT_SIZE - sizeof(hello_msg)*write_time);

    for (int i = 0; i < read_time; i++)
        nread = atbuf_read(buf, msg, sizeof(hello_msg));
    assert_true(atbuf_size(buf) == ATBUF_DEFAULT_SIZE);
    //assert_true(atbuf_garbage(buf) == sizeof(hello_msg)*read_time);
    assert_true(atbuf_used(buf) == sizeof(hello_msg)*(write_time-read_time));
    //assert_true(atbuf_spare(buf) == ATBUF_DEFAULT_SIZE - sizeof(hello_msg)*write_time);
    assert_true(memcmp(hello_msg, msg, strlen(hello_msg)) == 0);
    msg[nread] = 0;

    assert_true(atbuf_size(buf) == ATBUF_DEFAULT_SIZE);
    //assert_true(atbuf_garbage(buf) == 0);
    assert_true(atbuf_used(buf) == sizeof(hello_msg)*(write_time-read_time));
    //assert_true(atbuf_spare(buf) == ATBUF_DEFAULT_SIZE - sizeof(hello_msg)*(write_time-read_time));

    atbuf_delete(buf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_atbuf),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
