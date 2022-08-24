#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include "json.h"

static void test_json(void **status)
{
    struct json_object *jo = json_object_new(
        "{header: '/hello/x', test: {len: 12, name: 'yon'}}");

    int value_int = 0;
    assert_true(json_get_int(jo, "/test/len", &value_int) == 0);
    assert_true(value_int == 12);

    char value_str[256];
    assert_true(json_get_string(jo, "/header", value_str, sizeof(value_str)) == 0);
    assert_string_equal(value_str, "/hello/x");
    assert_true(json_get_string(jo, "/test/name", value_str, sizeof(value_str)) == 0);
    assert_string_equal(value_str, "yon");

    json_object_delete(jo);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_json),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
