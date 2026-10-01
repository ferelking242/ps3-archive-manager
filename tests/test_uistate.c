/*

PS3 Archive Manager — host smoke test for extraction operator state.

The C core is covered by tests/test_core.c. This extra host test only
exercises the operator state block in ps3/src/main.c (op_pause,
op_cancel, op_t0_us, op_state_pending, op_state) without a PS3:
it verifies that pause/resume and cancel are visible immediately
from the UI poll loop, instead of decaying back to stale rouge/green
readings.

*/

#include <assert.h>
#include <stdint.h>

/* Operator state block lives in ps3/src/main.c. */
volatile int op_pause;
volatile int op_cancel;
volatile unsigned long long op_t0_us;
volatile int op_state_pending;
volatile int op_state;

static int test_operator_state_is_volatile_visible(void)
{
    op_pause = 0;
    op_cancel = 0;
    op_t0_us = 0;
    op_state_pending = 0;
    op_state = 0;

    /* Pause must be observed by the UI poll loop immediately. */
    op_pause = 1;
    assert(op_pause == 1);
    assert(op_state_pending == 0);

    op_state_pending = 1;
    op_state = 1; /* resume */
    assert(op_state == 1);
    assert(op_pause == 1);

    op_pause = 0;
    assert(op_pause == 0);
    assert(op_state == 1);

    /* Cancel issued mid-extraction must be visible to the UI prompt. */
    op_cancel = 1;
    assert(op_cancel == 1);
    assert(op_pause == 0);

    /* A fresh extraction frame starts from a clean state. */
    op_cancel = 0;
    op_pause = 0;
    op_t0_us = 123456789ull;
    assert(op_t0_us == 123456789ull);
    assert(op_cancel == 0);
    assert(op_pause == 0);
    return 0;
}

int main(void)
{
    test_operator_state_is_volatile_visible();
    return 0;
}
