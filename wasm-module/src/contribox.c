# include "emscripten.h"
# include "contribox.h"

EMSCRIPTEN_KEEPALIVE
int init() {
    uint32_t flag = 0;
    if (wally_init(flag) != 0) {
        return -1;
    }
    return 0;
}
