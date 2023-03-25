package log

// #include <apix/log.h>
import "C"

func LogSetLevelDebug() {
    C.log_set_level(C.LOG_LV_DEBUG)
}
