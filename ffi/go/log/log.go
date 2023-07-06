package log

// #include <apix/log.h>
import "C"

func LogSetLevelInfo() {
    C.log_set_level(C.LOG_LV_INFO)
}

func LogSetLevelDebug() {
    C.log_set_level(C.LOG_LV_DEBUG)
}

func LogSetLevelTrace() {
    C.log_set_level(C.LOG_LV_TRACE)
}
