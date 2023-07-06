package apix_test
import "github.com/yonzkon/apix/ffi/go/apix"
import "github.com/yonzkon/apix/ffi/go/srrp"
import "github.com/yonzkon/apix/ffi/go/log"
import "testing"
import "fmt"

func TestBase(T *testing.T) {
    log.LogSetLevelDebug()

    ctx := apix.New()
    ctx.EnablePosix()
    ctx.SetWaitTimeout(0)
    stream := ctx.OpenUnixClient("/tmp/srrp")
    stream.UpgradeToSrrp("testid")

    pac, _ := srrp.NewCtrl("testid", "/sync", "")
    stream.Send(pac.Raw)

    pac, _ = srrp.NewRequest("testid", "test_dstid", "/hello", "{}")
    stream.Send(pac.Raw)

    for true {
        switch stream.WaitEvent() {
        case apix.EventOpen:
            fmt.Println("open")
            break;
        case apix.EventClose:
            fmt.Println("close")
            break;
        case apix.EventAccept:
            fmt.Println("never enter accept")
            break;
        case apix.EventPollin:
            pac, err := stream.WaitSrrpPacket();
            if err == nil {
                fmt.Println("recv srrp: " + string(pac.Raw))
            } else {
                //fmt.Println(err)
            }

            //buf := make([]byte, 256)
            //nr := stream.ReadFromBuffer( buf)
            //if nr > 0 {
            //    pac, err := srrp.Parse(buf)
            //    if err == nil {
            //        fmt.Println("recv srrp: " + string(pac.Raw))
            //    } else {
            //        fmt.Println("recv raw: " + string(buf))
            //    }
            //}
            break;
        default:
            break;
        }
    }

    stream.Close()
    ctx.Drop()
}
