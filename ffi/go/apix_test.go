package apix_test
import "github.com/yonzkon/apix/go/apix"
import "github.com/yonzkon/apix/go/srrp"
import "github.com/yonzkon/apix/go/log"
import "testing"
import "fmt"

func TestBase(T *testing.T) {
    log.LogSetLevelDebug()

    ctx := apix.New()
    ctx.EnablePosix()
    ctx.SetWaitTimeout(0)
    stream := ctx.OpenUnixClient("/tmp/apix")

    pac, _ := srrp.NewCtrl(0xff00, "/sync", "")
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
            buf := make([]byte, 256)
            nr := stream.ReadFromBuffer( buf)
            if nr > 0 {
                pac, err := srrp.Parse(buf)
                if err == nil {
                    fmt.Println("recv srrp: " + string(pac.Raw))
                } else {
                    fmt.Println("recv raw: " + string(buf))
                }
            }
            break;
        default:
            break;
        }
    }

    stream.Close()
    ctx.Drop()
}
