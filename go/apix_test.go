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
    fd := ctx.OpenTcpClient("127.0.0.1:8080")

    pac, _ := srrp.NewCtrl(1111, "/online")
    ctx.Send(fd, pac.Payload)

    for true {
        ctx.Poll()

        buf := make([]byte, 256)
        nr := ctx.ReadFromBuffer(fd, buf)
        if nr > 0 {
            pac, err := srrp.Parse(buf)
            if err == nil {
                fmt.Println("recv srrp: " + string(pac.Payload))
            } else {
                fmt.Println("recv raw: " + string(buf))
            }
        }
    }

    ctx.Close(fd)
    ctx.Destroy()
}
