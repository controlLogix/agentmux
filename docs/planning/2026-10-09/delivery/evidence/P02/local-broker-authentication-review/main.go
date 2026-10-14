package main
import("bufio";"encoding/json";"fmt";"net";"os";"strings";"time";"github.com/nats-io/nats.go")
func main(){
 listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{os.Exit(2)};defer listener.Close()
 secret:=strings.Repeat("s",48)
 captured:=make(chan bool,1);done:=make(chan struct{})
 go func(){defer close(done);conn,e:=listener.Accept();if e!=nil{captured<-false;return};defer conn.Close();conn.SetDeadline(time.Now().Add(2*time.Second));fmt.Fprint(conn,"INFO {\"server_id\":\"fixture\",\"server_name\":\"fixture_server\",\"version\":\"2.15.0\",\"proto\":1,\"auth_required\":true,\"max_payload\":1048576}\r\n");reader:=bufio.NewReader(conn);received:=false
 for{line,e:=reader.ReadString('\n');if e!=nil{captured<-received;return};if strings.HasPrefix(line,"CONNECT "){var body map[string]any;json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line,"CONNECT "))),&body);received=body["pass"]==secret};if strings.TrimSpace(line)=="PING"{fmt.Fprint(conn,"PONG\r\n");captured<-received;return}}
 }()
 nc,e:=nats.Connect("nats://"+listener.Addr().String(),nats.UserInfo("runtime-client",secret),nats.NoReconnect(),nats.IgnoreDiscoveredServers(),nats.NoEcho(),nats.Timeout(time.Second))
 matched:=false;if e==nil{matched=nc.ConnectedServerName()=="fixture_server"&&nc.ConnectedServerVersion()=="2.15.0";nc.Close()}
 received:=<-captured;listener.Close();<-done
 json.NewEncoder(os.Stdout).Encode(map[string]any{"syntheticPasswordReceivedByImpersonator":received,"selfReportedIdentityChecksMatched":matched,"clientConnectSucceeded":e==nil,"realCredentialsUsed":false,"ownedSocketsJoined":true})
 if !received||!matched||e!=nil{os.Exit(3)}
}
