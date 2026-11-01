// Node Manager Agent: an outbound-only, restricted VPS control plane.
// Uses stdlib only. No listening sockets, no arbitrary shell and no SSH.
package main

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "runtime"
    "path/filepath"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "os"
    "os/exec"
    "strconv"
    "strings"
    "sync/atomic"
    "syscall"
    "time"
)

const Version = "1.5.0"
const MaxBody = 160000
const Helper = "/usr/local/libexec/node-manager-helper"

type Task struct {
    ID string `json:"id"`
    Action string `json:"action"`
    Payload map[string]interface{} `json:"payload"`
}
type Pull struct {
    Job *Task `json:"job"`
}
type HeartbeatReply struct {
    NextHeartbeatMS int64 `json:"next_heartbeat_ms"`
}
type Response struct {
    ID string `json:"id"`
    OK bool `json:"ok"`
    Result map[string]interface{} `json:"result"`
    Error string `json:"error,omitempty"`
}
type Agent struct {
    Client *http.Client
    URL string
    ID string
    Token string
}

func (a *Agent) send(ctx context.Context, method, route string, request interface{}, out interface{}) error {
    var raw []byte
    var err error
    if request != nil {
        raw,err = json.Marshal(request)
        if err != nil{return err}
        if len(raw)>MaxBody{return errors.New("oversized request")}
    }
    req,err:=http.NewRequestWithContext(ctx,method,a.URL+route,bytes.NewReader(raw))
    if err!=nil{return err}
    req.Header.Set("Authorization","Bearer "+a.Token)
    req.Header.Set("X-Node-Id",a.ID)
    req.Header.Set("User-Agent","node-manager-agent/"+Version)
    if request!=nil {req.Header.Set("Content-Type","application/json")}
    resp,err:=a.Client.Do(req)
    if err!=nil{return err}
    defer resp.Body.Close()
    if resp.StatusCode!=200 {return fmt.Errorf("manager HTTP %d",resp.StatusCode)}
    if out==nil{return nil}
    return json.NewDecoder(io.LimitReader(resp.Body,MaxBody)).Decode(out)
}

// Read lightweight kernel counters. These are cumulative, not Mbps samples.
// Use the default-route interface to avoid counting docker/veth traffic twice.
var lastNetSample struct {
    iface string
    rx uint64
    tx uint64
    when time.Time
}

func addNetworkCounters(status map[string]interface{}) {
    iface:=""
    if raw,err:=os.ReadFile("/proc/net/route");err==nil{
        for _,line:=range strings.Split(string(raw),"\n")[1:]{
            fields:=strings.Fields(line)
            if len(fields)>2 && fields[1]=="00000000" {
                iface=fields[0]
                break
            }
        }
    }
    if iface!=""{
        if raw,err:=os.ReadFile("/proc/net/dev");err==nil{
            for _,line:=range strings.Split(string(raw),"\n"){
                parts:=strings.SplitN(line,":",2)
                if len(parts)!=2 || strings.TrimSpace(parts[0])!=iface{continue}
                nums:=strings.Fields(parts[1])
                if len(nums)>=16 {
                    status["net_interface"]=iface
                    rx,rxErr:=strconv.ParseUint(nums[0],10,64)
                    tx,txErr:=strconv.ParseUint(nums[8],10,64)
                    now:=time.Now()
                    if rxErr==nil && txErr==nil {
                        elapsed:=now.Sub(lastNetSample.when).Seconds()
                        if lastNetSample.iface==iface && elapsed>0.20 && rx>=lastNetSample.rx && tx>=lastNetSample.tx {
                            status["net_rx_mbps"]=float64(rx-lastNetSample.rx)*8/elapsed/1000000
                            status["net_tx_mbps"]=float64(tx-lastNetSample.tx)*8/elapsed/1000000
                        }
                        lastNetSample.iface=iface
                        lastNetSample.rx=rx
                        lastNetSample.tx=tx
                        lastNetSample.when=now
                    }
                    for key,index:=range map[string]int{
                        "net_rx_bytes":0,"net_rx_dropped":3,
                        "net_tx_bytes":8,"net_tx_dropped":11}{
                        if n,e:=strconv.ParseUint(nums[index],10,64);e==nil{status[key]=n}
                    }
                }
                break
            }
        }
    }
    if raw,err:=os.ReadFile("/proc/net/snmp");err==nil{
        lines:=strings.Split(string(raw),"\n")
        for i:=0;i+1<len(lines);i++{
            if !strings.HasPrefix(lines[i],"Tcp:")||!strings.HasPrefix(lines[i+1],"Tcp:"){continue}
            names:=strings.Fields(lines[i]);values:=strings.Fields(lines[i+1])
            if len(names)!=len(values){continue}
            for j,k:=range names {
                if k=="RetransSegs" {
                    if n,e:=strconv.ParseUint(values[j],10,64);e==nil{status["tcp_retrans_segs"]=n}
                }
                if k=="CurrEstab" {
                    if n,e:=strconv.ParseUint(values[j],10,64);e==nil{status["tcp_established"]=n}
                }
            }
            break
        }
    }
}

func systemStatus() map[string]interface{} {
    status:=map[string]interface{}{"agent":"online","version":Version}
    if b,err:=os.ReadFile("/proc/uptime");err==nil {
        parts:=strings.Fields(string(b))
        if len(parts)>0 {if v,e:=strconv.ParseFloat(parts[0],64);e==nil{status["uptime_seconds"]=int64(v)}}
    }
    if b,err:=os.ReadFile("/proc/loadavg");err==nil {
        parts:=strings.Fields(string(b));if len(parts)>=3{status["load1"]=parts[0];status["load5"]=parts[1];status["load15"]=parts[2]}
    }
    if b,err:=os.ReadFile("/proc/meminfo");err==nil {
        for _,line:=range strings.Split(string(b),"\n") {
            for _,field:=range []string{"MemTotal:","MemAvailable:"}{
                if strings.HasPrefix(line,field) {
                    parts:=strings.Fields(line[len(field):])
                    if len(parts)>0{if kb,e:=strconv.ParseUint(parts[0],10,64);e==nil{status[strings.TrimSuffix(field,":")+"_bytes"]=kb*1024}}
                }
            }
        }
    }
    var fs syscall.Statfs_t
    if syscall.Statfs("/",&fs)==nil{
        status["disk_total_bytes"]=fs.Blocks*uint64(fs.Bsize)
        status["disk_available_bytes"]=fs.Bavail*uint64(fs.Bsize)
    }
    status["architecture"]=runtime.GOARCH
    addNetworkCounters(status)
    return status
}

func (a *Agent) execute(job *Task) Response {
    if job.Action=="agent.update" {return a.performUpdate(job)}

    resp:=Response{ID:job.ID,OK:false,Result:map[string]interface{}{}}
    if job.Action=="system.status" {
        resp.OK=true
        resp.Result=systemStatus()
        return resp
    }
    allowed:=map[string]bool{"docker.status":true,"docker.logs":true,
        "docker.restart":true,"logs.read":true,"service.status":true,"service.restart":true,
        "cert.status":true,"config.read":true,"config.apply":true,"baseline.status":true,
        "security.fail2ban.install":true,"security.fail2ban.unban":true,
        "node.cleanup":true,"node.cleanup.finish":true}
    if !allowed[job.Action] {resp.Error="unsupported operation";return resp}
    if job.Payload==nil {job.Payload=map[string]interface{}{}}
    raw,err:=json.Marshal(job.Payload)
    if err!=nil||len(raw)>50000{resp.Error="invalid payload";return resp}
    actionTimeout:=45*time.Second
    if job.Action=="node.cleanup" {actionTimeout=110*time.Second}
    ctx,cancel:=context.WithTimeout(context.Background(),actionTimeout)
    defer cancel()
    cmd:=exec.CommandContext(ctx,"sudo","-n",Helper,job.Action)
    cmd.Stdin=bytes.NewReader(raw)
    var stdout,stderr bytes.Buffer
    cmd.Stdout=&boundedWriter{w:&stdout, limit:125000}
    cmd.Stderr=&boundedWriter{w:&stderr, limit:500}
    err=cmd.Run()
    if err!=nil {
        // Never return stderr: it could contain sensitive certificate or config data.
        if ctx.Err()!=nil{resp.Error="agent action timed out"}else{resp.Error="agent helper rejected operation"}
        return resp
    }
    var data map[string]interface{}
    if err=json.Unmarshal(stdout.Bytes(),&data);err!=nil{
        resp.Error="invalid helper response";return resp
    }
    if data==nil{resp.Error="empty helper response";return resp}
    resp.OK=true
    resp.Result=data
    return resp
}

type boundedWriter struct {w io.Writer; limit int}
func (b *boundedWriter) Write(p []byte)(int,error){
    if len(p)>b.limit {return 0, errors.New("helper output limit exceeded")}
    n,err:=b.w.Write(p)
    b.limit-=n
    return n,err
}

// A successful authenticated heartbeat is the only condition that confirms
// an updated agent. The independent root updater rolls back if it never occurs.
func acknowledgeUpdate(){
    pending,err:=os.ReadFile("/var/lib/node-manager/update-pending")
    if err!=nil{return}
    values:=strings.Fields(string(pending))
    if len(values)!=2||values[0]!=Version{return}
    raw,err:=os.ReadFile("/usr/local/bin/node-manager-agent")
    if err!=nil{return}
    sum:=sha256.Sum256(raw)
    if hex.EncodeToString(sum[:])!=values[1]{return}
    _=os.WriteFile("/var/lib/node-manager/update-ok",[]byte(Version+" "+values[1]),0600)
}

func (a *Agent) performUpdate(job *Task) Response {
    fail:=func(msg string)Response{return Response{ID:job.ID,OK:false,
        Result:map[string]interface{}{},Error:msg}}
    payload:=job.Payload
    if payload==nil{return fail("missing update parameters")}
    next,_:=payload["version"].(string)
    digest,_:=payload["sha256"].(string)
    sizeRaw,ok:=payload["size"].(float64)
    if !ok ||sizeRaw<10000||sizeRaw>14000000{return fail("invalid agent artifact size")}
    size:=int64(sizeRaw)
    if !strings.HasPrefix(next,"1.")||len(next)>18||len(digest)!=64||next==Version{
        return fail("invalid or redundant update")
    }
    if runtime.GOARCH!="amd64"&&runtime.GOARCH!="arm64"{
        return fail("unsupported agent architecture")
    }
    url:=a.URL+"/update/binary/"+runtime.GOARCH
    ctx,cancel:=context.WithTimeout(context.Background(),45*time.Second)
    defer cancel()
    req,err:=http.NewRequestWithContext(ctx,"GET",url,nil)
    if err!=nil{return fail("invalid artifact URL")}
    req.Header.Set("Authorization","Bearer "+a.Token)
    req.Header.Set("X-Node-Id",a.ID)
    response,err:=a.Client.Do(req)
    if err!=nil{return fail("agent binary unavailable")}
    defer response.Body.Close()
    if response.StatusCode!=200{return fail("artifact request rejected")}
    binary,err:=io.ReadAll(io.LimitReader(response.Body,size+1))
    if err!=nil||int64(len(binary))!=size{return fail("download length mismatch")}
    sum:=sha256.Sum256(binary)
    if hex.EncodeToString(sum[:])!=digest{return fail("download SHA-256 mismatch")}
    dir:="/var/lib/node-manager"
    tmp,err:=os.CreateTemp(dir,".agent-update-*")
    if err!=nil{return fail("update staging unavailable")}
    tmpName:=tmp.Name()
    defer os.Remove(tmpName)
    if _,err=tmp.Write(binary);err!=nil{tmp.Close();return fail("agent staging failed")}
    if err=tmp.Sync();err!=nil{tmp.Close();return fail("agent staging sync failed")}
    tmp.Close()
    if err=os.Chmod(tmpName,0600);err!=nil{return fail("agent staging permissions failed")}
    if err=os.Rename(tmpName,filepath.Join(dir,"update.bin"));err!=nil{
        return fail("agent staging rename failed")
    }
    raw,_:=json.Marshal(map[string]interface{}{"version":next,"sha256":digest})
    sudoCtx,sudoCancel:=context.WithTimeout(context.Background(),18*time.Second)
    defer sudoCancel()
    cmd:=exec.CommandContext(sudoCtx,"sudo","-n",Helper,"agent.update")
    cmd.Stdin=bytes.NewReader(raw)
    if err=cmd.Run();err!=nil{return fail("systemd updater rejected verified artifact")}
    return Response{ID:job.ID,OK:true,
        Result:map[string]interface{}{"scheduled":true,"version":next}}
}

func clampHeartbeat(ms int64) int64 {
    if ms<=1000{return 1000}
    if ms<=5000{return 5000}
    return 5000
}

func (a *Agent) heartbeatLoop(interval *int64) {
    for {
        ctx,cancel:=context.WithTimeout(context.Background(),12*time.Second)
        var reply HeartbeatReply
        err:=a.send(ctx,"POST","/heartbeat",map[string]interface{}{
            "version":Version,"metrics":systemStatus()},&reply)
        cancel()
        if err!=nil {
            log.Printf("heartbeat failed: %v",err)
        } else {
            acknowledgeUpdate()
            atomic.StoreInt64(interval,clampHeartbeat(reply.NextHeartbeatMS))
        }
        time.Sleep(time.Duration(atomic.LoadInt64(interval))*time.Millisecond)
    }
}

func (a *Agent) taskLoop() {
    for {
        ctx,cancel:=context.WithTimeout(context.Background(),35*time.Second)
        var pulled Pull
        err:=a.send(ctx,"GET","/pull",nil,&pulled)
        cancel()
        if err!=nil{
            log.Printf("pull failed: %v",err)
            time.Sleep(time.Second)
            continue
        }
        if pulled.Job==nil{continue}
        result:=a.execute(pulled.Job)
        ctx,cancel=context.WithTimeout(context.Background(),50*time.Second)
        err=a.send(ctx,"POST","/report",result,nil)
        cancel()
        if err!=nil{
            // Do NOT log task results, which could contain secrets.
            log.Printf("task acknowledgement failed: %v",err)
        }
    }
}

func main(){
    manager:=os.Getenv("MANAGER_URL")
    id:=os.Getenv("NODE_ID")
    token:=os.Getenv("AGENT_TOKEN")
    parsed,err:=url.Parse(manager)
    if err!=nil||parsed.Scheme!="https"||parsed.Host==""||parsed.User!=nil||parsed.RawQuery!=""||parsed.Fragment!=""||
        !strings.HasPrefix(id,"")||len(id)!=36||len(token)<32 {
        log.Fatal("invalid manager agent configuration; HTTPS URL, node ID and token required")
    }
    agent:=Agent{URL:strings.TrimRight(manager,"/")+"/api/agent/v1",
        ID:id,Token:token,Client:&http.Client{Timeout:50*time.Second,
        CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}}}
    log.Printf("node manager agent %s started",Version)
    var interval int64=5000
    go agent.heartbeatLoop(&interval)
    agent.taskLoop()
}

