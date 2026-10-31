// Node Manager Agent: an outbound-only, restricted VPS control plane.
// Uses stdlib only. No listening sockets, no arbitrary shell and no SSH.
package main

import (
    "bytes"
    "context"
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
    "syscall"
    "time"
)

const Version = "1.0.0"
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
    return status
}

func execute(job *Task) Response {
    resp:=Response{ID:job.ID,OK:false,Result:map[string]interface{}{}}
    if job.Action=="system.status" {
        resp.OK=true
        resp.Result=systemStatus()
        return resp
    }
    allowed:=map[string]bool{"docker.status":true,"docker.logs":true,
        "docker.restart":true,"logs.read":true,"service.status":true,"service.restart":true,
        "cert.status":true,"cert.export":true,"config.read":true,"config.apply":true}
    if !allowed[job.Action] {resp.Error="unsupported operation";return resp}
    if job.Payload==nil {job.Payload=map[string]interface{}{}}
    raw,err:=json.Marshal(job.Payload)
    if err!=nil||len(raw)>50000{resp.Error="invalid payload";return resp}
    ctx,cancel:=context.WithTimeout(context.Background(),45*time.Second)
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

func main(){
    manager:=os.Getenv("MANAGER_URL")
    token:=os.Getenv("AGENT_TOKEN")
    id:=os.Getenv("NODE_ID")
    endpoint,err:=url.Parse(manager)
    if err!=nil||endpoint.Scheme!="https"||endpoint.Hostname()==""||endpoint.User!=nil||
        endpoint.RawQuery!=""||endpoint.Fragment!=""||endpoint.Path!=""||
        len(token)<40||len(id)<32{
        log.Fatal("invalid manager agent configuration; HTTPS URL, node ID and token required")
    }
    agent:=Agent{URL:strings.TrimRight(manager,"/")+"/api/agent/v1",
        ID:id,Token:token,Client:&http.Client{Timeout:50*time.Second}}
    // No token or certificate content is ever logged.
    log.Printf("node manager agent %s started",Version)
    lastHeartbeat:=time.Time{}
    for {
        if time.Since(lastHeartbeat)>=15*time.Second{
            ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
            err:=agent.send(ctx,"POST","/heartbeat",map[string]interface{}{
                "version":Version,"metrics":systemStatus()},nil)
            cancel()
            if err!=nil {log.Printf("heartbeat failed: %v",err)}
            lastHeartbeat=time.Now()
        }
        ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
        var pulled Pull
        err:=agent.send(ctx,"GET","/pull",nil,&pulled)
        cancel()
        if err!=nil{
            log.Printf("pull failed: %v",err)
            time.Sleep(10*time.Second)
            continue
        }
        if pulled.Job==nil{time.Sleep(5*time.Second);continue}
        result:=execute(pulled.Job)
        ctx,cancel=context.WithTimeout(context.Background(),50*time.Second)
        err=agent.send(ctx,"POST","/report",result,nil)
        cancel()
        if err!=nil{
            // Do NOT log task results, which could contain secrets.
            log.Printf("task acknowledgement failed: %v",err)
        }
    }
}
