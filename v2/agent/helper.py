#!/usr/bin/env python3
"""Minimal privileged helper for an unprivileged node-manager-agent.

Never executes a user-supplied command string. Every operation and path is
allowlisted, input is bounded, processes use argv without a shell.
"""
import base64
import ipaddress
import shutil
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

FILES = {
    "nginx": Path("/opt/nginx/nginx.conf"),
    "nginx-compose": Path("/opt/nginx/docker-compose.yml"),
    "node-compose": Path("/opt/remnanode/docker-compose.yml"),
}
CONTAINERS = {"nginx", "remnanode"}
SYSTEMD = {"docker.service", "certbot.timer", "xppn-node-firewall.service"}
ACTIONS = {"docker.status", "docker.logs", "docker.restart",
           "service.status", "service.restart", "logs.read", "cert.status",
           "cert.export", "config.read", "config.apply",
           "node.cleanup", "node.cleanup.finish"}


def fail(message):
    print(message[:120], file=sys.stderr)
    raise SystemExit(1)


def run(args, timeout=15, limit=34000):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        fail("action execution failed")
    if result.returncode or len(result.stdout) > limit:
        fail("action failed validation")
    return result.stdout.decode("utf-8", "replace")


def domain():
    value = Path("/opt/remnanode/domain").read_text().strip().lower()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{1,249})\.[a-z]{2,63}", value):
        fail("invalid node domain")
    return value


def cert_paths():
    name = domain()
    root = Path("/opt/nginx/certs")
    return root / (name + "_fullchain.pem"), root / (name + "_privkey.key")


def config_path(request):
    name = request.get("name")
    if not isinstance(name, str) or name not in FILES:
        fail("unsupported config")
    return FILES[name]


def inspect_config(request):
    path = config_path(request)
    raw = path.read_bytes()
    if len(raw) > 45000:
        fail("config too large")
    return {"name": request["name"], "content":raw.decode("utf-8"),
            "sha256": hashlib.sha256(raw).hexdigest()}


def update_nginx(request):
    if request.get("name") != "nginx":
        fail("only nginx configuration can currently be applied")
    content=request.get("content")
    expected=request.get("expected_sha256")
    if not isinstance(content,str) or not 0<len(content.encode())<=35000:
        fail("invalid config size")
    if not isinstance(expected,str) or not re.fullmatch(r"[a-f0-9]{64}",expected):
        fail("missing revision")
    path=FILES["nginx"]
    old=path.read_bytes()
    if hashlib.sha256(old).hexdigest()!=expected:
        fail("config was changed by another process")
    candidate=content.encode()
    if b"\x00" in candidate:
        fail("binary config not supported")
    # Nginx configuration is a bind-mounted FILE. Replacing the host inode
    # would leave the running container stuck on the old config.
    # Preserve inode and first save a bounded, root-only rollback snapshot.
    backup=path.parent/(".agent-nginx-backup-"+hashlib.sha256(old).hexdigest()[:16])
    fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(old);stream.flush();os.fsync(stream.fileno())
    def put(data):
        with open(path,"r+b") as stream:
            stream.seek(0);stream.write(data);stream.truncate()
            stream.flush();os.fsync(stream.fileno())
    put(candidate)
    try:
        run(["docker","exec","nginx","nginx","-t"],timeout=12)
        run(["docker","exec","nginx","nginx","-s","reload"],timeout=12)
    except SystemExit:
        put(old)
        try:run(["docker","exec","nginx","nginx","-s","reload"],timeout=12)
        except SystemExit:pass
        fail("nginx validation failed; original config restored")
    return {"name":"nginx","applied":True,
            "sha256":hashlib.sha256(candidate).hexdigest()}

def _check_cleanup_domain(request, prepared=False):
    requested=request.get("domain")
    if not isinstance(requested,str) or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.-]{1,249})\.[a-z]{2,63}",requested):
        fail("invalid cleanup target")
    actual=(Path("/var/lib/node-manager/cleanup-ready").read_text().strip()
            if prepared else domain())
    if actual!=requested:
        fail("cleanup target is different VPS")
    return requested


def _owned_path(path):
    if path.is_symlink():
        fail("managed path unexpectedly became a symlink")
    if path.exists() and not path.is_dir():
        fail("managed directory has unexpected type")
    return path


def _compose_down(file,allowed):
    if not file.is_file() or file.is_symlink():
        fail("managed compose file is missing or linked")
    services=run(["docker","compose","-f",str(file),"config","--services"],
                 timeout=12,limit=2000).splitlines()
    if not services or set(services)!=set(allowed):
        fail("managed compose was modified; refusing to remove other services")
    run(["docker","compose","-f",str(file),"down","--timeout","5"],
        timeout=28,limit=2000)


def _undo_managed_firewall():
    path=Path("/opt/remnanode/panel-ip")
    if not path.is_file() or path.is_symlink():
        fail("managed panel IP missing")
    address=path.read_text().strip()
    if ipaddress.ip_address(address).version!=4:
        fail("invalid managed firewall address")
    rule=["INPUT","-p","tcp","--dport","2222","!","-s",address,"-j","DROP"]
    for program,args in [("iptables",rule),
                         ("ip6tables",["INPUT","-p","tcp","--dport","2222","-j","DROP"])]:
        if shutil.which(program):
            exists=subprocess.run([program,"-C",*args],capture_output=True,timeout=7)
            if exists.returncode==0:
                run([program,"-D",*args],timeout=10,limit=1000)


def _cleanup_managed(request):
    name=_check_cleanup_domain(request)
    node=_owned_path(Path("/opt/remnanode"))
    nginx=_owned_path(Path("/opt/nginx"))
    if not node.is_dir() or not nginx.is_dir():
        fail("managed directories absent; manual inspection required")
    if (node/"domain").is_symlink() or (node/"domain").read_text().strip()!=name:
        fail("node identity does not match")
    _compose_down(node/"docker-compose.yml",{"remnanode"})
    _compose_down(nginx/"docker-compose.yml",{"nginx"})
    _undo_managed_firewall()
    renewal=Path("/etc/letsencrypt/renewal")/(name+".conf")
    if renewal.is_symlink():fail("certbot renewal config is linked")
    certificate_deleted=renewal.is_file()
    if certificate_deleted:
        run(["certbot","delete","--cert-name",name,"--non-interactive"],timeout=25,limit=2000)
    run(["systemctl","disable","--now","xppn-node-firewall.service"],timeout=12,limit=1000)
    managed_files=[
        Path("/etc/systemd/system/xppn-node-firewall.service"),
        Path("/etc/logrotate.d/xppn-remnanode"),
        Path("/etc/letsencrypt/renewal-hooks/deploy/xppn-node.sh"),
        Path("/usr/local/sbin/xppn-cert-refresh"),
        Path("/usr/local/sbin/xppn-node-firewall"),
    ]
    for path in managed_files:
        if path.is_symlink():fail("managed file unexpectedly linked")
        if path.is_file():path.unlink()
    run(["systemctl","daemon-reload"],timeout=12,limit=1000)
    for path in (node,nginx,_owned_path(Path("/var/log/remnanode"))):
        if path.exists():shutil.rmtree(path)
    marker=Path("/var/lib/node-manager")
    marker.mkdir(mode=0o700,parents=True,exist_ok=True)
    file=marker/"cleanup-ready"
    if file.is_symlink():fail("cleanup marker unexpectedly linked")
    file.write_text(name+"\n")
    file.chmod(0o600)
    return {"cleaned":True,"node":name,"containers_removed":True,
            "certbot_certificate_deleted":certificate_deleted,"agent_remains":True}


def _finish_cleanup(request):
    name=_check_cleanup_domain(request,prepared=True)
    script=Path("/usr/local/libexec/node-manager-uninstall.sh")
    if not script.is_file() or script.is_symlink():
        fail("agent uninstall script missing")
    run(["systemd-run","--unit=node-manager-self-remove","--on-active=20s",
         str(script)],timeout=12,limit=3000)
    return {"scheduled":True,"node":name,"verified_removed":False}


def execute(action, data):
    if action=="node.cleanup":return _cleanup_managed(data)
    if action=="node.cleanup.finish":return _finish_cleanup(data)
    if action == "docker.status":
        result=[]
        for name in sorted(CONTAINERS):
            proc=subprocess.run(["docker","inspect","--format","{{json .State}}",name],
                                capture_output=True,timeout=8,check=False)
            if proc.returncode:
                result.append({"name":name,"running":False,"installed":False})
                continue
            state=json.loads(proc.stdout)
            result.append({"name":name,"running":bool(state.get("Running")),
                           "installed":True,"status":str(state.get("Status",""))[:32],
                           "exit_code":state.get("ExitCode")})
        return {"containers":result}
    if action == "docker.restart":
        name=data.get("name")
        if name not in CONTAINERS:fail("container not allowed")
        run(["docker","restart","--time","8",name],timeout=30)
        return {"restarted":name}
    if action=="logs.read":
        entries={
            "xray-error":Path("/var/log/remnanode/error.log"),
            "xray-access":Path("/var/log/remnanode/access.log"),
            "nginx-access":Path("/opt/nginx/logs/access.log"),
            "nginx-error":Path("/opt/nginx/logs/error.log"),
            "certbot":Path("/var/log/letsencrypt/letsencrypt.log"),
        }
        source=data.get("source")
        if not isinstance(source,str) or source not in entries:
            fail("log source not allowed")
        path=entries[source]
        if path.is_symlink():fail("symlinked log source is not allowed")
        if not path.is_file():return {"source":source,"logs":"Лог пока не создан"}
        with open(path,"rb") as log:
            log.seek(0,2)
            size=log.tell()
            log.seek(max(0,size-65536))
            raw=log.read(65536)
        count=data.get("tail",100)
        if not isinstance(count,int) or not 1<=count<=200:fail("invalid log tail")
        return {"source":source,
                "logs":b"\n".join(raw.splitlines()[-count:])[-26000:].decode("utf-8","replace")}
    if action == "docker.logs":
        name=data.get("name")
        if name not in CONTAINERS:fail("container not allowed")
        tail=data.get("tail",80)
        if not isinstance(tail,int) or not 1<=tail<=200:fail("invalid tail")
        raw=subprocess.run(["docker","logs","--tail",str(tail),name],
                           capture_output=True,timeout=12,check=False)
        if raw.returncode:fail("could not read container logs")
        logtext=(raw.stdout + raw.stderr)[-26000:].decode("utf-8","replace")
        return {"name":name,"logs":logtext}
    if action == "service.status":
        names=sorted(SYSTEMD)
        result=[]
        for name in names:
            check=subprocess.run(["systemctl","is-active",name],capture_output=True,timeout=7)
            result.append({"name":name,"active":check.returncode==0})
        return {"services":result}
    if action == "service.restart":
        name=data.get("name")
        # Only the Certbot scheduler is restartable by the agent in v1.
        if name!="certbot.timer":fail("service restart not allowed")
        run(["systemctl","restart",name],timeout=25)
        return {"restarted":name}
    if action in {"cert.export","cert.status"}:
        chain_path,key_path=cert_paths()
        chain=chain_path.read_bytes()
        key=key_path.read_bytes()
        if not chain or not key or len(chain)+len(key)>90000:fail("invalid tls files")
        details=run(["openssl","x509","-in",str(chain_path),"-noout","-enddate","-fingerprint","-sha256"],
                    timeout=10,limit=600)
        if action=="cert.export":
            # Sensitive: sent ONLY inside TLS agent-to-manager response.
            return {"domain":domain(),"chain":base64.b64encode(chain).decode(),
                    "key":base64.b64encode(key).decode()}
        return {"domain":domain(),"details":details[:500],
                "certificate_sha256":hashlib.sha256(chain).hexdigest()}
    if action=="config.read":return inspect_config(data)
    if action=="config.apply":return update_nginx(data)
    fail("unsupported operation")


def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ACTIONS:fail("action not allowed")
    raw=sys.stdin.buffer.read(51001)
    if len(raw)>50000:fail("payload too large")
    try:
        data=json.loads(raw or b"{}")
        if not isinstance(data,dict):fail("payload must be an object")
        answer=execute(sys.argv[1],data)
        encoded=json.dumps(answer,ensure_ascii=True,separators=(",",":"))
        if len(encoded)>125000:fail("result too large")
        print(encoded)
    except (OSError,ValueError,KeyError,UnicodeError,subprocess.SubprocessError):
        fail("node helper action failed")


if __name__=="__main__":
    main()
