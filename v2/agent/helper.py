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
import urllib.request
import urllib.error
import urllib.parse

FILES = {
    "nginx": Path("/opt/nginx/nginx.conf"),
    "nginx-compose": Path("/opt/nginx/docker-compose.yml"),
    "node-compose": Path("/opt/remnanode/docker-compose.yml"),
}
CONTAINERS = {"nginx", "remnanode"}
SYSTEMD = {"docker.service", "certbot.timer", "xppn-node-firewall.service"}
ACTIONS = {"docker.status", "docker.logs", "docker.restart",
           "service.status", "service.restart", "logs.read", "cert.status",
           "config.read", "config.apply", "baseline.status", "agent.update",
           "node.cleanup", "node.cleanup.finish",
           "security.fail2ban.install","security.fail2ban.unban"}


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


def _inspect(args, timeout=5):
    """Bounded, non-mutating observation; no command strings or shell."""
    try:
        completed=subprocess.run(args,capture_output=True,check=False,timeout=timeout)
        if completed.returncode: return None
        return completed.stdout.decode("utf-8","replace").strip()[:12000]
    except (OSError,subprocess.TimeoutExpired):
        return None


def _ssh_protection():
    """Inspect only the SSH jail. Never expose arbitrary systemd log lines."""
    raw=_inspect(["fail2ban-client","status","sshd"],timeout=6)
    ips=[]
    if raw:
        m=re.search(r"Banned IP list:\s*([^\r\n]*)",raw)
        if m:
            for item in m.group(1).split():
                try:
                    if isinstance(ipaddress.ip_address(item),ipaddress.IPv4Address):
                        ips.append(item)
                except ValueError:
                    pass
    # Deduplicated history extracted only from tagged Fail2Ban journal events.
    events=[]
    out=_inspect(["journalctl","-u","fail2ban.service","-n","150","--no-pager","-o","short-iso"],timeout=8)
    if out:
        for line in out.splitlines():
            m=re.search(r"\[sshd\]\s+(Ban|Unban)\s+([0-9.]+)",line)
            if not m:continue
            try:
                if not isinstance(ipaddress.ip_address(m.group(2)),ipaddress.IPv4Address):continue
            except ValueError:
                continue
            events.append({"action":m.group(1).lower(),"ip":m.group(2),
                           "when":line[:25]})
    return {"banned_ips":ips[:50],"history":events[-30:],
            "banned_count":len(ips) if raw else None}


def _admin_ipv4(raw):
    if not isinstance(raw,str) or len(raw)>45:
        fail("administrator IP required")
    try:
        addr=ipaddress.ip_address(raw)
        if addr.version!=4 or not addr.is_global:
            fail("administrator IP must be public IPv4")
    except ValueError:
        fail("administrator IP invalid")
    return str(addr)


def install_ssh_protection(data):
    admin=_admin_ipv4(data.get("admin_ip"))
    script=Path("/usr/local/libexec/node-manager-fail2ban")
    if not script.is_file() or script.is_symlink():
        fail("SSH protection installer not deployed")
    if not data.get("confirmed") is True:
        fail("explicit confirmation required")
    # Deployment is a task, not a blocking apt job. Observe through baseline.status.
    if _inspect(["systemctl","is-active","fail2ban.service"])=="active" and _inspect(["fail2ban-client","status","sshd"]):
        return {"scheduled":False,"already_protected":True}
    run(["systemd-run","--collect","--unit=xppn-ssh-protection-"+os.urandom(4).hex(),
         "--on-active=2s",str(script),admin],timeout=12,limit=1200)
    return {"scheduled":True,"message":"SSH-only Fail2Ban installation scheduled"}


def unban_ssh_ip(data):
    if data.get("confirmed") is not True:fail("explicit confirmation required")
    ip=_admin_ipv4(data.get("ip"))
    if _inspect(["systemctl","is-active","fail2ban.service"])!="active":
        fail("fail2ban not active")
    status=_ssh_protection()
    if ip not in status["banned_ips"]:fail("IP not in SSH ban list")
    run(["fail2ban-client","set","sshd","unbanip",ip],timeout=10,limit=240)
    return {"unbanned":ip}


def baseline_status():
    """Read-only actual state. Never interpret absent tooling as protection."""
    congestion=_inspect(["sysctl","-n","net.ipv4.tcp_congestion_control"])
    available=_inspect(["sysctl","-n","net.ipv4.tcp_available_congestion_control"])
    qdisc=_inspect(["sysctl","-n","net.core.default_qdisc"])
    rule_file=Path("/etc/sysctl.d/90-xppn-baseline.conf")
    f2b_available=shutil.which("fail2ban-client") is not None
    f2b_active=(_inspect(["systemctl","is-active","fail2ban.service"])=="active")
    jail=_inspect(["fail2ban-client","status","sshd"]) if f2b_active else None
    banned=None
    if jail:
        hit=re.search(r"Currently banned:\s*(\d+)",jail)
        if hit: banned=int(hit.group(1))
    panel=Path("/opt/remnanode/panel-ip")
    panel_ip=panel.read_text().strip() if panel.is_file() and not panel.is_symlink() else ""
    panel_valid=False
    try:
        panel_valid=bool(ipaddress.IPv4Address(panel_ip))
    except ValueError:
        pass
    fwall=(_inspect(["systemctl","is-active","xppn-node-firewall.service"])=="active")
    rule=None
    if panel_valid:
        check=subprocess.run(
            ["iptables","-C","INPUT","-p","tcp","--dport","2222","!","-s",panel_ip,"-j","DROP"],
            capture_output=True,timeout=5,check=False)
        rule=check.returncode==0
    baseline_history=Path("/var/log/xppn-baseline-status.log")
    events=[]
    if baseline_history.is_file() and not baseline_history.is_symlink():
        try:
            events=[v for v in baseline_history.read_text("utf-8").splitlines()[-30:]
                    if re.fullmatch(r"[a-z0-9-]{3,65}",v)]
        except (OSError,UnicodeError):
            pass
    install_state=Path("/var/lib/node-manager/ssh-protection.state")
    current_state=""
    if install_state.is_file() and not install_state.is_symlink():
        try:
            raw=install_state.read_text("utf-8").strip()
            if re.fullmatch(r"[a-z0-9-]{3,60}",raw):current_state=raw
        except OSError:
            pass
    ssh_security=_ssh_protection() if jail is not None else {"banned_ips":[],"history":[],"banned_count":None}
    return {
        "security_helper_ready":Path("/usr/local/libexec/node-manager-fail2ban").is_file(),
        "ssh_install_state":current_state,
        **ssh_security,
        "baseline_events":events,
        "tcp_congestion":congestion,
        "available_congestion":available,
        "default_qdisc":qdisc,
        "bbr_config_managed":rule_file.is_file() and not rule_file.is_symlink(),
        "fail2ban_installed":f2b_available,
        "fail2ban_active":f2b_active,
        "sshd_jail_active":jail is not None,
        "sshd_banned_count":banned,
        "panel_firewall_service_active":fwall,
        "panel_firewall_ipv4_rule":rule,
        "nginx_logrotate":Path("/etc/logrotate.d/xppn-nginx").is_file(),
        "read_only":True,
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        return None


def trusted_agent_release():
    """Root re-checks the immutable Manager release over HTTPS itself.

    Unprivileged nodemanager cannot authorise arbitrary executable content:
    its supplied hash and bytes must match this authenticated Manager manifest.
    """
    env=Path("/etc/node-manager/agent.env")
    if env.is_symlink() or not env.is_file() or env.stat().st_size>4096:
        fail("trusted agent identity missing")
    values={}
    for line in env.read_text("utf-8").splitlines():
        if "=" in line:
            key,value=line.split("=",1)
            if key in ("MANAGER_URL","NODE_ID","AGENT_TOKEN"):
                values[key]=value
    manager=values.get("MANAGER_URL","")
    node_id=values.get("NODE_ID","")
    token=values.get("AGENT_TOKEN","")
    parsed=urllib.parse.urlsplit(manager)
    if (parsed.scheme!="https" or not parsed.hostname or parsed.username or
        parsed.password or parsed.port not in (None,443) or parsed.path not in ("","/") or
        parsed.query or parsed.fragment or
        not re.fullmatch(r"[0-9a-f-]{36}",node_id) or
        not re.fullmatch(r"[A-Za-z0-9_-]{40,128}",token)):
        fail("invalid trusted agent update source")
    req=urllib.request.Request(
        manager.rstrip("/")+"/api/agent/v1/update/manifest",
        headers={"Authorization":"Bearer "+token,"X-Node-Id":node_id,
                 "Accept":"application/json"})
    try:
        with urllib.request.build_opener(_NoRedirect()).open(req,timeout=12) as response:
            if response.status!=200:fail("trusted manifest unavailable")
            raw=response.read(4097)
            if len(raw)>4096:fail("trusted manifest too large")
        manifest=json.loads(raw)
    except (OSError,ValueError,UnicodeError,urllib.error.URLError):
        fail("cannot verify trusted Manager release")
    arch={"x86_64":"amd64","aarch64":"arm64"}.get(os.uname().machine)
    if not arch or not isinstance(manifest,dict):
        fail("unsupported verified agent release")
    item=manifest.get("binaries",{}).get(arch)
    if not isinstance(item,dict):
        fail("trusted agent release missing architecture")
    return item


def schedule_agent_update(data):
    """Execute only the pinned manager-downloaded binary from fixed path."""
    version=data.get("version")
    expected=data.get("sha256")
    if not isinstance(version,str) or not re.fullmatch(r"1\.[0-9]{1,3}\.[0-9]{1,3}",version):
        fail("invalid agent update version")
    if not isinstance(expected,str) or not re.fullmatch(r"[a-f0-9]{64}",expected):
        fail("invalid agent checksum")
    path=Path("/var/lib/node-manager/update.bin")
    if path.is_symlink() or not path.is_file() or path.stat().st_size>14000000:
        fail("staged agent update missing or invalid")
    release=trusted_agent_release()
    if release.get("version")!=version or release.get("sha256")!=expected or release.get("size")!=path.stat().st_size:
        fail("agent update is not in trusted Manager release")
    if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
        fail("staged agent update checksum mismatch")
    updater=Path("/usr/local/libexec/node-manager-updater")
    if not updater.is_file() or updater.is_symlink():
        fail("agent updater missing")
    # A standalone transient timer ensures the current agent can ACK the
    # task before the service is stopped. The watchdog lives in updater.
    run(["systemd-run","--collect","--unit=xppn-agent-upgrade-"+expected[:12],"--on-active=4s",
         str(updater),version,expected],timeout=10,limit=1200)
    return {"scheduled":True,"version":version,"sha256":expected}


def execute(action, data):
    if action=="security.fail2ban.install":return install_ssh_protection(data)
    if action=="security.fail2ban.unban":return unban_ssh_ip(data)
    if action=="agent.update":return schedule_agent_update(data)
    if action=="baseline.status":return baseline_status()
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
    if action=="cert.status":
        chain_path,key_path=cert_paths()
        chain=chain_path.read_bytes()
        key=key_path.read_bytes()
        if not chain or not key or len(chain)+len(key)>90000:fail("invalid tls files")
        actual=domain()
        # Verify matching public keys and domain before reporting success;
        # no private key or PEM content ever leaves this VPS.
        certificate_public=run(["openssl","x509","-in",str(chain_path),"-pubkey","-noout"],timeout=8)
        key_public=run(["openssl","pkey","-in",str(key_path),"-pubout"],timeout=8)
        if certificate_public.strip()!=key_public.strip():
            fail("certificate and private key do not match")
        hostcheck=run(["openssl","x509","-in",str(chain_path),"-noout","-checkhost",actual],timeout=8)
        if "does match certificate" not in hostcheck:
            fail("certificate hostname mismatch")
        run(["openssl","x509","-in",str(chain_path),"-noout","-checkend","3600"],timeout=8)
        # Only the dedicated Remnawave Node container may consume this path.
        mounts_raw=run(["docker","inspect","--format","{{json .Mounts}}","remnanode"],timeout=8,limit=15000)
        mounts=json.loads(mounts_raw)
        if not any(m.get("Source")=="/opt/nginx/certs" and
                   m.get("Destination")=="/opt/nginx/certs" and
                   m.get("RW") is False for m in mounts):
            fail("Remnawave Node does not have the expected read-only TLS mount")
        for check in (chain_path,key_path):
            run(["docker","exec","remnanode","test","-s",str(check)],timeout=8,limit=200)
        details=run(["openssl","x509","-in",str(chain_path),"-noout","-enddate","-fingerprint","-sha256"],
                    timeout=10,limit=600)
        return {"domain":actual,"details":details[:500],
                "certificate_sha256":hashlib.sha256(chain).hexdigest(),
                "node_tls_mount_verified":True}
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
