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
           "security.fail2ban.install","security.fail2ban.unban",
           "security.settings.apply"}


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


def _security_bool(value, name):
    if not isinstance(value, bool):
        fail(name + " must be boolean")
    return value


def _security_int(value, name, minimum, maximum, allow_minus_one=False):
    if isinstance(value, bool) or not isinstance(value, int):
        fail(name + " must be integer")
    if allow_minus_one and value == -1:
        return value
    if not minimum <= value <= maximum:
        fail(name + " out of range")
    return value


def _security_networks(value, name, limit=32):
    if not isinstance(value, list) or len(value) > limit:
        fail(name + " invalid")
    result=[]
    for item in value:
        if not isinstance(item,str) or len(item)>80:
            fail(name + " invalid")
        try:
            network=ipaddress.ip_network(item.strip(),strict=False)
        except ValueError:
            fail(name + " invalid")
        canonical=str(network)
        if canonical not in result:
            result.append(canonical)
    return result


def _replace_root_file(path, content, mode=0o644):
    if path.is_symlink():
        fail("managed file unexpectedly linked")
    data=content.encode("utf-8") if isinstance(content,str) else content
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=".xppn-",dir=str(path.parent))
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,"wb") as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
        os.chmod(path,mode)
    finally:
        try:os.unlink(tmp)
        except FileNotFoundError:pass


def _install_packages(packages):
    missing=[name for name in packages if shutil.which(name) is None]
    if not missing:return
    proc=subprocess.run(
        ["apt-get","-o","DPkg::Lock::Timeout=60","install","-y","-qq",*packages],
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=150,check=False,
        env={**os.environ,"DEBIAN_FRONTEND":"noninteractive","NEEDRESTART_MODE":"l"})
    if proc.returncode:
        fail("package installation failed")


def _apply_tcp_settings(cfg):
    enabled=_security_bool(cfg.get("enabled"),"tcp.enabled")
    cc=str(cfg.get("congestion_control","")).strip().lower()
    qdisc=str(cfg.get("qdisc","")).strip().lower()
    if cc not in {"bbr","cubic","reno"}:fail("unsupported congestion control")
    if qdisc not in {"fq","fq_codel"}:fail("unsupported qdisc")
    managed=Path("/etc/sysctl.d/90-xppn-baseline.conf")
    previous=Path("/etc/xppn-baseline-previous")
    current_cc=_inspect(["sysctl","-n","net.ipv4.tcp_congestion_control"]) or ""
    current_qdisc=_inspect(["sysctl","-n","net.core.default_qdisc"]) or ""
    if enabled:
        if shutil.which("modprobe"):
            if cc=="bbr":subprocess.run(["modprobe","tcp_bbr"],capture_output=True,timeout=8)
            if qdisc=="fq":subprocess.run(["modprobe","sch_fq"],capture_output=True,timeout=8)
            if qdisc=="fq_codel":subprocess.run(["modprobe","sch_fq_codel"],capture_output=True,timeout=8)
        available=(_inspect(["sysctl","-n","net.ipv4.tcp_available_congestion_control"]) or "").split()
        if cc not in available:fail("requested congestion control unavailable")
        if not managed.exists() and current_cc and current_qdisc and not previous.exists():
            if re.fullmatch(r"[a-z0-9_]+",current_cc) and re.fullmatch(r"[a-z0-9_]+",current_qdisc):
                _replace_root_file(previous,
                    "tcp_congestion_control="+current_cc+"\ndefault_qdisc="+current_qdisc+"\n",0o600)
        old=managed.read_bytes() if managed.is_file() and not managed.is_symlink() else None
        content=("# Managed by XPPN Manager. Only selected TCP congestion and default qdisc.\n"
                 "net.core.default_qdisc = "+qdisc+"\n"
                 "net.ipv4.tcp_congestion_control = "+cc+"\n")
        _replace_root_file(managed,content,0o644)
        try:
            run(["sysctl","-p",str(managed)],timeout=12,limit=1500)
            if _inspect(["sysctl","-n","net.ipv4.tcp_congestion_control"])!=cc:
                raise SystemExit(1)
            if _inspect(["sysctl","-n","net.core.default_qdisc"])!=qdisc:
                raise SystemExit(1)
        except SystemExit:
            if old is None:
                try:managed.unlink()
                except FileNotFoundError:pass
            else:_replace_root_file(managed,old,0o644)
            if current_cc:subprocess.run(["sysctl","-w","net.ipv4.tcp_congestion_control="+current_cc],capture_output=True,timeout=8)
            if current_qdisc:subprocess.run(["sysctl","-w","net.core.default_qdisc="+current_qdisc],capture_output=True,timeout=8)
            fail("tcp settings failed validation")
    else:
        if managed.is_symlink():fail("managed sysctl unexpectedly linked")
        if managed.is_file():managed.unlink()
        restored=False
        if previous.is_file() and not previous.is_symlink():
            values={}
            for line in previous.read_text("utf-8").splitlines():
                if "=" in line:
                    key,value=line.split("=",1)
                    if key in ("tcp_congestion_control","default_qdisc") and re.fullmatch(r"[a-z0-9_]+",value):
                        values[key]=value
            if values.get("tcp_congestion_control"):
                subprocess.run(["sysctl","-w","net.ipv4.tcp_congestion_control="+values["tcp_congestion_control"]],
                               capture_output=True,timeout=8)
                restored=True
            if values.get("default_qdisc"):
                subprocess.run(["sysctl","-w","net.core.default_qdisc="+values["default_qdisc"]],
                               capture_output=True,timeout=8)
                restored=True
        return {"enabled":False,"restored_previous":restored}
    return {"enabled":True,"congestion_control":cc,"qdisc":qdisc}


def _ssh_ports():
    raw=_inspect(["/usr/sbin/sshd","-T"],timeout=8) or ""
    ports=[]
    for line in raw.splitlines():
        parts=line.split()
        if len(parts)==2 and parts[0]=="port" and parts[1].isdigit():
            number=int(parts[1])
            if 1<=number<=65535 and str(number) not in ports:ports.append(str(number))
    if not ports:fail("ssh port unavailable")
    return ",".join(ports)


def _apply_fail2ban_settings(cfg, panel_ip):
    enabled=_security_bool(cfg.get("enabled"),"fail2ban.enabled")
    maxretry=_security_int(cfg.get("maxretry"),"fail2ban.maxretry",1,20)
    findtime=_security_int(cfg.get("findtime_seconds"),"fail2ban.findtime",60,86400)
    bantime=_security_int(cfg.get("bantime_seconds"),"fail2ban.bantime",60,604800,True)
    trusted=_security_networks(cfg.get("trusted_sources",[]),"fail2ban.trusted")
    conf=Path("/etc/fail2ban/jail.d/90-xppn-sshd.local")
    marker=Path("/var/lib/node-manager/fail2ban-managed")
    if not enabled:
        if conf.is_symlink():fail("managed fail2ban config linked")
        if conf.is_file():
            marker.parent.mkdir(parents=True,exist_ok=True)
            _replace_root_file(marker,"managed\n",0o600)
            conf.unlink()
            if shutil.which("fail2ban-client"):
                subprocess.run(["systemctl","restart","fail2ban.service"],capture_output=True,timeout=20)
        return {"enabled":False}
    if shutil.which("fail2ban-client") and not conf.exists() and not marker.exists():
        fail("existing fail2ban needs review")
    if shutil.which("fail2ban-client") is None:
        _install_packages(["fail2ban","python3-systemd"])
    ports=_ssh_ports()
    ignore=["127.0.0.1/8","::1"]
    for item in trusted:
        if item not in ignore:ignore.append(item)
    if panel_ip and panel_ip+"/32" not in ignore:ignore.append(panel_ip+"/32")
    content=("# Managed by XPPN Manager. SSH jail only.\n"
             "[sshd]\n"
             "enabled = true\n"
             "backend = systemd\n"
             "mode = normal\n"
             "port = "+ports+"\n"
             "maxretry = "+str(maxretry)+"\n"
             "findtime = "+str(findtime)+"\n"
             "bantime = "+str(bantime)+"\n"
             "ignoreip = "+" ".join(ignore)+"\n")
    old=conf.read_bytes() if conf.is_file() and not conf.is_symlink() else None
    _replace_root_file(conf,content,0o644)
    marker.parent.mkdir(parents=True,exist_ok=True)
    _replace_root_file(marker,"managed\n",0o600)
    test=subprocess.run(["fail2ban-client","-t"],capture_output=True,timeout=20,check=False)
    if test.returncode:
        if old is None:
            try:conf.unlink()
            except FileNotFoundError:pass
        else:_replace_root_file(conf,old,0o644)
        fail("fail2ban configuration invalid")
    proc=subprocess.run(["systemctl","enable","--now","fail2ban.service"],
                        capture_output=True,timeout=25,check=False)
    if proc.returncode:
        fail("fail2ban service unavailable")
    run(["fail2ban-client","reload"],timeout=15,limit=2000)
    if _inspect(["fail2ban-client","status","sshd"],timeout=8) is None:
        fail("fail2ban ssh jail unavailable")
    return {"enabled":True,"maxretry":maxretry,"findtime_seconds":findtime,
            "bantime_seconds":bantime,"trusted_sources":trusted}


def _firewall_script(panel_ip, allowed, block_ipv6, enabled, legacy_ipv6=False):
    old_panel=panel_ip
    lines=["#!/usr/bin/env bash","set -Eeuo pipefail",
           "PORT=2222",
           "cleanup4(){",
           " while iptables -C INPUT -p tcp --dport \"$PORT\" -j XPPN_NODE_API4 2>/dev/null; do iptables -D INPUT -p tcp --dport \"$PORT\" -j XPPN_NODE_API4; done",
           " iptables -F XPPN_NODE_API4 2>/dev/null || true",
           " iptables -X XPPN_NODE_API4 2>/dev/null || true",
           "}",
           "cleanup6(){",
           " if command -v ip6tables >/dev/null; then",
           "  while ip6tables -C INPUT -p tcp --dport \"$PORT\" -j XPPN_NODE_API6 2>/dev/null; do ip6tables -D INPUT -p tcp --dport \"$PORT\" -j XPPN_NODE_API6; done",
           "  ip6tables -F XPPN_NODE_API6 2>/dev/null || true",
           "  ip6tables -X XPPN_NODE_API6 2>/dev/null || true",
           " fi",
           "}",
           "cleanup4","cleanup6"]
    if old_panel:
        lines.append(
          "while iptables -C INPUT -p tcp --dport \"$PORT\" ! -s "+old_panel+" -j DROP 2>/dev/null; do iptables -D INPUT -p tcp --dport \"$PORT\" ! -s "+old_panel+" -j DROP; done")
    if legacy_ipv6:
        # Remove the one rule created by the legacy XPPN installer only during
        # migration. Never keep deleting generic user-owned IPv6 DROP rules.
        lines.append(
          "if command -v ip6tables >/dev/null && ip6tables -C INPUT -p tcp --dport \"$PORT\" -j DROP 2>/dev/null; then ip6tables -D INPUT -p tcp --dport \"$PORT\" -j DROP; fi")
    if not enabled:return "\n".join(lines)+"\n"
    ipv4=[];ipv6=[]
    for source in allowed:
        network=ipaddress.ip_network(source,strict=False)
        (ipv4 if network.version==4 else ipv6).append(str(network))
    lines += ["iptables -N XPPN_NODE_API4"]
    for source in ipv4:lines.append("iptables -A XPPN_NODE_API4 -s "+source+" -j ACCEPT")
    lines += ["iptables -A XPPN_NODE_API4 -j DROP",
              "iptables -I INPUT 1 -p tcp --dport \"$PORT\" -j XPPN_NODE_API4"]
    if block_ipv6 or ipv6:
        lines += ["if command -v ip6tables >/dev/null; then",
                  " ip6tables -N XPPN_NODE_API6"]
        for source in ipv6:lines.append(" ip6tables -A XPPN_NODE_API6 -s "+source+" -j ACCEPT")
        lines += [" ip6tables -A XPPN_NODE_API6 -j DROP",
                  " ip6tables -I INPUT 1 -p tcp --dport \"$PORT\" -j XPPN_NODE_API6",
                  "fi"]
    return "\n".join(lines)+"\n"


def _apply_firewall_settings(cfg):
    enabled=_security_bool(cfg.get("enabled"),"firewall.enabled")
    block_ipv6=_security_bool(cfg.get("block_ipv6"),"firewall.block_ipv6")
    allowed=_security_networks(cfg.get("allowed_sources",[]),"firewall.allowed")
    panel_ip=str(cfg.get("panel_ip","")).strip()
    old_panel=""
    panel_path=Path("/opt/remnanode/panel-ip")
    if panel_path.is_file() and not panel_path.is_symlink():
        old_panel=panel_path.read_text("utf-8").strip()
    if enabled:
        try:
            panel=ipaddress.ip_address(panel_ip)
        except ValueError:
            fail("panel ipv4 required")
        if panel.version!=4 or not panel.is_global:fail("panel ipv4 invalid")
        if not any(panel in ipaddress.ip_network(item,strict=False) for item in allowed):
            fail("firewall must allow panel ipv4")
    else:
        panel_ip=old_panel if re.fullmatch(r"[0-9.]+",old_panel or "") else ""
    script_path=Path("/usr/local/sbin/xppn-node-firewall")
    unit=Path("/etc/systemd/system/xppn-node-firewall.service")
    old_script=script_path.read_bytes() if script_path.is_file() and not script_path.is_symlink() else None
    legacy_ipv6=bool(old_script and b"XPPN_NODE_API6" not in old_script and
                     b"ip6tables -C INPUT -p tcp --dport 2222 -j DROP" in old_script)
    script=_firewall_script(old_panel or panel_ip,allowed,block_ipv6,enabled,legacy_ipv6)
    _replace_root_file(script_path,script,0o700)
    _replace_root_file(unit,
        "[Unit]\nDescription=Restrict Remnawave Node API to allowed sources\n"
        "Wants=docker.service\nAfter=docker.service\n"
        "[Service]\nType=oneshot\nExecStart=/usr/local/sbin/xppn-node-firewall\n"
        "RemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n",0o644)
    run(["systemctl","daemon-reload"],timeout=15,limit=1000)
    try:
        run([str(script_path)],timeout=20,limit=1800)
    except SystemExit:
        if old_script is not None:
            _replace_root_file(script_path,old_script,0o700)
            try:run([str(script_path)],timeout=20,limit=1800)
            except SystemExit:pass
        fail("firewall update failed")
    if enabled:
        _replace_root_file(panel_path,panel_ip+"\n",0o600)
        run(["systemctl","enable","xppn-node-firewall.service"],timeout=15,limit=1000)
        run(["systemctl","restart","xppn-node-firewall.service"],timeout=20,limit=1000)
    else:
        subprocess.run(["systemctl","disable","--now","xppn-node-firewall.service"],
                       capture_output=True,timeout=15)
    return {"enabled":enabled,"allowed_sources":allowed,
            "block_ipv6":block_ipv6,"panel_ip":panel_ip if enabled else ""}


def _logrotate_config(path, size_mb, archives, compress):
    directive="compress" if compress else "nocompress"
    return (path+" {\n"
            "    daily\n"
            "    size "+str(size_mb)+"M\n"
            "    rotate "+str(archives)+"\n"
            "    "+directive+"\n"
            "    missingok\n"
            "    notifempty\n"
            "    copytruncate\n"
            "}\n")


def _apply_one_logrotate(cfg, file_path, log_path, name):
    enabled=_security_bool(cfg.get("enabled"),name+".enabled")
    size_mb=_security_int(cfg.get("size_mb"),name+".size",1,2048)
    archives=_security_int(cfg.get("archives"),name+".archives",1,30)
    compress=_security_bool(cfg.get("compress"),name+".compress")
    path=Path(file_path)
    if not enabled:
        if path.is_symlink():fail("managed logrotate linked")
        if path.is_file():path.unlink()
        return {"enabled":False}
    _install_packages(["logrotate"])
    old=path.read_bytes() if path.is_file() and not path.is_symlink() else None
    _replace_root_file(path,_logrotate_config(log_path,size_mb,archives,compress),0o644)
    proc=subprocess.run(["logrotate","-d",str(path)],capture_output=True,timeout=15,check=False)
    if proc.returncode:
        if old is None:
            try:path.unlink()
            except FileNotFoundError:pass
        else:_replace_root_file(path,old,0o644)
        fail(name+" logrotate invalid")
    return {"enabled":True,"size_mb":size_mb,"archives":archives,"compress":compress}


def _apply_log_settings(cfg):
    if not isinstance(cfg,dict):fail("logs invalid")
    nginx=_apply_one_logrotate(cfg.get("nginx",{}),"/etc/logrotate.d/xppn-nginx",
                               "/opt/nginx/logs/*.log","nginx")
    node=_apply_one_logrotate(cfg.get("remnanode",{}),"/etc/logrotate.d/xppn-remnanode",
                              "/var/log/remnanode/*.log","remnanode")
    if shutil.which("systemctl"):
        subprocess.run(["systemctl","enable","--now","logrotate.timer"],
                       capture_output=True,timeout=20)
    return {"nginx":nginx,"remnanode":node}


def apply_security_settings(data):
    revision=data.get("revision")
    cfg=data.get("config")
    if isinstance(revision,bool) or not isinstance(revision,int) or revision<1:
        fail("invalid security revision")
    if not isinstance(cfg,dict):fail("invalid security config")
    for name in ("tcp","fail2ban","firewall","logs"):
        if not isinstance(cfg.get(name),dict):fail("incomplete security config")
    firewall_cfg=cfg["firewall"]
    panel_ip=str(firewall_cfg.get("panel_ip","")).strip()
    # Validate all user-controlled fields before the first mutation.
    _security_bool(cfg["tcp"].get("enabled"),"tcp.enabled")
    if str(cfg["tcp"].get("congestion_control","")).lower() not in {"bbr","cubic","reno"}:
        fail("unsupported congestion control")
    if str(cfg["tcp"].get("qdisc","")).lower() not in {"fq","fq_codel"}:
        fail("unsupported qdisc")
    _security_bool(cfg["fail2ban"].get("enabled"),"fail2ban.enabled")
    _security_int(cfg["fail2ban"].get("maxretry"),"fail2ban.maxretry",1,20)
    _security_int(cfg["fail2ban"].get("findtime_seconds"),"fail2ban.findtime",60,86400)
    _security_int(cfg["fail2ban"].get("bantime_seconds"),"fail2ban.bantime",60,604800,True)
    _security_networks(cfg["fail2ban"].get("trusted_sources",[]),"fail2ban.trusted")
    _security_bool(firewall_cfg.get("enabled"),"firewall.enabled")
    _security_bool(firewall_cfg.get("block_ipv6"),"firewall.block_ipv6")
    _security_networks(firewall_cfg.get("allowed_sources",[]),"firewall.allowed")
    for logname in ("nginx","remnanode"):
        item=cfg["logs"].get(logname)
        if not isinstance(item,dict):fail("logs incomplete")
        _security_bool(item.get("enabled"),logname+".enabled")
        _security_int(item.get("size_mb"),logname+".size",1,2048)
        _security_int(item.get("archives"),logname+".archives",1,30)
        _security_bool(item.get("compress"),logname+".compress")
    logs=_apply_log_settings(cfg["logs"])
    fail2ban=_apply_fail2ban_settings(cfg["fail2ban"],panel_ip)
    tcp=_apply_tcp_settings(cfg["tcp"])
    firewall=_apply_firewall_settings(firewall_cfg)
    return {"revision":revision,"applied":True,"tcp":tcp,"fail2ban":fail2ban,
            "firewall":firewall,"logs":logs}


def _active_qdisc():
    route=_inspect(["ip","-o","route","show","default"],timeout=5) or ""
    match=re.search(r"(?:^|\s)dev\s+([A-Za-z0-9_.:-]+)",route)
    if not match:return {"interface":"","qdisc":""}
    iface=match.group(1)
    out=_inspect(["tc","qdisc","show","dev",iface],timeout=5) or ""
    qdisc=""
    for line in out.splitlines():
        parts=line.split()
        if len(parts)>=2 and parts[0]=="qdisc":
            qdisc=parts[1];break
    return {"interface":iface,"qdisc":qdisc}


def _iptables_has(args):
    try:
        return subprocess.run(args,capture_output=True,timeout=5,check=False).returncode==0
    except (OSError,subprocess.TimeoutExpired):
        return False


def _logrotate_ok(path):
    target=Path(path)
    if not target.is_file() or target.is_symlink() or not shutil.which("logrotate"):
        return False
    try:
        return subprocess.run(["logrotate","-d",str(target)],capture_output=True,
                              timeout=10,check=False).returncode==0
    except (OSError,subprocess.TimeoutExpired):
        return False


def _directory_log_bytes(path):
    root=Path(path)
    total=0
    if not root.is_dir() or root.is_symlink():return 0
    try:
        for item in root.iterdir():
            if item.is_file() and not item.is_symlink() and item.name.endswith(".log"):
                total+=min(item.stat().st_size,2**40)
    except OSError:
        return 0
    return total


def _f2b_value(field):
    value=_inspect(["fail2ban-client","get","sshd",field],timeout=6)
    return value if value is not None else ""


def _managed_fail2ban_config():
    path=Path("/etc/fail2ban/jail.d/90-xppn-sshd.local")
    result={"maxretry":None,"findtime":None,"bantime":None,"ignoreip":[]}
    if not path.is_file() or path.is_symlink():return result
    try:
        for line in path.read_text("utf-8").splitlines():
            stripped=line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:continue
            key,value=(part.strip() for part in stripped.split("=",1))
            if key in ("maxretry","findtime","bantime"):
                try:result[key]=int(value)
                except ValueError:pass
            elif key=="ignoreip":
                result["ignoreip"]=[x for x in value.split() if len(x)<=80][:40]
    except (OSError,UnicodeError):
        pass
    return result


def _logrotate_state(path):
    target=Path(path)
    state={"enabled":False,"valid":False,"size_mb":None,"archives":None,"compress":None}
    if not target.is_file() or target.is_symlink():return state
    state["enabled"]=True
    state["valid"]=_logrotate_ok(path)
    try:
        for line in target.read_text("utf-8").splitlines():
            stripped=line.strip()
            m=re.fullmatch(r"size\s+([0-9]{1,4})M",stripped)
            if m:state["size_mb"]=int(m.group(1))
            m=re.fullmatch(r"rotate\s+([0-9]{1,2})",stripped)
            if m:state["archives"]=int(m.group(1))
            if stripped=="compress":state["compress"]=True
            if stripped=="nocompress":state["compress"]=False
    except (OSError,UnicodeError):
        pass
    return state


def _firewall_allowed_sources(program,chain):
    raw=_inspect([program,"-S",chain],timeout=6)
    if not raw:return []
    result=[]
    for line in raw.splitlines():
        match=re.search(r"(?:^|\s)-s\s+([^\s]+).*\s-j\s+ACCEPT(?:\s|$)",line)
        if not match:continue
        try:source=str(ipaddress.ip_network(match.group(1),strict=False))
        except ValueError:continue
        if source not in result:result.append(source)
    return result[:40]


def baseline_status():
    """Read-only actual state. Never interpret absent tooling as protection."""
    congestion=_inspect(["sysctl","-n","net.ipv4.tcp_congestion_control"])
    available=_inspect(["sysctl","-n","net.ipv4.tcp_available_congestion_control"])
    qdisc=_inspect(["sysctl","-n","net.core.default_qdisc"])
    active_qdisc=_active_qdisc()
    rule_file=Path("/etc/sysctl.d/90-xppn-baseline.conf")
    f2b_available=shutil.which("fail2ban-client") is not None
    f2b_active=(_inspect(["systemctl","is-active","fail2ban.service"])=="active")
    jail=_inspect(["fail2ban-client","status","sshd"]) if f2b_active else None
    banned=None
    if jail:
        hit=re.search(r"Currently banned:\s*(\d+)",jail)
        if hit:banned=int(hit.group(1))
    panel=Path("/opt/remnanode/panel-ip")
    panel_ip=panel.read_text().strip() if panel.is_file() and not panel.is_symlink() else ""
    panel_valid=False
    try:
        panel_valid=bool(ipaddress.IPv4Address(panel_ip))
    except ValueError:
        pass
    fwall=(_inspect(["systemctl","is-active","xppn-node-firewall.service"])=="active")
    fwall_enabled=(_inspect(["systemctl","is-enabled","xppn-node-firewall.service"])=="enabled")
    custom4=_iptables_has(["iptables","-C","INPUT","-p","tcp","--dport","2222",
                           "-j","XPPN_NODE_API4"])
    custom4_drop=_iptables_has(["iptables","-C","XPPN_NODE_API4","-j","DROP"]) if custom4 else False
    custom4_panel=(_iptables_has(["iptables","-C","XPPN_NODE_API4","-s",panel_ip+"/32",
                                  "-j","ACCEPT"]) if custom4 and panel_valid else False)
    legacy=False
    if panel_valid:
        legacy=_iptables_has(["iptables","-C","INPUT","-p","tcp","--dport","2222",
                              "!","-s",panel_ip,"-j","DROP"])
    ipv6=False
    if shutil.which("ip6tables"):
        custom6=_iptables_has(["ip6tables","-C","INPUT","-p","tcp","--dport","2222",
                               "-j","XPPN_NODE_API6"])
        ipv6=custom6 and _iptables_has(["ip6tables","-C","XPPN_NODE_API6","-j","DROP"])
        if not ipv6:
            ipv6=_iptables_has(["ip6tables","-C","INPUT","-p","tcp","--dport","2222","-j","DROP"])
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
    nginx_rotate_state=_logrotate_state("/etc/logrotate.d/xppn-nginx")
    node_rotate_state=_logrotate_state("/etc/logrotate.d/xppn-remnanode")
    nginx_rotate=nginx_rotate_state["valid"]
    node_rotate=node_rotate_state["valid"]
    rotate_timer=(_inspect(["systemctl","is-active","logrotate.timer"])=="active")
    managed_f2b=_managed_fail2ban_config()
    firewall_sources=_firewall_allowed_sources("iptables","XPPN_NODE_API4") if custom4 else []
    if shutil.which("ip6tables"):
        firewall_sources += [x for x in _firewall_allowed_sources("ip6tables","XPPN_NODE_API6")
                             if x not in firewall_sources]
    return {
        "security_settings_supported":True,
        "security_helper_ready":Path("/usr/local/libexec/node-manager-fail2ban").is_file(),
        "ssh_install_state":current_state,
        **ssh_security,
        "baseline_events":events,
        "tcp_congestion":congestion,
        "available_congestion":available,
        "default_qdisc":qdisc,
        "active_qdisc":active_qdisc.get("qdisc",""),
        "network_interface":active_qdisc.get("interface",""),
        "bbr_config_managed":rule_file.is_file() and not rule_file.is_symlink(),
        "fail2ban_installed":f2b_available,
        "fail2ban_active":f2b_active,
        "sshd_jail_active":jail is not None,
        "sshd_banned_count":banned,
        "fail2ban_maxretry":managed_f2b["maxretry"] if jail else None,
        "fail2ban_findtime":managed_f2b["findtime"] if jail else None,
        "fail2ban_bantime":managed_f2b["bantime"] if jail else None,
        "fail2ban_ignoreip":managed_f2b["ignoreip"] if jail else [],
        "panel_firewall_service_active":fwall,
        "panel_firewall_service_enabled":fwall_enabled,
        "panel_firewall_ipv4_rule":bool((custom4 and custom4_drop and custom4_panel) or legacy),
        "panel_firewall_ipv6_rule":ipv6,
        "panel_firewall_mode":"managed-chain" if custom4 else ("legacy" if legacy else ""),
        "panel_firewall_panel_ip":panel_ip if panel_valid else "",
        "panel_firewall_allowed_sources":firewall_sources,
        "nginx_logrotate":nginx_rotate,
        "remnanode_logrotate":node_rotate,
        "nginx_logrotate_state":nginx_rotate_state,
        "remnanode_logrotate_state":node_rotate_state,
        "logrotate_timer_active":rotate_timer,
        "nginx_log_bytes":_directory_log_bytes("/opt/nginx/logs"),
        "remnanode_log_bytes":_directory_log_bytes("/var/log/remnanode"),
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
    if action=="security.settings.apply":return apply_security_settings(data)
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
