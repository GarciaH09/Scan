import socket
import sys
import argparse
import concurrent.futures
import time
from datetime import datetime
 
# ─── Cores para terminal ────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
 
def colored(text, color):
    return f"{color}{text}{C.RESET}"
 
# ─── Mapeamento de portas conhecidas ────────────────────────────────────────
KNOWN_PORTS = {
    21:    "FTP",          22:    "SSH",          23:    "Telnet",
    25:    "SMTP",         53:    "DNS",           67:    "DHCP",
    68:    "DHCP-Client",  69:    "TFTP",          80:    "HTTP",
    88:    "Kerberos",     110:   "POP3",          111:   "RPC",
    119:   "NNTP",         123:   "NTP",           135:   "MSRPC",
    137:   "NetBIOS-NS",   138:   "NetBIOS-DGM",  139:   "NetBIOS",
    143:   "IMAP",         161:   "SNMP",          162:   "SNMP-Trap",
    194:   "IRC",          389:   "LDAP",          443:   "HTTPS",
    445:   "SMB",          465:   "SMTPS",         500:   "IKE/IPSec",
    514:   "Syslog",       587:   "SMTP-TLS",      636:   "LDAPS",
    873:   "rsync",        993:   "IMAPS",         995:   "POP3S",
    1080:  "SOCKS5",       1194:  "OpenVPN",       1433:  "MSSQL",
    1521:  "Oracle-DB",    1723:  "PPTP",          2049:  "NFS",
    2181:  "ZooKeeper",    2375:  "Docker",        2376:  "Docker-TLS",
    3000:  "Grafana/Dev",  3306:  "MySQL",         3389:  "RDP",
    3690:  "SVN",          4369:  "RabbitMQ",      4444:  "Metasploit",
    5000:  "Flask/UPnP",   5432:  "PostgreSQL",    5672:  "AMQP",
    5900:  "VNC",          5985:  "WinRM-HTTP",    5986:  "WinRM-HTTPS",
    6379:  "Redis",        6443:  "Kubernetes-API",7001:  "WebLogic",
    7077:  "Spark",        8080:  "HTTP-Proxy",    8443:  "HTTPS-Alt",
    8888:  "Jupyter",      9000:  "SonarQube",     9200:  "Elasticsearch",
    9300:  "ES-Transport", 10250: "Kubelet",       11211: "Memcached",
    15672: "RabbitMQ-UI",  27017: "MongoDB",       27018: "MongoDB-Sh",
    50000: "SAP",          51820: "WireGuard",
}
 
# Top 20 portas mais comuns para scan rápido
TOP20 = [21, 22, 23, 25, 53, 80, 110, 139, 143, 194,
         443, 445, 587, 993, 995, 1433, 3306, 3389, 5900, 8080]
 
# Top 100 portas mais comuns
TOP100 = sorted(list(KNOWN_PORTS.keys()))
 
 
# ─── Funções auxiliares ──────────────────────────────────────────────────────
 
def get_service_name(port: int) -> str:
    """Retorna o nome do serviço para uma porta."""
    if port in KNOWN_PORTS:
        return KNOWN_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"
 
 
def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Tenta capturar o banner do serviço via TCP."""
    probes = {
        80:   b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
        8080: b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
        8443: b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
        21:   None,   # FTP envia banner automaticamente
        22:   None,   # SSH envia banner automaticamente
        25:   None,   # SMTP envia banner automaticamente
        110:  None,   # POP3 envia banner automaticamente
        143:  None,   # IMAP envia banner automaticamente
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        probe = probes.get(port, b"\r\n")
        if probe:
            s.send(probe)
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        # Retorna apenas a primeira linha, truncada
        return banner.split("\n")[0][:70] if banner else ""
    except Exception:
        return ""
 
 
def scan_port(host: str, port: int, timeout: float, banners: bool) -> dict | None:
    """Testa se uma porta está aberta via TCP connect."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            service = get_service_name(port)
            banner  = grab_banner(host, port, timeout + 1) if banners else ""
            return {"port": port, "state": "open", "service": service, "banner": banner}
    except Exception:
        pass
    return None
 
 
def parse_ports(spec: str) -> list[int]:
    """Converte especificação de portas para lista de inteiros."""
    if spec.lower() == "top20":
        return TOP20
    if spec.lower() == "top100":
        return TOP100
    if spec.lower() in ["-", "all"]:
        return list(range(1, 65536))
 
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))
 
 
def resolve_host(host: str) -> tuple[str, str]:
    """Resolve hostname → IP e tenta rDNS."""
    try:
        ip = socket.gethostbyname(host)
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except Exception:
            rdns = ip
        return ip, rdns
    except Exception:
        return "", ""
 
 
def ping_sweep_host(host: str, timeout: float) -> bool:
    """Verifica se host está ativo tentando conectar em portas comuns."""
    for port in [80, 443, 22, 445, 8080, 23, 25, 3389]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                s.close()
                return True
            s.close()
        except Exception:
            pass
    return False
 
 
def cidr_to_hosts(cidr: str) -> list[str]:
    """Expande CIDR simples (IPv4 /8 a /30) para lista de hosts."""
    if "/" not in cidr:
        return [cidr]
    ip_str, prefix_str = cidr.split("/")
    prefix = int(prefix_str)
    parts = list(map(int, ip_str.split(".")))
    base = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    network = base & mask
    count = 1 << (32 - prefix)
    hosts = []
    for i in range(1, count - 1):  # exclui rede e broadcast
        n = network + i
        hosts.append(f"{(n>>24)&0xFF}.{(n>>16)&0xFF}.{(n>>8)&0xFF}.{n&0xFF}")
    return hosts
 
 
# ─── Engine de scan ──────────────────────────────────────────────────────────
 
def scan_host(host: str, ports: list[int], timeout: float,
              threads: int, banners: bool, verbose: bool) -> list[dict]:
    """Escaneia um host e retorna as portas abertas."""
    ip, rdns = resolve_host(host)
    if not ip:
        print(colored(f"\n[!] Não foi possível resolver: {host}", C.RED))
        return []
 
    label = host if host == ip else f"{host} ({ip})"
    print(f"\n{colored('═'*62, C.BLUE)}")
    print(colored(f"  Alvo   : {label}", C.BOLD))
    if rdns != ip:
        print(f"  rDNS   : {rdns}")
    print(f"  Portas : {len(ports)}")
    print(f"  Início : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(colored("═"*62, C.BLUE))
 
    open_ports: list[dict] = []
 
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout, banners): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)
                if verbose:
                    banner_str = colored(f"  « {res['banner'][:40]}", C.DIM) if res["banner"] else ""
                    print(f"  {colored('[+]', C.GREEN)} "
                          f"{colored(str(res['port'])+'/tcp', C.CYAN):<14} "
                          f"{colored('open', C.GREEN):<8} "
                          f"{res['service']:<18}{banner_str}")
 
    open_ports.sort(key=lambda x: x["port"])
 
    if not verbose:
        print(f"\n  {colored('PORT', C.BOLD):<14} {colored('STATE', C.BOLD):<10} "
              f"{colored('SERVICE', C.BOLD):<18} {colored('BANNER', C.BOLD)}")
        print(f"  {'-'*58}")
        if open_ports:
            for p in open_ports:
                banner_str = colored(p["banner"][:35], C.DIM) if p["banner"] else ""
                print(f"  {colored(str(p['port'])+'/tcp', C.CYAN):<14} "
                      f"{colored('open', C.GREEN):<10} "
                      f"{p['service']:<18} {banner_str}")
        else:
            print(f"  {colored('Nenhuma porta aberta encontrada.', C.YELLOW)}")
 
    status_color = C.GREEN if open_ports else C.YELLOW
    print(f"\n  {colored(f'✓ {len(open_ports)} porta(s) abertas', status_color)} "
          f"{colored(f'de {len(ports)} escaneadas', C.DIM)}")
    print(f"  Fim    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return open_ports
 
 
def ping_sweep(targets: list[str], timeout: float, threads: int) -> list[str]:
    """Descobre hosts ativos em uma faixa de IPs."""
    print(colored(f"\n[*] Ping sweep em {len(targets)} hosts...\n", C.YELLOW))
    active = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(ping_sweep_host, t, timeout): t for t in targets}
        for fut in concurrent.futures.as_completed(futures):
            t = futures[fut]
            if fut.result():
                active.append(t)
                print(f"  {colored('[+]', C.GREEN)} {colored(t, C.CYAN)}"
                      f" {colored('- host ativo', C.GREEN)}")
    active.sort(key=lambda ip: list(map(int, ip.split("."))))
    print(f"\n  {colored(f'✓ {len(active)} hosts ativos encontrados', C.GREEN)}")
    return active
 
 
# ─── Entrada principal ───────────────────────────────────────────────────────
 
BANNER = f"""
{colored('╔══════════════════════════════════════════════╗', C.BLUE)}
{colored('║', C.BLUE)}  {colored('NetScan', C.BOLD+C.CYAN)} — Port Scanner estilo Nmap          {colored('║', C.BLUE)}
{colored('║', C.BLUE)}  {colored('⚠  Use apenas em redes que você autoriza', C.YELLOW)}   {colored('║', C.BLUE)}
{colored('╚══════════════════════════════════════════════╝', C.BLUE)}
"""
 
EPILOG = """
Exemplos de uso:
  python netscan.py 192.168.1.1                     # portas 1-1024
  python netscan.py 192.168.1.1 -p 22,80,443        # portas específicas
  python netscan.py 192.168.1.1 -p 1-65535 -T 200   # scan completo, 200 threads
  python netscan.py 192.168.1.1 -p top20 -b         # top 20 portas + banner
  python netscan.py 192.168.1.0/24 --ping-sweep     # descobrir hosts na rede
  python netscan.py meuservidor.com -p top100 -v    # verbose em tempo real
"""
 
def main():
    print(BANNER)
 
    parser = argparse.ArgumentParser(
        description="NetScan — Scanner de portas estilo Nmap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument("alvo",
        help="IP, hostname ou CIDR (ex: 192.168.1.1, 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024", metavar="PORTAS",
        help="Portas: 22,80,443 | 1-1024 | top20 | top100 | all  [padrão: 1-1024]")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, metavar="SEG",
        help="Timeout por porta em segundos  [padrão: 1.0]")
    parser.add_argument("-T", "--threads", type=int, default=100, metavar="N",
        help="Threads paralelas  [padrão: 100]")
    parser.add_argument("-b", "--banners", action="store_true",
        help="Captura banners dos serviços (mais lento)")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="Exibe portas abertas em tempo real")
    parser.add_argument("--ping-sweep", action="store_true",
        help="Apenas descobre hosts ativos (não escaneia portas)")
    parser.add_argument("-o", "--output", metavar="ARQUIVO",
        help="Salva resultados em arquivo texto")
 
    args = parser.parse_args()
 
    targets = cidr_to_hosts(args.alvo)
 
    # ── Ping sweep ──────────────────────────────────────────────────────────
    if args.ping_sweep:
        start = time.time()
        active = ping_sweep(targets, args.timeout, args.threads)
        elapsed = time.time() - start
        print(colored(f"\n  Concluído em {elapsed:.2f}s\n", C.DIM))
        if args.output and active:
            with open(args.output, "w") as f:
                f.write("\n".join(active) + "\n")
            print(f"  Resultados salvos em: {args.output}\n")
        return
 
    # ── Port scan ───────────────────────────────────────────────────────────
    ports = parse_ports(args.ports)
 
    print(colored(f"[*] Alvos   : {len(targets)} host(s)", C.CYAN))
    print(colored(f"[*] Portas  : {len(ports)}  ({args.ports})", C.CYAN))
    print(colored(f"[*] Threads : {args.threads} | Timeout: {args.timeout}s | "
                  f"Banners: {'sim' if args.banners else 'não'}", C.CYAN))
 
    start = time.time()
    all_results: dict[str, list[dict]] = {}
 
    for target in targets:
        results = scan_host(target, ports, args.timeout, args.threads,
                            args.banners, args.verbose)
        all_results[target] = results
 
    elapsed = time.time() - start
    print(colored(f"\n{'═'*62}", C.BLUE))
    print(colored(f"  Scan completo em {elapsed:.2f} segundos", C.BOLD))
    print(colored("═"*62, C.BLUE) + "\n")
 
    # ── Salvar em arquivo ───────────────────────────────────────────────────
    if args.output:
        with open(args.output, "w") as f:
            f.write(f"NetScan — {datetime.now()}\n")
            f.write(f"Alvo(s): {args.alvo} | Portas: {args.ports}\n\n")
            for host, results in all_results.items():
                f.write(f"HOST: {host}\n")
                f.write(f"{'PORT':<12} {'STATE':<8} {'SERVICE':<16} BANNER\n")
                f.write("-" * 55 + "\n")
                for p in results:
                    f.write(f"{str(p['port'])+'/tcp':<12} {'open':<8} "
                            f"{p['service']:<16} {p['banner']}\n")
                f.write("\n")
        print(f"  Resultados salvos em: {colored(args.output, C.CYAN)}\n")
 
 
if __name__ == "__main__":
    main()