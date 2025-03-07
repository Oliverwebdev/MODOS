import os
import platform
import logging

logger = logging.getLogger("dos_framework")

class SystemOptimizer:
    @staticmethod
    def optimize_system(advanced: bool = False):
        if os.geteuid() != 0:
            logger.warning("Keine Root-Rechte. Systemoptimierungen werden übersprungen.")
            return False
        try:
            if platform.system() == "Linux":
                os.system("ulimit -n 999999")
                os.system("sysctl -w net.core.somaxconn=65535")
                os.system("sysctl -w net.ipv4.tcp_max_syn_backlog=65535")
                os.system("sysctl -w net.core.rmem_max=16777216")
                os.system("sysctl -w net.core.wmem_max=16777216")
                os.system("sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216'")
                os.system("sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216'")
                os.system("sysctl -w net.ipv4.ip_local_port_range='1024 65535'")
                os.system("sysctl -w net.ipv4.conf.all.rp_filter=0")
                os.system("sysctl -w net.ipv4.conf.default.rp_filter=0")
                if advanced:
                    os.system("sysctl -w net.ipv4.tcp_fin_timeout=1")
                    os.system("sysctl -w net.ipv4.tcp_tw_reuse=1")
                    os.system("sysctl -w net.core.netdev_max_backlog=5000")
                    os.system("sysctl -w net.ipv4.tcp_no_metrics_save=1")
                    os.system("sysctl -w net.ipv4.tcp_moderate_rcvbuf=1")
                    os.system("sysctl -w net.ipv4.ip_forward=1")
                    os.system("sysctl -w net.ipv4.tcp_mtu_probing=1")
                    if os.path.exists("/proc/sys/kernel/numa_balancing"):
                        os.system("sysctl -w kernel.numa_balancing=0")
                    os.system("sysctl -w fs.inotify.max_user_watches=524288")
                    ifaces = os.listdir("/sys/class/net/")
                    eth_ifaces = [iface for iface in ifaces if iface.startswith(("eth", "ens", "eno", "enp"))]
                    if eth_ifaces:
                        eth = eth_ifaces[0]
                        os.system(f"ethtool -G {eth} rx 4096 tx 4096 2>/dev/null || true")
                        os.system(f"ethtool -K {eth} tso off gso off 2>/dev/null || true")
                os.system("modprobe ip_gre")
                logger.info("Systemoptimierungen erfolgreich angewendet.")
                return True
            else:
                logger.warning("Systemoptimierungen werden nur unter Linux unterstützt.")
                return False
        except Exception as e:
            logger.error(f"Fehler bei Systemoptimierungen: {str(e)}")
            return False

    @staticmethod
    def optimize_process_priority():
        try:
            if platform.system() in ["Linux", "Darwin"]:
                os.nice(-20)
                logger.info("Prozesspriorität auf Maximum gesetzt.")
                return True
            elif platform.system() == "Windows":
                import psutil
                p = psutil.Process(os.getpid())
                p.nice(psutil.HIGH_PRIORITY_CLASS)
                logger.info("Prozesspriorität auf Maximum gesetzt.")
                return True
            return False
        except Exception as e:
            logger.warning(f"Fehler beim Setzen der Prozesspriorität: {str(e)}")
            return False
