"""
AEGIS WIRELESS v1.0
WiFi Security Analysis Tool
Educational & Defensive Use Only

HOW TO RUN:
    Open a terminal in VS Code (Ctrl + `) and type:
        python main.py

LEGAL DISCLAIMER:
    This tool is for EDUCATIONAL and DEFENSIVE purposes only.
    Only scan networks and devices you OWN or have PERMISSION
    to scan. Unauthorized network scanning may violate laws
    such as the Computer Fraud and Abuse Act (CFAA).
"""

# ---------- IMPORTS ----------

import sys       # For system operations like exiting
import os        # For file path operations
import json      # For reading JSON data
import time      # For timing operations

# ── Add project root to Python path ──
# This line tells Python "look in this folder for modules."
# Without it, Python can't find our scanner/, core/, etc.
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Now we can import our custom modules
from scanner.wifi_scan import WiFiScanner, WiFiNetwork
from scanner.port_probe import PortScanner
from core.engine import RiskEngine
from core.blacklist import BlacklistManager
from network.enforcement import NetworkEnforcer
from network.vpn_tunnel import VPNStatus
from api.telemetry import AegisLogger


# ---------- TERMINAL COLORS ----------
# These codes make text colorful in the terminal.
# They work on most modern terminals including VS Code.

class Colors:
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


# ---------- MAIN APPLICATION CLASS ----------

class AegisWireless:
    """
    The main application. Ties together all modules:
    WiFi scanning, port scanning, risk analysis, blacklist,
    enforcement, VPN status, and logging.
    """

    def __init__(self):
        # Create an instance of each module
        self.wifi_scanner = WiFiScanner()
        self.port_scanner = PortScanner()
        self.risk_engine = RiskEngine()
        self.blacklist = BlacklistManager()
        self.enforcer = NetworkEnforcer()
        self.logger = AegisLogger()

        # Cache of last scan results
        self.last_wifi_results = []
        self.last_port_report = None
        self.last_assessments = []

    # ── BANNER ──────────────────────────────────────────────────

    @staticmethod
    def print_banner():
        """Print the ASCII art banner."""
        C = Colors
        banner = f"""
{C.CYAN}{C.BOLD}
    ===================================================
         _    _____ ____ ___ ____
        / \\  | ____/ ___|_ _/ ___|
       / _ \\ |  _|| |  _ | |\\___ \\
      / ___ \\| |__| |_| || | ___) |
     /_/   \\_\\_____|\\____|___|____/  WIRELESS v1.0

     WiFi Security Analysis Tool
     Educational & Defensive Use Only
    ===================================================
{C.RESET}"""
        print(banner)

    # ── MAIN MENU LOOP ──────────────────────────────────────────

    def run(self):
        """Main event loop — show menu, handle choices."""
        self.print_banner()
        self._print_legal_notice()
        self.logger.log_message("Aegis Wireless session started")

        while True:
            self._print_menu()
            choice = input(
                f"\n  {Colors.CYAN}Enter choice (1-8): "
                f"{Colors.RESET}"
            ).strip()

            if choice == "1":
                self._menu_wifi_scan()
            elif choice == "2":
                self._menu_port_scan()
            elif choice == "3":
                self._menu_risk_analysis()
            elif choice == "4":
                self._menu_blacklist()
            elif choice == "5":
                self._menu_view_logs()
            elif choice == "6":
                self._menu_vpn_status()
            elif choice == "7":
                self._menu_full_audit()
            elif choice in ("8", "q", "quit", "exit"):
                self._exit()
            else:
                print(f"  {Colors.YELLOW}Invalid choice. "
                      f"Please enter 1-8.{Colors.RESET}")

    def _print_menu(self):
        """Display the main menu."""
        C = Colors
        print(f"""
  {C.BOLD}{'-' * 50}
  MAIN MENU
  {'-' * 50}{C.RESET}
  {C.CYAN}1{C.RESET} | Scan WiFi Networks
  {C.CYAN}2{C.RESET} | Scan Ports on a Device
  {C.CYAN}3{C.RESET} | Analyze Network Risk
  {C.CYAN}4{C.RESET} | Manage Blacklist
  {C.CYAN}5{C.RESET} | View Scan Logs
  {C.CYAN}6{C.RESET} | Check VPN Status
  {C.CYAN}7{C.RESET} | Full Network Audit (scan + analyze all)
  {C.CYAN}8{C.RESET} | Exit
  {C.BOLD}{'-' * 50}{C.RESET}""")

    # ── 1. WIFI SCAN ────────────────────────────────────────────

    def _menu_wifi_scan(self):
        """Scan for nearby WiFi networks."""
        C = Colors
        print(f"\n  {C.BOLD}WiFi Network Scanner{C.RESET}")
        print(f"  {C.DIM}Detecting nearby networks...{C.RESET}\n")

        networks = self.wifi_scanner.scan()
        self.last_wifi_results = networks

        if not networks:
            print(f"  {C.YELLOW}No networks found. "
                  f"Is WiFi enabled?{C.RESET}")
            return

        # Display results as a table
        print(f"  Found {C.GREEN}{len(networks)}{C.RESET} "
              f"network(s):\n")
        print(f"  {'#':<4} {'SSID':<28} {'Signal':>6}  "
              f"{'Encryption':<16} {'Channel':>7}  {'Band'}")
        print(f"  {'-' * 80}")

        for i, net in enumerate(networks, 1):
            # Color-code by encryption type
            if net.encryption == "Open":
                enc_color = C.RED
            elif net.encryption in ("WEP", "WPA"):
                enc_color = C.YELLOW
            else:
                enc_color = C.GREEN

            # Create a visual signal strength bar
            bars = self._signal_bar(net.signal_strength)

            print(
                f"  {i:<4} {net.ssid:<28} "
                f"{bars} {net.signal_strength:>3}%  "
                f"{enc_color}{net.encryption:<16}{C.RESET} "
                f"{net.channel:>5}   {net.band}"
            )

        # Log the results
        self.logger.log_wifi_scan(
            self.wifi_scanner.get_results_as_dicts()
        )

        # Warn about open networks
        open_nets = [n for n in networks
                     if n.encryption == "Open"]
        if open_nets:
            print(f"\n  {C.RED}{C.BOLD}"
                  f"{len(open_nets)} OPEN network(s) "
                  f"detected!{C.RESET}")
            print(f"  {C.RED}  Open networks transmit all "
                  f"data without encryption.{C.RESET}")

    @staticmethod
    def _signal_bar(strength: int) -> str:
        """Create a visual signal strength bar."""
        filled = strength // 20
        empty = 5 - filled
        if strength >= 70:
            color = Colors.GREEN
        elif strength >= 40:
            color = Colors.YELLOW
        else:
            color = Colors.RED
        return (f"{color}{'#' * filled}"
                f"{'.' * empty}{Colors.RESET}")

    # ── 2. PORT SCAN ────────────────────────────────────────────

    def _menu_port_scan(self):
        """Scan a device for open ports."""
        C = Colors
        print(f"\n  {C.BOLD}Port Scanner{C.RESET}")

        local_ip = self.port_scanner.get_local_ip()
        print(f"  {C.DIM}Your local IP: {local_ip}{C.RESET}")
        print(f"  {C.DIM}Tip: scan 127.0.0.1 to check "
              f"your own machine.{C.RESET}\n")

        target = input(
            f"  Enter target IP [default: 127.0.0.1]: "
        ).strip()
        if not target:
            target = "127.0.0.1"

        print(f"\n  Scan type:")
        print(f"    1 | Quick scan (common ports — fast)")
        print(f"    2 | Full scan  (ports 1-1024 — slower)")
        scan_type = input(f"  Choose [1]: ").strip()

        print()
        if scan_type == "2":
            report = self.port_scanner.full_scan(target)
        else:
            report = self.port_scanner.quick_scan(target)

        self.last_port_report = report

        # Display summary
        print(f"\n  {C.BOLD}{'=' * 50}")
        print(f"  SCAN RESULTS: {report.target}")
        print(f"  {'=' * 50}{C.RESET}")
        print(f"  Ports scanned: {report.total_scanned}")
        open_color = (C.GREEN if len(report.open_ports) < 5
                      else C.RED)
        print(f"  Open ports:    {open_color}"
              f"{len(report.open_ports)}{C.RESET}")
        print(f"  Closed:        {report.closed_count}")

        if report.open_ports:
            print(f"\n  {'Port':<8} {'Service':<18} "
                  f"{'Risk Note'}")
            print(f"  {'-' * 50}")
            for p in report.open_ports:
                print(f"  {p.port:<8} {p.service:<18} "
                      f"{p.risk_note}")
                if p.banner:
                    print(f"  {C.DIM}         Banner: "
                          f"{p.banner[:60]}{C.RESET}")

        # Log
        self.logger.log_port_scan(report.to_dict())

    # ── 3. RISK ANALYSIS ───────────────────────────────────────

    def _menu_risk_analysis(self):
        """Analyze risk level of scanned networks."""
        C = Colors
        print(f"\n  {C.BOLD}Network Risk Analysis{C.RESET}")

        if not self.last_wifi_results:
            print(f"  {C.YELLOW}No WiFi scan data. "
                  f"Run a WiFi scan first (option 1).{C.RESET}")
            return

        print(f"\n  Available networks from last scan:")
        for i, net in enumerate(self.last_wifi_results, 1):
            print(f"    {i} | {net.ssid} ({net.encryption})")
        print(f"    A | Analyze ALL networks")

        choice = input(
            f"\n  Select network # or 'A': "
        ).strip()

        if choice.lower() == "a":
            # Analyze all networks
            assessments = self.risk_engine.analyze_multiple(
                self.last_wifi_results
            )
            self.last_assessments = assessments
            for assessment in assessments:
                RiskEngine.print_assessment(assessment)
                self.logger.log_assessment(
                    assessment.to_dict()
                )
                self.enforcer.enforce(assessment)
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.last_wifi_results):
                    net = self.last_wifi_results[idx]
                    assessment = self.risk_engine.analyze(
                        net, self.last_port_report
                    )
                    self.last_assessments = [assessment]
                    RiskEngine.print_assessment(assessment)
                    self.logger.log_assessment(
                        assessment.to_dict()
                    )
                    self.enforcer.enforce(assessment)
                else:
                    print(f"  {C.YELLOW}"
                          f"Invalid selection.{C.RESET}")
            except ValueError:
                print(f"  {C.YELLOW}"
                      f"Please enter a number or 'A'.{C.RESET}")

    # ── 4. BLACKLIST MANAGEMENT ────────────────────────────────

    def _menu_blacklist(self):
        """Manage the blacklist of unsafe networks."""
        C = Colors
        print(f"\n  {C.BOLD}Blacklist Manager{C.RESET}")
        print(f"  {C.DIM}Mark networks as unsafe to get "
              f"warnings in future scans.{C.RESET}")
        print(f"""
    1 | View blacklisted networks
    2 | Add a network
    3 | Remove a network
    4 | Back to main menu""")

        choice = input(f"\n  Choice: ").strip()

        if choice == "1":
            self.blacklist.print_all()

        elif choice == "2":
            ssid = input(
                f"  Network name (SSID): "
            ).strip()
            if ssid:
                reason = input(
                    f"  Reason for blacklisting: "
                ).strip()
                success = self.blacklist.add(
                    ssid, reason=reason
                )
                if success:
                    self.logger.log_blacklist_change(
                        "added", ssid, reason
                    )

        elif choice == "3":
            self.blacklist.print_all()
            ssid = input(
                f"  Network name to remove: "
            ).strip()
            if ssid:
                success = self.blacklist.remove(ssid)
                if success:
                    self.logger.log_blacklist_change(
                        "removed", ssid
                    )

    # ── 5. VIEW LOGS ───────────────────────────────────────────

    def _menu_view_logs(self):
        """View scan logs."""
        C = Colors
        print(f"\n  {C.BOLD}Scan Logs{C.RESET}")

        logs = self.logger.list_logs()
        if not logs:
            print(f"  {C.DIM}No logs found yet. "
                  f"Run a scan first.{C.RESET}")
            return

        print(f"\n  Log files:")
        for f in logs:
            print(f"    - {f}")

        print(f"\n    1 | View today's log")
        print(f"    2 | Clear all logs")
        print(f"    3 | Back")

        choice = input(f"\n  Choice: ").strip()

        if choice == "1":
            data = self.logger.read_json_log()
            if data:
                output = json.dumps(data, indent=2)
                # Show first 3000 characters
                print(f"\n{output[:3000]}")
                if len(output) > 3000:
                    print(f"\n  {C.DIM}... (output "
                          f"truncated){C.RESET}")
        elif choice == "2":
            confirm = input(
                f"  {C.YELLOW}Delete all logs? "
                f"(yes/no): {C.RESET}"
            ).strip()
            if confirm.lower() == "yes":
                self.logger.clear_logs()

    # ── 6. VPN STATUS ──────────────────────────────────────────

    def _menu_vpn_status(self):
        """Check VPN connection status."""
        C = Colors
        print(f"\n  {C.BOLD}VPN Status Check{C.RESET}\n")

        vpn_active = VPNStatus.is_vpn_active()

        if vpn_active:
            print(f"  {C.GREEN}[OK] VPN connection "
                  f"detected.{C.RESET}")
            print(f"  {C.GREEN}  Your traffic appears "
                  f"to be tunneled.{C.RESET}")
        else:
            print(f"  {C.YELLOW}[!] No VPN "
                  f"detected.{C.RESET}")
            print(f"  {C.YELLOW}  Your traffic may be "
                  f"visible on this network.{C.RESET}")
            print(f"\n  {C.BOLD}Recommended VPN "
                  f"options:{C.RESET}")
            for name, desc in (
                VPNStatus.recommend_vpn().items()
            ):
                print(f"    - {C.CYAN}{name}{C.RESET}: "
                      f"{desc}")

    # ── 7. FULL AUDIT ──────────────────────────────────────────

    def _menu_full_audit(self):
        """Run a complete network audit."""
        C = Colors
        print(f"\n  {C.BOLD}{'=' * 50}")
        print(f"  FULL NETWORK AUDIT")
        print(f"  {'=' * 50}{C.RESET}")
        print(f"  {C.DIM}This will: scan WiFi -> scan ports "
              f"-> analyze all -> report{C.RESET}\n")

        confirm = input(
            f"  Start full audit? (yes/no): "
        ).strip()
        if confirm.lower() not in ("yes", "y"):
            return

        # Step 1: WiFi Scan
        print(f"\n  {C.CYAN}[Step 1/4] Scanning WiFi "
              f"networks...{C.RESET}")
        networks = self.wifi_scanner.scan()
        self.last_wifi_results = networks
        print(f"  Found {len(networks)} network(s).\n")

        if not networks:
            print(f"  {C.YELLOW}No networks found. "
                  f"Audit aborted.{C.RESET}")
            return

        # Step 2: Port scan (localhost)
        print(f"  {C.CYAN}[Step 2/4] Scanning local "
              f"ports...{C.RESET}")
        report = self.port_scanner.quick_scan("127.0.0.1")
        self.last_port_report = report
        print(f"  Found {len(report.open_ports)} "
              f"open port(s).\n")

        # Step 3: VPN check
        print(f"  {C.CYAN}[Step 3/4] Checking VPN "
              f"status...{C.RESET}")
        vpn = VPNStatus.is_vpn_active()
        print(f"  VPN: {'Active' if vpn else 'Not detected'}\n")

        # Step 4: Risk analysis on all networks
        print(f"  {C.CYAN}[Step 4/4] Analyzing all "
              f"networks...{C.RESET}\n")
        assessments = self.risk_engine.analyze_multiple(
            networks
        )
        self.last_assessments = assessments

        # Print summary table
        print(f"\n  {C.BOLD}AUDIT RESULTS{C.RESET}")
        print(f"  {'-' * 60}")
        print(f"  {'Network':<28} {'Score':>6}  "
              f"{'Level':<12} {'Issues':>6}")
        print(f"  {'-' * 60}")

        for a in assessments:
            level_color = {
                "SAFE": C.GREEN,
                "MODERATE": C.YELLOW,
                "DANGEROUS": C.RED
            }.get(a.risk_level, "")
            print(
                f"  {a.ssid:<28} "
                f"{a.safety_score:>5}/100  "
                f"{level_color}{a.risk_level:<12}{C.RESET} "
                f"{len(a.findings):>5}"
            )

        # Stats
        safe = sum(1 for a in assessments
                   if a.risk_level == "SAFE")
        moderate = sum(1 for a in assessments
                       if a.risk_level == "MODERATE")
        dangerous = sum(1 for a in assessments
                        if a.risk_level == "DANGEROUS")

        print(f"\n  {C.BOLD}Summary:{C.RESET}")
        print(f"    {C.GREEN}Safe:      {safe}{C.RESET}")
        print(f"    {C.YELLOW}Moderate:  {moderate}{C.RESET}")
        print(f"    {C.RED}Dangerous: {dangerous}{C.RESET}")
        print(f"    VPN:       "
              f"{'Protected' if vpn else 'Unprotected'}")

        # Log everything
        self.logger.log_wifi_scan(
            self.wifi_scanner.get_results_as_dicts()
        )
        self.logger.log_port_scan(report.to_dict())
        for a in assessments:
            self.logger.log_assessment(a.to_dict())
        self.logger.log_message("Full audit completed")

    # ── LEGAL NOTICE ───────────────────────────────────────────

    @staticmethod
    def _print_legal_notice():
        """Print the legal disclaimer."""
        C = Colors
        print(f"""  {C.YELLOW}{C.BOLD}LEGAL & ETHICS NOTICE{C.RESET}
  {C.DIM}{'-' * 50}
  This tool is for EDUCATIONAL and DEFENSIVE use only.

  - Only scan networks and devices you OWN or have
    explicit PERMISSION to scan.
  - Unauthorized scanning may violate the Computer
    Fraud and Abuse Act (CFAA) or local laws.
  - This tool does NOT perform any attacks — it only
    observes publicly broadcast information.
  {'-' * 50}{C.RESET}
""")

    # ── EXIT ───────────────────────────────────────────────────

    def _exit(self):
        """Save logs and exit the program."""
        C = Colors
        print(f"\n  {C.CYAN}Saving session logs...{C.RESET}")
        self.logger.save_session()
        print(f"  {C.GREEN}Goodbye! Stay safe online.{C.RESET}\n")
        sys.exit(0)


# ---------- ENTRY POINT ----------
# This is what runs when you type "python main.py"

if __name__ == "__main__":
    try:
        app = AegisWireless()
        app.run()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print(f"\n\n  {Colors.CYAN}Interrupted. "
              f"Saving logs...{Colors.RESET}")
        try:
            app.logger.save_session()
        except Exception:
            pass
        print(f"  {Colors.GREEN}Goodbye!{Colors.RESET}\n")
        sys.exit(0)