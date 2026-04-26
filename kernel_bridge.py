
import ctypes
import struct
import threading
import logging
import time
import os
from typing import Optional, Callable

log = logging.getLogger("RansomWall.KernelBridge")

try:
    import win32file       
    import win32security  
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    log.debug("[KernelBridge] pywin32 not installed.  Run: pip install pywin32")

try:
    _fltlib = ctypes.WinDLL("fltlib.dll")
    FLTLIB_AVAILABLE = True
except (OSError, AttributeError):
    _fltlib = None
    FLTLIB_AVAILABLE = False
    log.warning("[KernelBridge] fltlib.dll not available.  "
                "RansomWallFilter.sys must be installed and running.")


RANSOMWALL_PORT_WNAME = "\\RansomWallPort"

RW_OP_UNKNOWN       = 0
RW_OP_READ          = 1   # IRP_MJ_READ
RW_OP_WRITE         = 2   # IRP_MJ_WRITE
RW_OP_RENAME        = 3   # IRP_MJ_SET_INFORMATION (FileRenameInformation)
RW_OP_DELETE        = 4   # IRP_MJ_SET_INFORMATION (FileDispositionInformation)
RW_OP_DIR_QUERY     = 5   # IRP_MJ_DIRECTORY
RW_OP_CREATE        = 6   # IRP_MJ_CREATE
RW_OP_FINGERPRINT   = 7   # Extension / magic-byte mismatch detected in kernel
RW_OP_ENTROPY_SPIKE = 8   # High-entropy write detected in kernel (paper §III-D-3g)

OP_NAMES = {
    RW_OP_UNKNOWN:       "unknown",
    RW_OP_READ:          "read",
    RW_OP_WRITE:         "write",
    RW_OP_RENAME:        "rename",
    RW_OP_DELETE:        "delete",
    RW_OP_DIR_QUERY:     "dir_query",
    RW_OP_CREATE:        "create",
    RW_OP_FINGERPRINT:   "fingerprint_mismatch",
    RW_OP_ENTROPY_SPIKE: "entropy_spike",
}

RW_CMD_SUSPEND_PID   = 1   # Pause monitoring for a PID
RW_CMD_KILL_PID      = 2   # Request ZwTerminateProcess for a PID
RW_CMD_WHITELIST_PID = 3   # Mark PID as benign; stop sending IRPs for it
RW_CMD_STATUS        = 4   # Query driver statistics


MSG_FORMAT = "<IIIi520sIqI1040s32s1040s32sIBBB"
MSG_SIZE   = struct.calcsize(MSG_FORMAT) 
FILTER_MSG_HEADER_SIZE = 16

class IRPMessage:
    __slots__ = [
        "message_size", "version", "process_id", "thread_id",
        "process_name", "operation", "timestamp", "file_size",
        "file_path", "file_extension", "dest_path", "dest_extension",
        "entropy_x100", "is_target_extension", "is_ransom_extension",
        "fingerprint_mismatch",
    ]

    @classmethod
    def from_bytes(cls, data: bytes) -> "IRPMessage":
        if len(data) < MSG_SIZE:
            raise ValueError(
                f"Kernel message too short: got {len(data)} bytes, "
                f"expected {MSG_SIZE}"
            )

        fields = struct.unpack_from(MSG_FORMAT, data)
        msg = cls()
        (
            msg.message_size,
            msg.version,
            msg.process_id,
            msg.thread_id,
            raw_proc,
            op,
            msg.timestamp,
            msg.file_size,
            raw_path,
            raw_ext,
            raw_dest,
            raw_dest_ext,
            msg.entropy_x100,
            is_target,
            is_ransom,
            fp_mismatch,
        ) = fields

        msg.operation            = op
        msg.process_name         = raw_proc.decode("utf-16-le",
                                                   errors="replace").rstrip("\x00")
        msg.file_path            = raw_path.decode("utf-16-le",
                                                   errors="replace").rstrip("\x00")
        msg.file_extension       = raw_ext.decode("utf-16-le",
                                                   errors="replace").rstrip("\x00")
        msg.dest_path            = raw_dest.decode("utf-16-le",
                                                   errors="replace").rstrip("\x00")
        msg.dest_extension       = raw_dest_ext.decode("utf-16-le",
                                                        errors="replace").rstrip("\x00")
        msg.is_target_extension  = bool(is_target)
        msg.is_ransom_extension  = bool(is_ransom)
        msg.fingerprint_mismatch = bool(fp_mismatch)
        return msg


    def op_name(self) -> str:
        return OP_NAMES.get(self.operation, "unknown")

    @property
    def entropy(self) -> float:
        return self.entropy_x100 / 100.0

    def __repr__(self) -> str:
        return (
            f"IRPMessage(op={self.op_name()}, pid={self.process_id}, "
            f"proc={self.process_name!r}, "
            f"file={self.file_path!r}, "
            f"entropy={self.entropy:.2f}, "
            f"ransom_ext={self.is_ransom_extension}, "
            f"fp_mismatch={self.fingerprint_mismatch})"
        )

CMD_FORMAT = "<II128s"
CMD_SIZE   = struct.calcsize(CMD_FORMAT)


def _build_command(command: int, target_pid: int) -> bytes:
    """Pack a RANSOMWALL_COMMAND for FilterSendMessage."""
    return struct.pack(CMD_FORMAT, command, target_pid, b"\x00" * 128)



class KernelBridge:
    def __init__(self,
                 dynamic_engine=None,
                 trap_layer=None,
                 on_irp_callback: Optional[Callable] = None):
        self._dynamic  = dynamic_engine
        self._trap     = trap_layer
        self._callback = on_irp_callback

        self._port: Optional[ctypes.c_void_p] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Diagnostic counters
        self._stats = {
            "received":        0,
            "errors":          0,
            "dropped":         0,
            "honey_hits":      0,
            "entropy_spikes":  0,
            "fp_mismatches":   0,
            "ransom_renames":  0,
        }


    def start(self) -> bool:
        
        if not FLTLIB_AVAILABLE:
            log.error("[KernelBridge] fltlib.dll unavailable.  "
                      "Is RansomWallFilter.sys loaded and running?")
            return False

        if not self._connect():
            return False

        self._running = True
        self._thread = threading.Thread(
            target=self._receive_loop,
            name="KernelBridge-Receiver",
            daemon=True,
        )
        self._thread.start()
        log.info(
            f"[KernelBridge] Connected to {RANSOMWALL_PORT_WNAME}.  "
            f"IRP message size = {MSG_SIZE} bytes.  "
            f"Receiving real kernel IRP events."
        )
        return True

    def stop(self):
        self._running = False
        if self._port:
            try:
                _fltlib.FilterPortClose(self._port)
            except Exception:
                pass
            self._port = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        log.info(f"[KernelBridge] Stopped.  Stats: {self._stats}")


    def _connect(self) -> bool:
        
        try:
            _fltlib.FilterConnectCommunicationPort.restype = ctypes.HRESULT
            _fltlib.FilterConnectCommunicationPort.argtypes = [
                ctypes.c_wchar_p,                  # lpPortName
                ctypes.c_ulong,                    # dwOptions
                ctypes.c_void_p,                   # lpContext
                ctypes.c_ushort,                   # wSizeOfContext
                ctypes.c_void_p,                   # lpSecurityAttributes
                ctypes.POINTER(ctypes.c_void_p),   # hPort (out)
            ]

            port_handle = ctypes.c_void_p()
            hr = _fltlib.FilterConnectCommunicationPort(
                RANSOMWALL_PORT_WNAME,     # L"\RansomWallPort"
                0,                         # dwOptions = 0
                None,                      # no connection context
                0,                         # wSizeOfContext = 0
                None,                      # default security attributes
                ctypes.byref(port_handle),
            )
            if hr != 0:
                log.error(
                    f"[KernelBridge] FilterConnectCommunicationPort failed: "
                    f"HRESULT=0x{hr & 0xFFFFFFFF:08X}.  "
                    f"Ensure RansomWallFilter.sys is loaded (install_driver.bat) "
                    f"and this process is running as Administrator."
                )
                return False

            self._port = port_handle
            log.info(f"[KernelBridge] Communication port opened: {RANSOMWALL_PORT_WNAME}")
            return True

        except Exception as exc:
            log.error(f"[KernelBridge] _connect() exception: {exc}")
            return False


    def _receive_loop(self):
        
        try:
            _fltlib.FilterGetMessage.restype = ctypes.HRESULT
            _fltlib.FilterGetMessage.argtypes = [
                ctypes.c_void_p,   # hPort
                ctypes.c_void_p,   # lpMessageBuffer
                ctypes.c_ulong,    # dwMessageBufferSize
                ctypes.c_void_p,   # lpOverlapped (NULL = synchronous)
            ]
        except Exception as exc:
            log.error(f"[KernelBridge] Cannot bind FilterGetMessage: {exc}")
            return

        buf_total = FILTER_MSG_HEADER_SIZE + MSG_SIZE + 64
        buf = ctypes.create_string_buffer(buf_total)

        log.debug(
            f"[KernelBridge] Receive loop started.  "
            f"buf_total={buf_total}  MSG_SIZE={MSG_SIZE}"
        )

        while self._running:
            try:
                hr = _fltlib.FilterGetMessage(
                    self._port,
                    buf,
                    buf_total,
                    None,   
                )

                if hr != 0:
                    if not self._running:
                        break
                    hresult_code = hr & 0xFFFFFFFF
                    if hresult_code not in (0x800703E3, 0x80070006):
                        log.debug(
                            f"[KernelBridge] FilterGetMessage returned "
                            f"0x{hresult_code:08X}"
                        )
                    time.sleep(0.005)
                    continue

                payload = bytes(buf)[FILTER_MSG_HEADER_SIZE:]
                self._dispatch(payload)
                self._stats["received"] += 1

            except Exception as exc:
                if self._running:
                    log.debug(f"[KernelBridge] Receive error: {exc}")
                    self._stats["errors"] += 1
                    time.sleep(0.01)

        log.debug("[KernelBridge] Receive loop exited.")


    def _dispatch(self, payload: bytes) -> None:
        
        try:
            msg = IRPMessage.from_bytes(payload)
        except Exception as exc:
            log.debug(f"[KernelBridge] Message parse error: {exc}")
            self._stats["errors"] += 1
            return

        log.debug(f"[KernelBridge] {msg}")

        self._dispatch_to_dynamic(msg)

        self._dispatch_to_trap(msg)
        if self._callback:
            try:
                self._callback(msg)
            except Exception as exc:
                log.debug(f"[KernelBridge] Callback error: {exc}")

    def _dispatch_to_dynamic(self, msg: IRPMessage) -> None:
        
        if not self._dynamic:
            return

        op = msg.operation

        if op == RW_OP_DIR_QUERY:
            self._dynamic.inject_irp("dir_query", msg.process_id,
                                     path=msg.file_path)

        elif op == RW_OP_READ:
            self._dynamic.inject_irp("read", msg.process_id,
                                     path=msg.file_path)

        elif op in (RW_OP_WRITE, RW_OP_ENTROPY_SPIKE):
            self._dynamic.inject_irp("write", msg.process_id,
                                     path=msg.file_path)
            if op == RW_OP_ENTROPY_SPIKE or msg.entropy > 7.2:
                with self._dynamic._lock:
                    if msg.process_id in self._dynamic._states:
                        self._dynamic._states[msg.process_id].entropy_spike_count += 1
                        self._dynamic._states[msg.process_id].recompute_score()
                self._stats["entropy_spikes"] += 1
                log.warning(
                    f"[KernelBridge] ENTROPY SPIKE  "
                    f"PID={msg.process_id}  proc={msg.process_name}  "
                    f"entropy={msg.entropy:.2f}  file=...{msg.file_path[-60:]}"
                )

        elif op == RW_OP_RENAME:
            self._dynamic.inject_irp("rename", msg.process_id,
                                     path=msg.file_path,
                                     dst_path=msg.dest_path)
            if msg.is_ransom_extension:
                self._stats["ransom_renames"] += 1
                log.warning(
                    f"[KernelBridge] RANSOM RENAME  "
                    f"PID={msg.process_id}  proc={msg.process_name}  "
                    f"{msg.file_extension!r} -> {msg.dest_extension!r}  "
                    f"...{msg.file_path[-50:]}"
                )

        elif op == RW_OP_DELETE:
            self._dynamic.inject_irp("delete", msg.process_id,
                                     path=msg.file_path)

        elif op == RW_OP_FINGERPRINT:
            self._dynamic.inject_irp("rename", msg.process_id,
                                     path=msg.file_path,
                                     dst_path=msg.dest_path)
            with self._dynamic._lock:
                if msg.process_id in self._dynamic._states:
                    self._dynamic._states[msg.process_id].fingerprint_mismatch += 1
                    self._dynamic._states[msg.process_id].recompute_score()
            self._stats["fp_mismatches"] += 1
            log.warning(
                f"[KernelBridge] FINGERPRINT MISMATCH  "
                f"PID={msg.process_id}  proc={msg.process_name}  "
                f"ext={msg.file_extension!r}  "
                f"file=...{msg.file_path[-50:]}"
            )

        elif op == RW_OP_CREATE and msg.is_target_extension:
            self._dynamic.inject_irp("read", msg.process_id,
                                     path=msg.file_path)

        if msg.fingerprint_mismatch and op not in (RW_OP_FINGERPRINT,):
            with self._dynamic._lock:
                if msg.process_id in self._dynamic._states:
                    self._dynamic._states[msg.process_id].fingerprint_mismatch += 1
                    self._dynamic._states[msg.process_id].recompute_score()
            self._stats["fp_mismatches"] += 1
            log.warning(
                f"[KernelBridge] FINGERPRINT MISMATCH (inline)  "
                f"PID={msg.process_id}  proc={msg.process_name}  "
                f"op={msg.op_name()}  ext={msg.file_extension!r}  "
                f"file=...{msg.file_path[-50:]}"
            )

    def _dispatch_to_trap(self, msg: IRPMessage) -> None:
        
        if not self._trap:
            return

        is_honey_file = (
            hasattr(self._trap, "honey_mgr") and
            bool(msg.file_path) and
            self._trap.honey_mgr.is_honey(msg.file_path)
        )
        is_honey_dest = (
            hasattr(self._trap, "honey_mgr") and
            bool(msg.dest_path) and
            self._trap.honey_mgr.is_honey(msg.dest_path)
        )

        if msg.operation in (RW_OP_WRITE, RW_OP_ENTROPY_SPIKE, RW_OP_CREATE):
            if is_honey_file:
                self._trap.inject_test_event(
                    "honey_file_write",
                    pid=msg.process_id,
                    target=msg.file_path,
                )
                self._stats["honey_hits"] += 1
                log.warning(
                    f"[KernelBridge] HONEY WRITE  "
                    f"PID={msg.process_id}  proc={msg.process_name}  "
                    f"file={msg.file_path}"
                )

        elif msg.operation == RW_OP_RENAME:
            if is_honey_file or is_honey_dest:
                self._trap.inject_test_event(
                    "honey_file_rename",
                    pid=msg.process_id,
                    target=msg.file_path,
                )
                self._stats["honey_hits"] += 1
                log.warning(
                    f"[KernelBridge] HONEY RENAME  "
                    f"PID={msg.process_id}  proc={msg.process_name}  "
                    f"{msg.file_path} -> {msg.dest_path}"
                )

            
            if msg.is_ransom_extension:
                self._trap.inject_test_event(
                    "crypto_api_usage",
                    pid=msg.process_id,
                    target=f"inferred from ransom rename: {msg.dest_extension}",
                )
                log.info(
                    f"[KernelBridge] CRYPTO API (inferred)  "
                    f"PID={msg.process_id}  proc={msg.process_name}  "
                    f"reason=ransom_rename({msg.dest_extension!r})"
                )

        elif msg.operation == RW_OP_DELETE:
            if is_honey_file:
                self._trap.inject_test_event(
                    "honey_file_delete",
                    pid=msg.process_id,
                    target=msg.file_path,
                )
                self._stats["honey_hits"] += 1
                log.warning(
                    f"[KernelBridge] HONEY DELETE  "
                    f"PID={msg.process_id}  proc={msg.process_name}  "
                    f"file={msg.file_path}"
                )

        if msg.operation == RW_OP_ENTROPY_SPIKE or (
            msg.operation == RW_OP_WRITE and msg.entropy > 7.2
        ):
            self._trap.inject_test_event(
                "entropy_spike",
                pid=msg.process_id,
                target=msg.file_path,
            )

        if (msg.operation not in (RW_OP_READ, RW_OP_DIR_QUERY, RW_OP_CREATE) and
                hasattr(self._trap, "honey_mgr")):
            for hdir in self._trap.honey_mgr.honey_dirs:
                if msg.file_path.startswith(hdir):
                    self._trap.inject_test_event(
                        "honey_dir_modified",
                        pid=msg.process_id,
                        target=hdir,
                    )
                    break


    def _send_command(self, command: int, target_pid: int) -> bool:
        
        if not self._port or not FLTLIB_AVAILABLE:
            log.warning("[KernelBridge] _send_command: port not open.")
            return False

        try:
            _fltlib.FilterSendMessage.restype = ctypes.HRESULT
            _fltlib.FilterSendMessage.argtypes = [
                ctypes.c_void_p,                   # hPort
                ctypes.c_void_p,                   # lpInBuffer
                ctypes.c_ulong,                    # dwInBufferSize
                ctypes.c_void_p,                   # lpOutBuffer (NULL)
                ctypes.c_ulong,                    # dwOutBufferSize
                ctypes.POINTER(ctypes.c_ulong),    # lpBytesReturned
            ]

            cmd_bytes = _build_command(command, target_pid)
            cmd_buf   = ctypes.create_string_buffer(cmd_bytes)
            returned  = ctypes.c_ulong(0)

            hr = _fltlib.FilterSendMessage(
                self._port,
                cmd_buf,
                len(cmd_bytes),
                None,   
                0,
                ctypes.byref(returned),
            )

            if hr != 0:
                log.debug(
                    f"[KernelBridge] FilterSendMessage cmd={command} "
                    f"pid={target_pid} HRESULT=0x{hr & 0xFFFFFFFF:08X}"
                )
                return False
            return True

        except Exception as exc:
            log.error(f"[KernelBridge] _send_command error: {exc}")
            return False

    def kill_pid(self, pid: int) -> bool:
        
        log.warning(f"[KernelBridge] Sending KILL_PID command: PID={pid}")
        return self._send_command(RW_CMD_KILL_PID, pid)

    def whitelist_pid(self, pid: int) -> bool:
        
        log.info(f"[KernelBridge] Whitelisting PID={pid} in kernel driver")
        return self._send_command(RW_CMD_WHITELIST_PID, pid)


    def get_driver_stats(self) -> dict:
       
        if not self._port or not FLTLIB_AVAILABLE:
            return {}

        try:
            _fltlib.FilterSendMessage.restype = ctypes.HRESULT
            _fltlib.FilterSendMessage.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_ulong,
                ctypes.c_void_p,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
            ]

            out_buf  = ctypes.create_string_buffer(12)
            returned = ctypes.c_ulong(0)
            cmd_bytes = _build_command(RW_CMD_STATUS, 0)
            cmd_buf   = ctypes.create_string_buffer(cmd_bytes)

            hr = _fltlib.FilterSendMessage(
                self._port,
                cmd_buf, len(cmd_bytes),
                out_buf, 12,
                ctypes.byref(returned),
            )

            if hr == 0 and returned.value >= 12:
                total, suspicious, dropped = struct.unpack("<III", bytes(out_buf[:12]))
                return {
                    "kernel_total_irps":      total,
                    "kernel_suspicious_irps": suspicious,
                    "kernel_dropped_msgs":    dropped,
                    "bridge_received":        self._stats["received"],
                    "bridge_errors":          self._stats["errors"],
                    "bridge_honey_hits":      self._stats["honey_hits"],
                    "bridge_entropy_spikes":  self._stats["entropy_spikes"],
                    "bridge_fp_mismatches":   self._stats["fp_mismatches"],
                    "bridge_ransom_renames":  self._stats["ransom_renames"],
                }

        except Exception as exc:
            log.debug(f"[KernelBridge] get_driver_stats error: {exc}")

        return {}


    @staticmethod
    def is_driver_loaded() -> bool:
        if not FLTLIB_AVAILABLE:
            return False
        try:
            _fltlib.FilterConnectCommunicationPort.restype = ctypes.HRESULT
            _fltlib.FilterConnectCommunicationPort.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_ulong,
                ctypes.c_void_p,
                ctypes.c_ushort,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            test_port = ctypes.c_void_p()
            hr = _fltlib.FilterConnectCommunicationPort(
                RANSOMWALL_PORT_WNAME, 0, None, 0, None,
                ctypes.byref(test_port),
            )
            if hr == 0:
                _fltlib.FilterPortClose(test_port)
                return True
        except Exception:
            pass
        return False

    @property
    def stats(self) -> dict:
        """Return a copy of the bridge-side statistics dictionary."""
        return dict(self._stats)



class RansomWallSystemWithKernel:
    def __init__(self, watch_dirs=None, backup_dir="rw_backup",
                 log_path="ransomwall_main.log"):
        from ransomwall_trap_layer    import TrapLayer
        from ransomwall_dynamic_layer import DynamicEngine
        from backup_layer             import BackupLayer
        from ml_layer                 import MLModel
        from main                     import FeatureAggregator, _setup_logging

        self.log        = _setup_logging(log_path)
        self.trap       = TrapLayer(watch_dirs=watch_dirs, cleanup_on_exit=True)
        self.dynamic    = DynamicEngine(watch_dirs=watch_dirs)
        self.backup     = BackupLayer(backup_dir=backup_dir)
        self.ml         = MLModel()
        self.aggregator = FeatureAggregator()

        self.kernel_bridge = KernelBridge(
            dynamic_engine  = self.dynamic,
            trap_layer      = self.trap,
            on_irp_callback = self._on_kernel_irp,
        )

        self._running    = False
        self._suspicious: set  = set()
        self._classified: dict = {}

    def _on_kernel_irp(self, msg: IRPMessage) -> None:
        if msg.is_ransom_extension or msg.fingerprint_mismatch:
            self.log.warning(
                f"[KERNEL-IRP] {msg.op_name().upper():12}  "
                f"PID={msg.process_id:<6}  "
                f"proc={msg.process_name:<20}  "
                f"entropy={msg.entropy:.2f}  "
                f"file=...{msg.file_path[-60:]}"
            )

    def start(self) -> None:
        self.log.info("[SYSTEM] Starting RansomWall (kernel-mode preferred)...")

        if self.kernel_bridge.start():
            self.log.info(
                "[SYSTEM] *** KERNEL MODE ACTIVE ***\n"
                "         Real IRP interception via RansomWallFilter.sys\n"
                "         Paper §IV-B minifilter driver is running."
            )
            self.trap.honey_mgr.deploy()
            self.trap.behavior.start(interval=2.0)
            self.trap.poller.start()
        else:
            self.log.warning(
                "[SYSTEM] Kernel driver unavailable.  "
                "Falling back to watchdog simulation.\n"
                "         To enable real kernel monitoring:\n"
                "         1. Build: install_driver.bat build\n"
                "         2. Sign:  install_driver.bat testsign (reboot)\n"
                "         3. Install: install_driver.bat install\n"
                "         4. Restart as Administrator"
            )
            self.trap.start()
            self.dynamic.start()

        self._running = True
        self.log.info("[SYSTEM] All layers active.")

    def stop(self) -> None:
        self._running = False
        self.kernel_bridge.stop()
        try:
            self.trap.stop()
        except Exception:
            pass
        try:
            self.dynamic.stop()
        except Exception:
            pass
        self.log.info("[SYSTEM] RansomWall (kernel mode) stopped.")

    def on_ransomware_verdict(self, pid: int) -> None:
        killed = self.kernel_bridge.kill_pid(pid)
        if killed:
            self.log.warning(
                f"[ACTION] PID={pid} KILLED via kernel "
                f"ZwTerminateProcess (unblockable)"
            )
        else:
            self.log.warning(
                f"[ACTION] Kernel kill failed for PID={pid}; "
                f"falling back to user-mode termination"
            )
            try:
                import psutil
                psutil.Process(pid).kill()
            except Exception:
                pass

        restored = self.backup.restore(pid)
        self.log.warning(f"[ACTION] Restored {restored} file(s) for PID={pid}")

    def on_benign_verdict(self, pid: int) -> None:
        self.kernel_bridge.whitelist_pid(pid)
        self.backup.cleanup(pid)

    def print_status(self) -> None:
        stats = self.kernel_bridge.get_driver_stats()
        if stats:
            print(f"\n{'='*55}")
            print("  Kernel Driver Statistics")
            print(f"{'='*55}")
            for k, v in stats.items():
                print(f"  {k:<32}: {v}")
            print(f"{'='*55}\n")
        else:
            print("[KernelBridge] Driver not connected — no stats available.")
