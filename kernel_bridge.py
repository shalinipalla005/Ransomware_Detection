"""
RansomWall: Kernel-Mode Bridge (User-Mode Side)
================================================
Paper §IV-A / §IV-B — COMSNETS 2018

This module replaces the watchdog-based filesystem monitoring in
ransomwall_dynamic_layer.py with a REAL kernel driver connection.

Architecture:
  [Kernel: RansomWallFilter.sys]
      |  (FltSendMessage -> named port \\RansomWallPort)
      v
  [THIS FILE: kernel_bridge.py]   <-- user-mode bridge
      |  (inject_irp / inject_test_event)
      v
  [DynamicEngine / TrapLayer / FeatureCollector]
      |
      v
  [MLModel -> Ransomware/Benign verdict]
      |  (RW_CMD_KILL_PID / RW_CMD_WHITELIST_PID)
      v
  [Kernel: RansomWallFilter.sys] (terminates process)

The kernel driver sends RANSOMWALL_IRP_MESSAGE structs over the
communication port (\\RansomWallPort).  This bridge unpacks them and
calls the appropriate Python layer methods, mirroring the paper's
Figure 2 logical workflow exactly:

  Paper §IV-A:
    "IRP Filter registers with File System I/O Manager during RansomWall
     initialization for receiving IRP messages.  During file operations,
     I/O Manager forwards generated IRP messages to the registered IRP
     Filter.  The IRP Filter forwards IRP messages, which are created for
     file operations on only user data files, to Dynamic and Trap Layers
     for feature computation."

Message struct layout matches RANSOMWALL_IRP_MESSAGE in RansomWallFilter.c
(#pragma pack(1)):

  Offset   Size   Field
  ------   ----   -----
  0        4      MessageSize      (ULONG)
  4        4      Version          (ULONG)
  8        4      ProcessId        (ULONG)
  12       4      ThreadId         (ULONG)
  16       520    ProcessName      (WCHAR[260])
  536      4      Operation        (ULONG / RANSOMWALL_OP_TYPE)
  540      8      Timestamp        (LARGE_INTEGER / INT64)
  548      4      FileSize         (ULONG)
  552      1040   FilePath         (WCHAR[520])
  1592     32     FileExtension    (USHORT[16] -> WCHAR[16])
  1624     1040   DestPath         (WCHAR[520])
  2664     32     DestExtension    (USHORT[16] -> WCHAR[16])
  2696     4      EntropyX100      (ULONG)
  2700     1      IsTargetExtension (BOOLEAN)
  2701     1      IsRansomExtension (BOOLEAN)
  2702     1      FingerprintMismatch (BOOLEAN)
  Total    2703 bytes  (packed)

Requirements:
  - Windows OS with RansomWallFilter.sys loaded and running
  - pip install pywin32
  - Run as Administrator (required to open the filter communication port)

Usage (replaces watchdog in main.py):
  bridge = KernelBridge(dynamic_engine=engine, trap_layer=trap)
  bridge.start()   # connects to kernel driver; begins receiving IRPs
  ...
  bridge.stop()
"""

import ctypes
import struct
import threading
import logging
import time
import os
from typing import Optional, Callable

log = logging.getLogger("RansomWall.KernelBridge")

# ── Win32 imports (optional — only needed at runtime on Windows) ──────────────
try:
    import win32file       # noqa: F401  (imported for side-effects on some builds)
    import win32security   # noqa: F401
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    log.debug("[KernelBridge] pywin32 not installed.  Run: pip install pywin32")

# ── Filter Communication API (fltlib.dll) ─────────────────────────────────────
try:
    _fltlib = ctypes.WinDLL("fltlib.dll")
    FLTLIB_AVAILABLE = True
except (OSError, AttributeError):
    _fltlib = None
    FLTLIB_AVAILABLE = False
    log.warning("[KernelBridge] fltlib.dll not available.  "
                "RansomWallFilter.sys must be installed and running.")


# ════════════════════════════════════════════════════════════════════════════ #
# PROTOCOL CONSTANTS  (must match RansomWallFilter.c exactly)
# ════════════════════════════════════════════════════════════════════════════ #

# Named communication port (paper §IV-A)
RANSOMWALL_PORT_WNAME = "\\RansomWallPort"

# IRP operation types  (mirrors RANSOMWALL_OP_TYPE enum in .c)
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

# Control commands sent FROM user-mode TO kernel driver
RW_CMD_SUSPEND_PID   = 1   # Pause monitoring for a PID
RW_CMD_KILL_PID      = 2   # Request ZwTerminateProcess for a PID
RW_CMD_WHITELIST_PID = 3   # Mark PID as benign; stop sending IRPs for it
RW_CMD_STATUS        = 4   # Query driver statistics


# ════════════════════════════════════════════════════════════════════════════ #
# IRP MESSAGE STRUCT
# Matches RANSOMWALL_IRP_MESSAGE (pragma pack 1) in RansomWallFilter.c
# ════════════════════════════════════════════════════════════════════════════ #

#  Field               C type          Size   Python fmt
#  MessageSize         ULONG           4      I
#  Version             ULONG           4      I
#  ProcessId           ULONG           4      I
#  ThreadId            ULONG           4      I
#  ProcessName         WCHAR[260]      520    520s   (UTF-16-LE)
#  Operation           ULONG           4      I
#  Timestamp           LARGE_INTEGER   8      q
#  FileSize            ULONG           4      I
#  FilePath            WCHAR[520]      1040   1040s  (UTF-16-LE)
#  FileExtension       USHORT[16]      32     32s    (UTF-16-LE, 16 chars)
#  DestPath            WCHAR[520]      1040   1040s  (UTF-16-LE)
#  DestExtension       USHORT[16]      32     32s    (UTF-16-LE, 16 chars)
#  EntropyX100         ULONG           4      I
#  IsTargetExtension   BOOLEAN         1      B
#  IsRansomExtension   BOOLEAN         1      B
#  FingerprintMismatch BOOLEAN         1      B
#  Total (packed)                      2703

MSG_FORMAT = "<IIIi520sIqI1040s32s1040s32sIBBB"
MSG_SIZE   = struct.calcsize(MSG_FORMAT)   # should equal 2703

# FILTER_MESSAGE_HEADER prepended by FltGetMessage:
#   ULONG  ReplyLength  (4)
#   ULONGLONG MessageId (8)
# Total header = 16 bytes (aligned), but the API uses ULONG+ULONGLONG = 12
# In practice WDK aligns it to 8 bytes -> 16 bytes.  We use 16 for safety.
FILTER_MSG_HEADER_SIZE = 16


# ════════════════════════════════════════════════════════════════════════════ #
# PARSED MESSAGE
# ════════════════════════════════════════════════════════════════════════════ #

class IRPMessage:
    """
    Parsed RANSOMWALL_IRP_MESSAGE from the kernel driver.

    Attributes map directly to what DynamicEngine.inject_irp() and
    TrapLayer.inject_test_event() expect (paper §IV-A, Figure 2).
    """
    __slots__ = [
        "message_size", "version", "process_id", "thread_id",
        "process_name", "operation", "timestamp", "file_size",
        "file_path", "file_extension", "dest_path", "dest_extension",
        "entropy_x100", "is_target_extension", "is_ransom_extension",
        "fingerprint_mismatch",
    ]

    @classmethod
    def from_bytes(cls, data: bytes) -> "IRPMessage":
        """Unpack a raw kernel message buffer into an IRPMessage."""
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

    # ── Derived helpers ───────────────────────────────────────────────────────

    def op_name(self) -> str:
        """Human-readable operation name (matches DynamicEngine inject_irp op names)."""
        return OP_NAMES.get(self.operation, "unknown")

    @property
    def entropy(self) -> float:
        """Shannon entropy as a float in [0.0, 8.0]."""
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


# ════════════════════════════════════════════════════════════════════════════ #
# COMMAND STRUCT  (user-mode -> kernel)
# Matches RANSOMWALL_COMMAND in RansomWallFilter.c
#   ULONG Command   (4)
#   ULONG TargetPid (4)
#   WCHAR Reserved[64] (128)
# Total = 136 bytes
# ════════════════════════════════════════════════════════════════════════════ #

CMD_FORMAT = "<II128s"
CMD_SIZE   = struct.calcsize(CMD_FORMAT)


def _build_command(command: int, target_pid: int) -> bytes:
    """Pack a RANSOMWALL_COMMAND for FilterSendMessage."""
    return struct.pack(CMD_FORMAT, command, target_pid, b"\x00" * 128)


# ════════════════════════════════════════════════════════════════════════════ #
# KERNEL BRIDGE
# ════════════════════════════════════════════════════════════════════════════ #

class KernelBridge:
    """
    Connects to the RansomWallFilter.sys kernel minifilter via the Filter
    Manager communication port (\\RansomWallPort).

    Paper §IV-A:
      "IRP Filter registers with File System I/O Manager during RansomWall
       initialization for receiving IRP messages."

    Receives RANSOMWALL_IRP_MESSAGE structs via FilterGetMessage (blocking)
    and dispatches them to:
      • DynamicEngine.inject_irp()         — file I/O counts (§III-D-3 a-e)
      • DynamicEngine state (entropy/fp)    — §III-D-3 f-g
      • TrapLayer.inject_test_event()       — honey-file and behavior features
                                              (§III-D-2 a, b, c, d, e)

    Also sends control commands back to the kernel:
      • kill_pid(pid)       → RW_CMD_KILL_PID      (ZwTerminateProcess)
      • whitelist_pid(pid)  → RW_CMD_WHITELIST_PID
    """

    def __init__(self,
                 dynamic_engine=None,
                 trap_layer=None,
                 on_irp_callback: Optional[Callable] = None):
        """
        Args:
          dynamic_engine:   ransomwall_dynamic_layer.DynamicEngine instance
          trap_layer:       ransomwall_trap_layer.TrapLayer instance
          on_irp_callback:  optional extra per-IRP callback(IRPMessage)
        """
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

    # ════════════════════════════════════════════════════════════════════════ #
    # LIFECYCLE
    # ════════════════════════════════════════════════════════════════════════ #

    def start(self) -> bool:
        """
        Connect to the kernel driver's communication port and start the
        IRP receive thread.

        Returns True on success; False if the driver is not loaded,
        fltlib.dll is unavailable, or we are not on Windows.
        """
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
        """Disconnect from the kernel driver and shut down the receive thread."""
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

    # ════════════════════════════════════════════════════════════════════════ #
    # CONNECTION  (FilterConnectCommunicationPort)
    # ════════════════════════════════════════════════════════════════════════ #

    def _connect(self) -> bool:
        """
        Open a handle to the kernel driver's communication port using
        FilterConnectCommunicationPort (fltlib.dll).

        This is the user-mode counterpart of FltCreateCommunicationPort
        called by the kernel driver during DriverEntry.

        HRESULT FilterConnectCommunicationPort(
            LPCWSTR                  lpPortName,
            DWORD                    dwOptions,
            LPCVOID                  lpContext,
            WORD                     wSizeOfContext,
            LPSECURITY_ATTRIBUTES    lpSecurityAttributes,
            HANDLE*                  hPort
        );
        """
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

    # ════════════════════════════════════════════════════════════════════════ #
    # IRP RECEIVE LOOP  (FilterGetMessage)
    # Paper §IV-A: blocking receive of kernel IRP messages
    # ════════════════════════════════════════════════════════════════════════ #

    def _receive_loop(self):
        """
        Continuously receive RANSOMWALL_IRP_MESSAGE structs from the kernel
        driver using FilterGetMessage (synchronous / blocking).

        Paper §IV-A:
          "File System activities are monitored by analyzing IRPs (I/O Request
           Packets) which are generated for each file operation.  IRP Filter
           registers with File System I/O Manager during RansomWall
           initialization for receiving IRP messages."

        The FILTER_MESSAGE_HEADER (16 bytes) is prepended by the Filter
        Manager and must be skipped to reach the RANSOMWALL_IRP_MESSAGE payload.

        HRESULT FilterGetMessage(
            HANDLE                  hPort,
            PFILTER_MESSAGE_HEADER  lpMessageBuffer,
            DWORD                   dwMessageBufferSize,
            LPOVERLAPPED            lpOverlapped     <- NULL = synchronous
        );
        """
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

        # Allocate receive buffer: FILTER_MESSAGE_HEADER + IRP payload + headroom
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
                    None,   # synchronous — blocks until the kernel sends a message
                )

                if hr != 0:
                    if not self._running:
                        break
                    # ERROR_OPERATION_ABORTED (0x800703E3) is normal on close
                    hresult_code = hr & 0xFFFFFFFF
                    if hresult_code not in (0x800703E3, 0x80070006):
                        log.debug(
                            f"[KernelBridge] FilterGetMessage returned "
                            f"0x{hresult_code:08X}"
                        )
                    time.sleep(0.005)
                    continue

                # Strip the FILTER_MESSAGE_HEADER to get the IRP payload
                payload = bytes(buf)[FILTER_MSG_HEADER_SIZE:]
                self._dispatch(payload)
                self._stats["received"] += 1

            except Exception as exc:
                if self._running:
                    log.debug(f"[KernelBridge] Receive error: {exc}")
                    self._stats["errors"] += 1
                    time.sleep(0.01)

        log.debug("[KernelBridge] Receive loop exited.")

    # ════════════════════════════════════════════════════════════════════════ #
    # IRP DISPATCH  (kernel -> Python layer routing)
    # Paper §IV-A Figure 2: "IRP Filter forwards IRP messages ... to Dynamic
    # and Trap Layers for feature computation."
    # ════════════════════════════════════════════════════════════════════════ #

    def _dispatch(self, payload: bytes) -> None:
        """
        Parse the raw payload into an IRPMessage and route it to the
        appropriate Python layer method.

        Routing table (paper §III-D):
          §III-D-3 a  dir_query count        → DynamicEngine "dir_query"
          §III-D-3 b  file_read count         → DynamicEngine "read"
          §III-D-3 c  file_write count        → DynamicEngine "write"
          §III-D-3 d  rename (data→non-data)  → DynamicEngine "rename"
          §III-D-3 e  file_delete count        → DynamicEngine "delete"
          §III-D-3 f  fingerprint mismatch     → DynamicEngine "rename" +
                                                  TrapLayer (if honey file)
          §III-D-3 g  entropy spike            → DynamicEngine "write"  +
                                                  TrapLayer entropy_spike
          §III-D-2 a  honey file write/rename/delete → TrapLayer
          §III-D-2 b  crypto API (ransom rename)     → TrapLayer
        """
        try:
            msg = IRPMessage.from_bytes(payload)
        except Exception as exc:
            log.debug(f"[KernelBridge] Message parse error: {exc}")
            self._stats["errors"] += 1
            return

        log.debug(f"[KernelBridge] {msg}")

        # ── Step 1: Route to DynamicEngine (paper §III-D-3) ──────────────────
        self._dispatch_to_dynamic(msg)

        # ── Step 2: Route to TrapLayer (paper §III-D-2) ──────────────────────
        self._dispatch_to_trap(msg)

        # ── Step 3: Optional caller-supplied callback ─────────────────────────
        if self._callback:
            try:
                self._callback(msg)
            except Exception as exc:
                log.debug(f"[KernelBridge] Callback error: {exc}")

    def _dispatch_to_dynamic(self, msg: IRPMessage) -> None:
        """
        Forward the IRP to DynamicEngine.inject_irp() for IRP count and
        derived feature computation.

        Paper §III-D-3: Read, Write, Rename, Delete, Dir-query counts;
        fingerprint-mismatch and entropy-spike flags.
        """
        if not self._dynamic:
            return

        op = msg.operation

        # §III-D-3 a — Directory listing queries
        if op == RW_OP_DIR_QUERY:
            self._dynamic.inject_irp("dir_query", msg.process_id,
                                     path=msg.file_path)

        # §III-D-3 b — File reads
        elif op == RW_OP_READ:
            self._dynamic.inject_irp("read", msg.process_id,
                                     path=msg.file_path)

        # §III-D-3 c / g — File writes (+ entropy spike check by kernel)
        elif op in (RW_OP_WRITE, RW_OP_ENTROPY_SPIKE):
            self._dynamic.inject_irp("write", msg.process_id,
                                     path=msg.file_path)
            if op == RW_OP_ENTROPY_SPIKE or msg.entropy > 7.2:
                # Kernel already computed the entropy; mark entropy spike
                # directly on the ProcessState without re-reading the file.
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

        # §III-D-3 d — File rename (data → non-data extension)
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

        # §III-D-3 e — File deletes
        elif op == RW_OP_DELETE:
            self._dynamic.inject_irp("delete", msg.process_id,
                                     path=msg.file_path)

        # §III-D-3 f — Fingerprint / magic-byte mismatch reported by kernel
        elif op == RW_OP_FINGERPRINT:
            # Treat as a rename-like event so rename_count is incremented
            self._dynamic.inject_irp("rename", msg.process_id,
                                     path=msg.file_path,
                                     dst_path=msg.dest_path)
            # Also directly increment the fingerprint_mismatch counter
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

        # §III-D-3 — IRP_MJ_CREATE: track as a read (file opened for access)
        elif op == RW_OP_CREATE and msg.is_target_extension:
            self._dynamic.inject_irp("read", msg.process_id,
                                     path=msg.file_path)

        # Also record inline fingerprint_mismatch flag on any IRP type
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
        """
        Forward the IRP to TrapLayer for honey-file and behavioral-trap
        feature recording.

        Paper §III-D-2:
          a. Honey file/directory modification (write, rename, delete)
          b. Suspicious Windows Crypto API usage  (inferred from ransom rename)
          c. Disabling safe-mode boot (bcdedit)   — handled by BehaviorDetector
          d. Deletion of Volume Shadow Copies      — handled by BehaviorDetector
          e. Suspicious Registry modifications     — handled by BehaviorDetector

        The kernel driver can directly identify honey files because the user-
        mode bridge told it which paths to watch (via the communication port
        at startup).  When the driver sets IsTargetExtension=TRUE and the
        path matches a honey file, we fire the appropriate trap feature.
        """
        if not self._trap:
            return

        # Determine whether this path touches a honey file / honey directory
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

        # §III-D-2 a  — Honey file WRITE (paper: "Write … operations on Honey
        #               Files/Directories are tracked for malicious activities")
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

        # §III-D-2 a  — Honey file RENAME
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

            # §III-D-2 b  — Ransomware-extension rename implies Crypto API use
            # "Most Ransomware variants use standard Windows Cryptographic APIs
            #  for encryption.  Massive use of these APIs can be considered
            #  suspicious." (paper §III-D-2b)
            # The kernel cannot easily detect DLL loads, but a rename to a
            # known ransomware extension strongly implies encryption was just
            # performed using a Crypto API.
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

        # §III-D-2 a  — Honey file DELETE
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

        # §III-D-3 g / §III-D-2 — Entropy spike also fires trap entropy_spike
        # "Entropy of data buffer in memory modified during file write operation
        #  to a value around 8 indicates encryption possibility." (§III-D-3g)
        if msg.operation == RW_OP_ENTROPY_SPIKE or (
            msg.operation == RW_OP_WRITE and msg.entropy > 7.2
        ):
            self._trap.inject_test_event(
                "entropy_spike",
                pid=msg.process_id,
                target=msg.file_path,
            )

        # Honey directory modification (any non-read IRP inside honey dir)
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

    # ════════════════════════════════════════════════════════════════════════ #
    # CONTROL COMMANDS (user-mode -> kernel)
    # ════════════════════════════════════════════════════════════════════════ #

    def _send_command(self, command: int, target_pid: int) -> bool:
        """
        Send a RANSOMWALL_COMMAND to the kernel driver via FilterSendMessage.

        Paper §IV-A: Used to trigger ZwTerminateProcess (kill) or to
        whitelist a benign PID so the driver stops sending IRPs for it.

        HRESULT FilterSendMessage(
            HANDLE  hPort,
            LPVOID  lpInBuffer,
            DWORD   dwInBufferSize,
            LPVOID  lpOutBuffer,
            DWORD   dwOutBufferSize,
            LPDWORD lpBytesReturned
        );
        """
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
                None,   # no response buffer required
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
        """
        Request the kernel driver to terminate a ransomware process via
        ZwTerminateProcess — a kernel-level kill that cannot be intercepted
        or blocked by user-mode hooks in the ransomware itself.

        Paper §III-B-4:
          "If Machine Learning layer classifies as Ransomware, the process
           is killed and files modified by it are restored."
        """
        log.warning(f"[KernelBridge] Sending KILL_PID command: PID={pid}")
        return self._send_command(RW_CMD_KILL_PID, pid)

    def whitelist_pid(self, pid: int) -> bool:
        """
        Tell the kernel driver to stop monitoring a process that the ML
        layer has classified as benign.  The driver will remove the PID
        from its active tracking set and stop sending IRPs for it.

        Paper §III-B-4:
          "If classified as Benign then files backed up due to the suspicious
           process are deleted."
        """
        log.info(f"[KernelBridge] Whitelisting PID={pid} in kernel driver")
        return self._send_command(RW_CMD_WHITELIST_PID, pid)

    # ════════════════════════════════════════════════════════════════════════ #
    # DRIVER STATISTICS
    # ════════════════════════════════════════════════════════════════════════ #

    def get_driver_stats(self) -> dict:
        """
        Query the kernel driver for its internal statistics counters:
          - Total IRPs intercepted
          - Suspicious IRP count
          - Dropped (queue-full) messages

        These are stored in the driver's g_TotalIRPs / g_SuspiciousIRPs /
        g_DroppedMessages volatile counters (see RansomWallFilter.c).

        Paper §V-G: "Feature values computation and collection for normal
        processes add less than 1% CPU Load."
        """
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

            # Driver returns 3 × ULONG = 12 bytes
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

    # ════════════════════════════════════════════════════════════════════════ #
    # UTILITY
    # ════════════════════════════════════════════════════════════════════════ #

    @staticmethod
    def is_driver_loaded() -> bool:
        """
        Check whether RansomWallFilter.sys is currently loaded by attempting
        to open the communication port.  Closes the port immediately if
        successful.  Returns True if the driver is running, False otherwise.
        """
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


# ════════════════════════════════════════════════════════════════════════════ #
# CONVENIENCE WRAPPER — drop-in for main.py
# ════════════════════════════════════════════════════════════════════════════ #

class RansomWallSystemWithKernel:
    """
    Drop-in replacement for RansomWallSystem (main.py) that uses the real
    kernel driver instead of watchdog when available.

    Usage in main.py or kernel_main.py:
      from kernel_bridge import RansomWallSystemWithKernel as RansomWallSystem

    The KernelBridge replaces:
      - watchdog.observers.Observer  (dynamic layer filesystem monitoring)
      - TrapEventHandler             (trap layer watchdog handler)
    with a direct connection to the RansomWallFilter.sys minifilter driver.

    When the driver is not loaded the system falls back transparently to the
    standard watchdog-based operation.
    """

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
        """
        Per-IRP callback for high-value events — provides the real-time
        trace logging described in paper §V evaluation (Section V-B debug
        traces collected per process).
        """
        if msg.is_ransom_extension or msg.fingerprint_mismatch:
            self.log.warning(
                f"[KERNEL-IRP] {msg.op_name().upper():12}  "
                f"PID={msg.process_id:<6}  "
                f"proc={msg.process_name:<20}  "
                f"entropy={msg.entropy:.2f}  "
                f"file=...{msg.file_path[-60:]}"
            )

    def start(self) -> None:
        """
        Start the system.  Tries the kernel bridge first; falls back to
        the watchdog-based simulation if the driver is not loaded.
        """
        self.log.info("[SYSTEM] Starting RansomWall (kernel-mode preferred)...")

        if self.kernel_bridge.start():
            self.log.info(
                "[SYSTEM] *** KERNEL MODE ACTIVE ***\n"
                "         Real IRP interception via RansomWallFilter.sys\n"
                "         Paper §IV-B minifilter driver is running."
            )
            # Honey files are still deployed by TrapLayer subsystems
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
        """Graceful shutdown of all layers."""
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
        """
        Paper §III-B-4: "If ML layer classifies as Ransomware:
          → process is killed (kernel-level ZwTerminateProcess)
          → files modified by it are restored to their original locations"
        """
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
        """
        Paper §III-B-4: "If classified as Benign then files backed up due
        to the suspicious process are deleted."
        Also tells the kernel driver to stop monitoring this PID.
        """
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
