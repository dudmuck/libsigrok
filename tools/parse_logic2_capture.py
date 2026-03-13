#!/usr/bin/env python3
"""
Parse a pcap file captured with tcpdump from usbmon to decode
Saleae Logic 8 (FX2, VID:PID 21a9:1004) USB commands.

Usage:
    tcpdump -i usbmon1 -w capture.pcap
    python3 parse_logic2_capture.py capture.pcap [--device-num N]
"""

import argparse
import struct
import sys
from collections import defaultdict

# LFSR cipher for Saleae Logic 8 (FX2)
FX2_INITIAL_LFSR = 0x354b248e

# Command IDs
CMD_START_CAPTURE  = 0x01
CMD_STOP_CAPTURE   = 0x02
CMD_READ_EEPROM    = 0x07
CMD_CLOCK_CONFIG   = 0x7b
CMD_FPGA_STATUS    = 0x7d
CMD_INIT_BITSTREAM = 0x7e
CMD_SEND_BITSTREAM = 0x7f
CMD_WRITE_REG      = 0x80
CMD_READ_REG       = 0x81
CMD_READ_TEMP      = 0x86
CMD_WRITE_I2C      = 0x87
CMD_READ_I2C       = 0x88
CMD_WAKE_I2C       = 0x89
CMD_READ_FW_VER    = 0x8b

CMD_NAMES = {
    CMD_START_CAPTURE:  "START_CAPTURE",
    CMD_STOP_CAPTURE:   "STOP_CAPTURE",
    CMD_READ_EEPROM:    "READ_EEPROM",
    CMD_CLOCK_CONFIG:   "CLOCK_CONFIG",
    CMD_FPGA_STATUS:    "FPGA_STATUS",
    CMD_INIT_BITSTREAM: "INIT_BITSTREAM",
    CMD_SEND_BITSTREAM: "SEND_BITSTREAM",
    CMD_WRITE_REG:      "WRITE_REG",
    CMD_READ_REG:       "READ_REG",
    CMD_READ_TEMP:      "READ_TEMP",
    CMD_WRITE_I2C:      "WRITE_I2C",
    CMD_READ_I2C:       "READ_I2C",
    CMD_WAKE_I2C:       "WAKE_I2C",
    CMD_READ_FW_VER:    "READ_FW_VER",
}

# Known FPGA register names
FPGA_REG_NAMES = {
    0x00: "control",
    0x03: "adc_idx",
    0x04: "adc_val_lsb",
    0x05: "adc_val_msb",
    0x06: "dig_ch_mask",
    0x08: "ana_ch_mask",
    0x0b: "samplerate_div",
    0x0d: "serial_data_ratio",
    0x0e: "mode",
    0x0f: "led_red",
    0x10: "led_green",
    0x11: "led_blue",
    0x13: "streaming_cfg",
    0x14: "clock_prediv",
    0x40: "status",
    0x7f: "fpga_id",
}

# Commands that have NO ack response on FX2
FX2_NO_ACK_CMDS = {CMD_WRITE_REG, CMD_INIT_BITSTREAM, CMD_START_CAPTURE, CMD_STOP_CAPTURE}


def iterate_lfsr(lfsr):
    """Iterate the LFSR cipher state."""
    max_iter = (lfsr & 0x1f) + 34
    for _ in range(max_iter + 1):
        feedback = (lfsr ^ (lfsr >> 1) ^ (lfsr >> 21) ^ (lfsr >> 31)) & 1
        lfsr = ((lfsr >> 1) | (feedback << 31)) & 0xffffffff
    return lfsr


def decrypt_data(data, lfsr):
    """Decrypt data using XOR with LFSR bytes. Returns (decrypted, new_lfsr)."""
    out = bytearray(len(data))
    for i in range(len(data)):
        mask = (lfsr >> ((i % 4) * 8)) & 0xff
        out[i] = data[i] ^ mask
    return bytes(out), iterate_lfsr(lfsr)


def decrypt_command(data, lfsr):
    """
    Decrypt an outgoing command (encrypt direction).
    Byte 0: bits in 0x28 are cleartext, other bits are XORed.
    Other bytes: plain XOR.
    Returns (decrypted, new_lfsr).
    """
    out = bytearray(len(data))
    for i in range(len(data)):
        mask = (lfsr >> ((i % 4) * 8)) & 0xff
        if i == 0:
            # Reverse the encrypt: cleartext bits are in 0x28,
            # other bits were XORed
            out[i] = (data[i] & 0x28) | ((data[i] ^ mask) & ~0x28)
        else:
            out[i] = data[i] ^ mask
    return bytes(out), iterate_lfsr(lfsr)


def format_reg_write(addr, val):
    """Format a register write with annotation."""
    name = FPGA_REG_NAMES.get(addr)
    if 0x1c <= addr <= 0x30:
        name = "i2c_master"
    s = f"0x{addr:02x}=0x{val:02x}"
    if name:
        s += f" ({name})"
    # Extra annotation for well-known registers
    if addr == 0x00:
        parts = []
        if val & 0x01:
            parts.append("data_en")
        if val & 0x04:
            parts.append("adc_reset")
        if val & 0x08:
            parts.append("serdes_reset")
        if parts:
            s += f" [{' | '.join(parts)}]"
    elif addr == 0x0e:
        if val == 0:
            s += " [raw parallel]"
        else:
            s += " [serial mode]"
    elif addr == 0x13:
        parts = []
        if val & 0x01:
            parts.append("counter_mode")
        if val & 0x02:
            parts.append("continuous")
        if parts:
            s += f" [{' | '.join(parts)}]"
    return s


def format_reg_read(addr):
    """Format a register read address with annotation."""
    name = FPGA_REG_NAMES.get(addr)
    if 0x1c <= addr <= 0x30:
        name = "i2c_master"
    s = f"0x{addr:02x}"
    if name:
        s += f" ({name})"
    return s


class LfsrState:
    """Track LFSR state through the protocol."""

    def __init__(self):
        self.lfsr = FX2_INITIAL_LFSR
        self.pending_reads = {}  # urb_id -> (cmd_byte, extra_info, expected_rsp_len)
        self.pkt_num = 0
        self.bitstream_bytes = 0
        self.in_bitstream = False

    def handle_out(self, data, pkt_num):
        """Process an OUT (host->device) bulk transfer on EP 0x01."""
        self.pkt_num = pkt_num
        if len(data) < 2:
            print(f"  [{pkt_num}] OUT: too short ({len(data)} bytes)")
            return None

        raw_byte0 = data[0]

        # Check for bitstream upload (byte 0 bit 3 set, unencrypted)
        if raw_byte0 & 0x08:
            cmd = data[1] if len(data) > 1 else 0
            if cmd == CMD_SEND_BITSTREAM:
                bs_len = data[2] if len(data) > 2 else 0
                self.bitstream_bytes += bs_len
                if not self.in_bitstream:
                    self.in_bitstream = True
                    print(f"  [{pkt_num}] SEND_BITSTREAM (unencrypted, starting upload...)")
                # No LFSR change, no ack
                return "bitstream"
            else:
                print(f"  [{pkt_num}] OUT: bit3 set, cmd=0x{cmd:02x}, {len(data)} bytes (unencrypted)")
                return None

        # Decrypt the command
        decrypted, new_lfsr = decrypt_command(data, self.lfsr)

        # If we were in bitstream mode, print summary
        if self.in_bitstream:
            print(f"           ... bitstream upload complete: {self.bitstream_bytes} bytes total")
            self.in_bitstream = False
            self.bitstream_bytes = 0

        byte0 = decrypted[0]

        # Check for reseed (byte 0 bit 5 set = 0x20)
        if byte0 == 0x20:
            self.lfsr = new_lfsr
            # FX2 rebuilds LFSR from decoded payload bytes 1-4 as LE uint32
            if len(decrypted) >= 5:
                new_seed = struct.unpack_from('<I', decrypted, 1)[0]
                print(f"  [{pkt_num}] RESEED: payload={decrypted[1:5].hex()}"
                      f" -> new LFSR=0x{new_seed:08x}")
                self.lfsr = new_seed
            else:
                print(f"  [{pkt_num}] RESEED: (short payload)")
            return "reseed"

        cmd = decrypted[1]
        cmd_name = CMD_NAMES.get(cmd, f"UNKNOWN(0x{cmd:02x})")
        self.lfsr = new_lfsr

        # Decode based on command type
        if cmd == CMD_WRITE_REG:
            cnt = decrypted[2] if len(decrypted) > 2 else 0
            pairs = []
            adc_idx = None
            adc_val_lsb = None
            adc_val_msb = None
            for i in range(cnt):
                off = 3 + 2 * i
                if off + 1 < len(decrypted):
                    addr = decrypted[off]
                    val = decrypted[off + 1]
                    pairs.append((addr, val))
                    # Track ADC writes
                    if addr == 0x03:
                        adc_idx = val
                    elif addr == 0x04:
                        adc_val_lsb = val
                    elif addr == 0x05:
                        adc_val_msb = val
            reg_strs = [format_reg_write(a, v) for a, v in pairs]
            print(f"  [{pkt_num}] WRITE_REG ({cnt}): {', '.join(reg_strs)}")
            # If we have a complete ADC write sequence, annotate it
            if adc_idx is not None and adc_val_lsb is not None and adc_val_msb is not None:
                adc_val = adc_val_lsb | (adc_val_msb << 8)
                print(f"           -> write_adc(0x{adc_idx:02x}, 0x{adc_val:04x})")
            # No ack on FX2
            return "no_ack"

        elif cmd == CMD_READ_REG:
            cnt = decrypted[2] if len(decrypted) > 2 else 0
            addrs = []
            for i in range(cnt):
                off = 3 + i
                if off < len(decrypted):
                    addrs.append(decrypted[off])
            addr_strs = [format_reg_read(a) for a in addrs]
            print(f"  [{pkt_num}] READ_REG ({cnt}): [{', '.join(addr_strs)}]")
            return ("read_reg", addrs, cnt)

        elif cmd == CMD_READ_EEPROM:
            if len(decrypted) >= 6:
                i2c_addr = decrypted[2]
                i2c_flags = decrypted[3]
                ee_addr = decrypted[4]
                ee_len = decrypted[5]
                print(f"  [{pkt_num}] READ_EEPROM: i2c=0x{i2c_addr:02x}"
                      f" flags=0x{i2c_flags:02x}"
                      f" addr=0x{ee_addr:02x} len={ee_len}")
                return ("read_eeprom", ee_len)
            else:
                print(f"  [{pkt_num}] READ_EEPROM: {decrypted.hex()}")
                return ("read_eeprom", 0)

        elif cmd == CMD_READ_TEMP:
            print(f"  [{pkt_num}] READ_TEMP")
            return ("read_temp", 2)  # FX2 returns 2 bytes

        elif cmd == CMD_READ_FW_VER:
            print(f"  [{pkt_num}] READ_FW_VER")
            return ("read_fw_ver", 128)

        elif cmd == CMD_INIT_BITSTREAM:
            print(f"  [{pkt_num}] INIT_BITSTREAM")
            return "no_ack"

        elif cmd == CMD_SEND_BITSTREAM:
            # Encrypted bitstream (FX3 path); shouldn't happen for FX2
            bs_len = decrypted[2] | (decrypted[3] << 8) if len(decrypted) >= 4 else 0
            print(f"  [{pkt_num}] SEND_BITSTREAM (encrypted): {bs_len} bytes")
            return ("send_bitstream_enc", 1)

        elif cmd == CMD_START_CAPTURE:
            print(f"  [{pkt_num}] START_CAPTURE")
            return "no_ack"

        elif cmd == CMD_STOP_CAPTURE:
            print(f"  [{pkt_num}] STOP_CAPTURE")
            return "no_ack"

        elif cmd == CMD_WRITE_I2C:
            i2c_addr = decrypted[2] if len(decrypted) > 2 else 0
            i2c_len = decrypted[3] if len(decrypted) > 3 else 0
            payload = decrypted[5:5 + i2c_len] if len(decrypted) >= 5 + i2c_len else b''
            print(f"  [{pkt_num}] WRITE_I2C: addr=0x{i2c_addr:02x}"
                  f" len={i2c_len} data={payload.hex()}")
            return ("write_i2c", 1)

        elif cmd == CMD_READ_I2C:
            i2c_addr = decrypted[2] if len(decrypted) > 2 else 0
            i2c_len = decrypted[3] if len(decrypted) > 3 else 0
            print(f"  [{pkt_num}] READ_I2C: addr=0x{i2c_addr:02x} len={i2c_len}")
            return ("read_i2c", 1 + i2c_len)

        elif cmd == CMD_WAKE_I2C:
            print(f"  [{pkt_num}] WAKE_I2C")
            return ("wake_i2c", 1)

        elif cmd == CMD_FPGA_STATUS:
            extra = decrypted[2] if len(decrypted) > 2 else 0
            print(f"  [{pkt_num}] FPGA_STATUS (arg=0x{extra:02x})")
            return ("fpga_status", 1)

        elif cmd == CMD_CLOCK_CONFIG:
            print(f"  [{pkt_num}] CLOCK_CONFIG: {decrypted[2:].hex()}")
            return ("clock_config", 1)

        else:
            print(f"  [{pkt_num}] {cmd_name}: {decrypted.hex()}")
            # Assume unknown read commands get a response (heuristic)
            if cmd >= 0x80:
                return ("unknown_read", 1)
            return "no_ack"

    def handle_in(self, data, pkt_num, cmd_info):
        """Process an IN (device->host) bulk transfer on EP 0x81."""
        if cmd_info is None:
            # Capture data or unmatched response
            if len(data) > 16:
                print(f"  [{pkt_num}] IN: capture data ({len(data)} bytes)")
            else:
                print(f"  [{pkt_num}] IN: unexpected response ({len(data)} bytes): {data.hex()}")
            return

        decrypted, new_lfsr = decrypt_data(data, self.lfsr)
        self.lfsr = new_lfsr

        if isinstance(cmd_info, tuple):
            kind = cmd_info[0]
            if kind == "read_reg":
                addrs = cmd_info[1]
                vals = []
                for i in range(min(len(decrypted), len(addrs))):
                    vals.append((addrs[i], decrypted[i]))
                reg_strs = [format_reg_write(a, v) for a, v in vals]
                print(f"  [{pkt_num}]   -> READ_REG response: {', '.join(reg_strs)}")
            elif kind == "read_eeprom":
                print(f"  [{pkt_num}]   -> READ_EEPROM response ({len(decrypted)} bytes):"
                      f" {decrypted.hex()}")
            elif kind == "read_temp":
                if len(decrypted) >= 1:
                    temp = struct.unpack('b', decrypted[0:1])[0]
                    print(f"  [{pkt_num}]   -> READ_TEMP response: {temp} C"
                          f" (raw: {decrypted.hex()})")
            elif kind == "read_fw_ver":
                try:
                    ver = decrypted.rstrip(b'\x00').decode('ascii', errors='replace')
                except Exception:
                    ver = decrypted.hex()
                print(f"  [{pkt_num}]   -> READ_FW_VER response: \"{ver}\"")
            elif kind == "fpga_status":
                val = decrypted[0] if len(decrypted) >= 1 else 0
                status = "configured" if val == 0xaa else f"0x{val:02x}"
                print(f"  [{pkt_num}]   -> FPGA_STATUS response: {status}")
            elif kind == "write_i2c":
                val = decrypted[0] if len(decrypted) >= 1 else 0
                ok = "OK" if val == 0x02 else f"0x{val:02x}"
                print(f"  [{pkt_num}]   -> WRITE_I2C response: {ok}")
            elif kind == "read_i2c":
                print(f"  [{pkt_num}]   -> READ_I2C response ({len(decrypted)} bytes):"
                      f" {decrypted.hex()}")
            elif kind == "wake_i2c":
                val = decrypted[0] if len(decrypted) >= 1 else 0
                print(f"  [{pkt_num}]   -> WAKE_I2C response: 0x{val:02x}")
            elif kind == "clock_config":
                print(f"  [{pkt_num}]   -> CLOCK_CONFIG response: {decrypted.hex()}")
            elif kind == "send_bitstream_enc":
                val = decrypted[0] if len(decrypted) >= 1 else 0
                print(f"  [{pkt_num}]   -> SEND_BITSTREAM response: 0x{val:02x}")
            else:
                print(f"  [{pkt_num}]   -> response ({len(decrypted)} bytes): {decrypted.hex()}")
        else:
            print(f"  [{pkt_num}]   -> response ({len(decrypted)} bytes): {decrypted.hex()}")


def detect_header_size(f, file_header_size):
    """Detect usbmon pcap header size (48 or 64 bytes) by examining packets."""
    pos = f.tell()
    # Read first packet header to check
    pkt_hdr = f.read(16)
    if len(pkt_hdr) < 16:
        f.seek(pos)
        return 48  # default

    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_hdr)

    # Read enough data to inspect the URB header
    remaining = f.read(incl_len)
    f.seek(pos)

    if len(remaining) < 48:
        return 48

    # In 48-byte format, bytes 36-39 = data length
    # In 64-byte format, bytes 36-39 = data length, extra 16 bytes before data
    # Try 48-byte: check if data_len + 48 == incl_len or close
    data_len_48 = struct.unpack_from('<i', remaining, 36)[0]
    if data_len_48 >= 0 and (48 + data_len_48) == incl_len:
        return 48

    # Try 64-byte
    if incl_len >= 64:
        data_len_64 = struct.unpack_from('<i', remaining, 36)[0]
        if data_len_64 >= 0 and (64 + data_len_64) == incl_len:
            return 64

    # Default to 48 and let parsing figure it out
    return 48


def parse_pcap(filename, device_filter=None):
    """Parse a pcap file and decode Saleae Logic 8 FX2 commands."""
    with open(filename, 'rb') as f:
        # Read pcap global header (24 bytes)
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            print("Error: file too short for pcap header", file=sys.stderr)
            sys.exit(1)

        magic = struct.unpack_from('<I', global_hdr, 0)[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            print(f"Error: not a pcap file (magic=0x{magic:08x})", file=sys.stderr)
            sys.exit(1)

        ver_major, ver_minor = struct.unpack_from(endian + 'HH', global_hdr, 4)
        snaplen = struct.unpack_from(endian + 'I', global_hdr, 16)[0]
        link_type = struct.unpack_from(endian + 'I', global_hdr, 20)[0]

        # link_type: 220 = LINKTYPE_USB_LINUX (48-byte), 249 = LINKTYPE_USB_LINUX_MMAPPED (64-byte)
        if link_type == 249:
            urb_hdr_size = 64
        elif link_type == 220:
            urb_hdr_size = 48
        else:
            # Try to auto-detect
            urb_hdr_size = detect_header_size(f, 24)
            print(f"Warning: link type {link_type}, auto-detected URB header size: {urb_hdr_size}",
                  file=sys.stderr)

        print(f"pcap v{ver_major}.{ver_minor}, link_type={link_type}, "
              f"urb_header={urb_hdr_size} bytes")

        state = LfsrState()

        # Track pending OUT commands by URB ID for matching with IN responses
        # For FX2, we track command info to associate with the next IN response
        pending_cmd_info = None  # Info about the last command that expects a response
        # URB tracking: submit/complete matching
        urb_submit_data = {}  # urb_id -> data (for OUT submits)
        urb_pending_in = {}   # urb_id -> True (for IN submits, waiting for complete)

        pkt_num = 0
        devices_seen = set()

        while True:
            # Read packet header (16 bytes)
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', pkt_hdr)

            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            pkt_num += 1

            if len(pkt_data) < urb_hdr_size:
                continue

            # Parse URB header
            urb_id = struct.unpack_from('<Q', pkt_data, 0)[0]
            event_type = chr(pkt_data[8])  # 'S' = submit, 'C' = complete
            xfer_type = pkt_data[9]        # 0x03 = bulk
            endpoint = pkt_data[10]        # bit 7 = direction (1=IN)
            devnum = pkt_data[11]
            busnum = struct.unpack_from('<H', pkt_data, 12)[0]
            data_len = struct.unpack_from('<i', pkt_data, 36)[0]

            # Only bulk transfers
            if xfer_type != 0x03:
                continue

            ep_num = endpoint & 0x7f
            ep_dir_in = bool(endpoint & 0x80)

            # Filter by device
            if device_filter is not None and devnum != device_filter:
                continue

            devices_seen.add(devnum)

            # Filter for our endpoints: 0x01 (OUT) and 0x81 (IN)
            if ep_num != 1:
                continue

            # Extract payload data
            payload = pkt_data[urb_hdr_size:urb_hdr_size + max(0, data_len)] if data_len > 0 else b''

            if event_type == 'S' and not ep_dir_in:
                # Submit on OUT endpoint - contains the data being sent
                if len(payload) > 0:
                    urb_submit_data[urb_id] = payload
            elif event_type == 'C' and not ep_dir_in:
                # Complete on OUT endpoint - data was in the submit
                data = urb_submit_data.pop(urb_id, None)
                if data is not None and len(data) > 0:
                    result = state.handle_out(data, pkt_num)
                    if result == "no_ack" or result == "reseed" or result == "bitstream":
                        pending_cmd_info = None
                    elif result is not None:
                        pending_cmd_info = result
                    else:
                        pending_cmd_info = None
            elif event_type == 'S' and ep_dir_in:
                # Submit on IN endpoint - request to read (no data yet)
                urb_pending_in[urb_id] = True
            elif event_type == 'C' and ep_dir_in:
                # Complete on IN endpoint - contains the response data
                urb_pending_in.pop(urb_id, None)
                if len(payload) > 0:
                    # Check if this is a response to a pending command or capture data
                    if pending_cmd_info is not None:
                        state.handle_in(payload, pkt_num, pending_cmd_info)
                        pending_cmd_info = None
                    elif len(payload) > 64:
                        # Likely capture data
                        print(f"  [{pkt_num}] IN: capture data ({len(payload)} bytes)")
                    else:
                        # Try to decrypt as response anyway
                        state.handle_in(payload, pkt_num, None)

        # Print final bitstream summary if still in progress
        if state.in_bitstream:
            print(f"           ... bitstream upload: {state.bitstream_bytes} bytes total")

        if device_filter is None and len(devices_seen) > 1:
            print(f"\nNote: saw multiple devices on EP1: {sorted(devices_seen)}")
            print("Use --device-num N to filter for a specific device.")

        print(f"\nProcessed {pkt_num} packets, final LFSR=0x{state.lfsr:08x}")


def main():
    parser = argparse.ArgumentParser(
        description="Parse usbmon pcap capture of Saleae Logic 8 (FX2) commands")
    parser.add_argument("pcap_file", help="Path to pcap file")
    parser.add_argument("--device-num", type=int, default=None,
                        help="USB device number to filter for")
    args = parser.parse_args()

    parse_pcap(args.pcap_file, args.device_num)


if __name__ == "__main__":
    main()
