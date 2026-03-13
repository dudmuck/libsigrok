#!/usr/bin/env python3
"""Generate test patterns on Raspberry Pi GPIO pins for Saleae Logic 8 testing.

Wiring (Logic 8 CH -> RPi GPIO -> RPi Header Pin):
  CH0 -> GPIO  4 -> Pin  7
  CH1 -> GPIO 17 -> Pin 11
  CH2 -> GPIO 27 -> Pin 13
  CH3 -> GPIO 22 -> Pin 15
  CH4 -> GPIO  5 -> Pin 29
  CH5 -> GPIO  6 -> Pin 31
  CH6 -> GPIO 13 -> Pin 33
  CH7 -> GPIO 19 -> Pin 35

Requires the gpiod Python library (libgpiod v2).
"""

import argparse
import signal
import sys
import threading
import time

try:
    import gpiod
    from gpiod.line import Direction, Value
except ImportError:
    print(
        "Error: 'gpiod' Python library not found.\n"
        "Install it with one of:\n"
        "  pip install gpiod\n"
        "  apt install python3-libgpiod\n"
        "\n"
        "This script requires libgpiod v2.",
        file=sys.stderr,
    )
    sys.exit(1)

# Channel-to-GPIO mapping (index = Logic 8 channel number)
CHANNEL_GPIOS = [4, 17, 27, 22, 5, 6, 13, 19]
GPIO_CHIP = "/dev/gpiochip0"

# Shared flag for clean shutdown
shutdown_event = threading.Event()


def log(msg):
    print(msg, file=sys.stderr)


def parse_channels(s):
    """Parse a comma-separated list of channel numbers (0-7)."""
    channels = []
    for part in s.split(","):
        ch = int(part.strip())
        if ch < 0 or ch > 7:
            raise argparse.ArgumentTypeError(
                f"Channel {ch} out of range (0-7)"
            )
        channels.append(ch)
    return sorted(set(channels))


def request_lines(channels):
    """Request GPIO lines for the given channel list. Returns (request, channel_list)."""
    gpios = [CHANNEL_GPIOS[ch] for ch in channels]
    config = {
        gpio: gpiod.LineSettings(direction=Direction.OUTPUT)
        for gpio in gpios
    }
    req = gpiod.request_lines(
        GPIO_CHIP,
        consumer="rpi_test_signals",
        config=config,
    )
    return req


def set_channels(req, channels, values):
    """Set channels to the given values dict {ch: bool}."""
    mapping = {}
    for ch in channels:
        v = values.get(ch, False)
        mapping[CHANNEL_GPIOS[ch]] = Value.ACTIVE if v else Value.INACTIVE
    req.set_values(mapping)


def pattern_all_high(req, channels, duration):
    log("Pattern: all-high (static)")
    vals = {ch: True for ch in channels}
    set_channels(req, channels, vals)
    log(f"  All {len(channels)} channels HIGH")
    wait_for_duration(duration)


def pattern_all_low(req, channels, duration):
    log("Pattern: all-low (static)")
    vals = {ch: False for ch in channels}
    set_channels(req, channels, vals)
    log(f"  All {len(channels)} channels LOW")
    wait_for_duration(duration)


def pattern_walking_1(req, channels, duration):
    log("Pattern: walking-1 (one channel high at a time, 100ms step)")
    deadline = time.monotonic() + duration if duration > 0 else None
    idx = 0
    while not shutdown_event.is_set():
        if deadline and time.monotonic() >= deadline:
            break
        active_ch = channels[idx % len(channels)]
        vals = {ch: (ch == active_ch) for ch in channels}
        set_channels(req, channels, vals)
        log(f"  CH{active_ch} HIGH")
        idx += 1
        shutdown_event.wait(0.1)


def pattern_walking_0(req, channels, duration):
    log("Pattern: walking-0 (all high except one, 100ms step)")
    deadline = time.monotonic() + duration if duration > 0 else None
    idx = 0
    while not shutdown_event.is_set():
        if deadline and time.monotonic() >= deadline:
            break
        low_ch = channels[idx % len(channels)]
        vals = {ch: (ch != low_ch) for ch in channels}
        set_channels(req, channels, vals)
        log(f"  CH{low_ch} LOW (others HIGH)")
        idx += 1
        shutdown_event.wait(0.1)


def pattern_binary_count(req, channels, duration):
    log("Pattern: binary-count (0-255 on CH0-CH7, CH0=LSB, 100ms step)")
    deadline = time.monotonic() + duration if duration > 0 else None
    count = 0
    while not shutdown_event.is_set():
        if deadline and time.monotonic() >= deadline:
            break
        vals = {}
        for ch in channels:
            vals[ch] = bool(count & (1 << ch))
        set_channels(req, channels, vals)
        log(f"  Count: {count:3d} (0x{count:02x}, 0b{count:08b})")
        count = (count + 1) & 0xFF
        shutdown_event.wait(0.1)


def pattern_alternating(req, channels, duration):
    log("Pattern: alternating (even HIGH / odd LOW, swap every 100ms)")
    deadline = time.monotonic() + duration if duration > 0 else None
    phase = 0
    while not shutdown_event.is_set():
        if deadline and time.monotonic() >= deadline:
            break
        vals = {}
        for ch in channels:
            if phase == 0:
                vals[ch] = (ch % 2 == 0)
            else:
                vals[ch] = (ch % 2 == 1)
        set_channels(req, channels, vals)
        state = "even=HIGH odd=LOW" if phase == 0 else "even=LOW odd=HIGH"
        log(f"  {state}")
        phase ^= 1
        shutdown_event.wait(0.1)


def square_wave_thread(req, channel, frequency):
    """Generate a square wave on a single channel at the given frequency."""
    gpio = CHANNEL_GPIOS[channel]
    half_period = 0.5 / frequency
    state = True
    log(f"  CH{channel}: {frequency} Hz square wave (thread started)")
    while not shutdown_event.is_set():
        val = Value.ACTIVE if state else Value.INACTIVE
        req.set_values({gpio: val})
        state = not state
        shutdown_event.wait(half_period)


def pattern_identify(req, channels, duration):
    """Each channel at a different frequency for identification.

    CH0: DC high, CH1: DC low,
    CH2: 1kHz, CH3: 500Hz, CH4: 250Hz, CH5: 125Hz, CH6: 62.5Hz, CH7: 31.25Hz
    """
    log("Pattern: identify (each channel at unique frequency)")

    # Frequency assignments (None = DC)
    freq_map = {
        0: ("DC HIGH", None, True),
        1: ("DC LOW", None, False),
        2: ("1000 Hz", 1000.0, None),
        3: ("500 Hz", 500.0, None),
        4: ("250 Hz", 250.0, None),
        5: ("125 Hz", 125.0, None),
        6: ("62.5 Hz", 62.5, None),
        7: ("31.25 Hz", 31.25, None),
    }

    threads = []

    for ch in channels:
        label, freq, dc_val = freq_map[ch]
        if freq is not None:
            # Square wave channel - spawn a thread
            t = threading.Thread(
                target=square_wave_thread,
                args=(req, ch, freq),
                daemon=True,
            )
            t.start()
            threads.append(t)
        else:
            # DC channel
            gpio = CHANNEL_GPIOS[ch]
            val = Value.ACTIVE if dc_val else Value.INACTIVE
            req.set_values({gpio: val})
            log(f"  CH{ch}: {label}")

    wait_for_duration(duration)

    # Signal threads to stop (shutdown_event set by wait_for_duration or signal)
    shutdown_event.set()
    for t in threads:
        t.join(timeout=1.0)


def wait_for_duration(duration):
    """Wait for the specified duration or until shutdown."""
    if duration > 0:
        shutdown_event.wait(duration)
    else:
        # Run forever until interrupted
        while not shutdown_event.is_set():
            shutdown_event.wait(1.0)


def main():
    parser = argparse.ArgumentParser(
        description="Generate test patterns on RPi GPIO for Saleae Logic 8 testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Wiring (Logic 8 CH -> RPi GPIO -> RPi Header Pin):
  CH0 -> GPIO  4 -> Pin  7      CH4 -> GPIO  5 -> Pin 29
  CH1 -> GPIO 17 -> Pin 11      CH5 -> GPIO  6 -> Pin 31
  CH2 -> GPIO 27 -> Pin 13      CH6 -> GPIO 13 -> Pin 33
  CH3 -> GPIO 22 -> Pin 15      CH7 -> GPIO 19 -> Pin 35
""",
    )
    parser.add_argument(
        "--pattern",
        choices=[
            "walking-1",
            "walking-0",
            "binary-count",
            "all-high",
            "all-low",
            "alternating",
            "identify",
        ],
        default="walking-1",
        help="Test pattern to generate (default: walking-1)",
    )
    parser.add_argument(
        "--channels",
        type=parse_channels,
        default=list(range(8)),
        help="Comma-separated channels to drive, e.g. 0,1,2,3 (default: all 8)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="Duration in seconds, 0 = run forever (default: 10)",
    )
    args = parser.parse_args()

    # Install signal handler for clean shutdown
    def on_signal(signum, frame):
        log("\nShutting down...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    log(f"Using GPIO chip: {GPIO_CHIP}")
    log(f"Channels: {', '.join(f'CH{ch}(GPIO{CHANNEL_GPIOS[ch]})' for ch in args.channels)}")
    dur_str = f"{args.duration}s" if args.duration > 0 else "forever"
    log(f"Duration: {dur_str}")
    log("")

    req = request_lines(args.channels)

    patterns = {
        "walking-1": pattern_walking_1,
        "walking-0": pattern_walking_0,
        "binary-count": pattern_binary_count,
        "all-high": pattern_all_high,
        "all-low": pattern_all_low,
        "alternating": pattern_alternating,
        "identify": pattern_identify,
    }

    try:
        patterns[args.pattern](req, args.channels, args.duration)
    finally:
        # Clean up: drive all channels low and release
        log("\nCleaning up: setting all channels LOW and releasing GPIO lines")
        try:
            set_channels(req, args.channels, {ch: False for ch in args.channels})
        except Exception:
            pass
        req.release()
        log("Done.")


if __name__ == "__main__":
    main()
