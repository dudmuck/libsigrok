# Saleae Logic 8 Firmware and Bitstream

The Saleae Logic 8 (USB VID:PID 21a9:1004) requires two firmware files
to operate with libsigrok:

1. **saleae-logic8-fx2.fw** — Cypress FX2LP (CY7C68013A) microcontroller
   firmware. Uploaded over USB each time the device is connected.

2. **saleae-logic8-fpga.bitstream** — Lattice ECP5 (LFE5U-45F) FPGA
   bitstream. Uploaded by the driver after the FX2 firmware is running.

Both files must be placed in one of the firmware search paths:

    $SIGROK_FIRMWARE_DIR (environment variable)
    $HOME/.local/share/sigrok-firmware
    $prefix/share/sigrok-firmware
    /usr/local/share/sigrok-firmware
    /usr/share/sigrok-firmware


## Extracting firmware from the vendor software

The firmware files can be extracted from the Saleae Logic 2 Linux
application using the `sigrok-util` extraction tools. You will need a
copy of the vendor application installed or its AppImage.

The Saleae Logic 2 application bundles firmware inside its resources.
The FX2 firmware and FPGA bitstream for the Logic 8 are stored
alongside firmware for other Saleae devices.

Typical steps:

1. Download the Saleae Logic 2 application for Linux from:
   https://www.saleae.com/downloads/

2. Extract or mount the AppImage:

       ./Logic-2.x.x-linux-x64.AppImage --appimage-extract

3. Use the appropriate sigrok-util script to locate and extract the
   firmware files from the extracted application directory.

4. Copy the resulting files to a firmware search path:

       cp saleae-logic8-fx2.fw ~/.local/share/sigrok-firmware/
       cp saleae-logic8-fpga.bitstream ~/.local/share/sigrok-firmware/


## Startup sequence

When sigrok-cli (or another frontend) opens the device:

1. If the FX2 chip has no firmware loaded (identified by USB descriptor
   strings not matching "Saleae Inc" / "Logic 8"), the driver uploads
   **saleae-logic8-fx2.fw** using the Cypress vendor request protocol
   and waits for the device to re-enumerate.

2. The driver initialises the encrypted command channel (LFSR reseed),
   reads the EEPROM serial number, then uploads
   **saleae-logic8-fpga.bitstream** to the FPGA via SPI bitbang through
   the FX2. This takes approximately 4 seconds due to the 62-byte
   per-packet limit of the FX2 bitstream path.

3. After bitstream upload, the driver verifies FPGA configuration by
   writing and reading back a scratch register (0x7f = 0xaa).

4. The ADC is initialised, configuration registers are written, and the
   device is ready for acquisition.


## Troubleshooting

- **Device not found**: Check that the udev rules from
  `contrib/60-libsigrok.rules` are installed and that your user has
  permission to access the USB device.

- **Firmware upload fails**: Verify that `saleae-logic8-fx2.fw` is
  present in one of the firmware search paths. Run with `-l 5` to see
  which paths are searched.

- **FPGA register read-back fails (0x00 != 0xaa)**: The FPGA bitstream
  file may be an incompatible version. Re-extract the bitstream from a
  current version of the Saleae Logic 2 application. The working
  bitstream is approximately 288 KB; an older non-working version is
  approximately 283 KB.

- **Slow startup (~4 seconds)**: This is normal. The FX2 bitstream
  upload path transfers 62 bytes per USB packet, requiring ~4600
  packets for the full bitstream.
