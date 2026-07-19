# Logic 8 analog capture — completion plan

Status snapshot 2026-07-19. The analog WIP from the March 2026 session
(session id 05f5206a…, transcript no longer available) was reverted from the
working tree to keep it clean; the complete diff is preserved as
**`saleae-logic8-analog-wip.patch`** (853 lines, applies to commit `c09d7129`).
Resume with:

    git apply saleae-logic8-analog-wip.patch

Reference notes: `~/.claude/projects/-mnt-foo-libsigrok/memory/analog-format.md`
(register tables, frame format, RPi calibration measurements).

## What the WIP patch already implements (end-to-end pipeline worked 2026-03-15)

- **Channel model** (`api.c`): per-model `num_logic_channels`/`num_analog_channels`;
  Logic 8 gains 8 analog channels A0–A7 (disabled by default), digital renamed
  D0–D15, "Logic" channel group + one group per analog channel,
  `SR_CONF_OSCILLOSCOPE` drvopt. NOTE: the rename means CLI usage changes from
  `-C 0=...` to `-C D0=...` everywhere once this lands.
- **Channel config** (`protocol.c` `configure_channels()`): splits enabled
  channels into digital mask/count and analog mask/count/list (analog index =
  `c->index - num_logic`).
- **FPGA register setup** (`saleae_logic_pro_prepare()`): analog register
  values from Logic 2 USB captures — 0x08=ana mask, 0x0a=1 (1ch) or 8 (multi),
  0x0d=ana_cnt×3, 0x13=0x00 in analog mode (0x02 digital-only), 0x14=0x06 (1ch)
  or 0x03, 0x0b/0x0c=0xff when no digital. Digital rate divisor (0x0b) still set
  when digital channels active, but 0x14 left at the analog value in mixed mode.
- **PLL reconfig before analog capture**: calls `configure_clocks()` in
  `prepare()` when analog channels are active — without this the FPGA outputs
  the `00 00 ff ff` test pattern. (CRITICAL, verified in March.)
- **Calibration loading** (`saleae_logic_pro_load_calibration()`): reads
  `~/.config/Logic/calibrations/{serial}-*.cal` (serial = EEPROM bytes 8..15 as
  little-endian uint64), string-parses the `fullScaleVoltageRanges` JSON array
  into per-channel `ana_vmin[]`/`ana_vmax[]`. Defaults −0.4/5.3 V when absent.
  Verified working: loads all 8 ranges for this unit (serial 11775469402856028454).
- **Frame conversion** (`saleae_logic_pro_convert_analog_fx2()`): 3-byte
  triplets, ADC sample = byte 2 (8-bit), 2 duplicate triplets per channel per
  mux cycle (frame = ana_cnt×6 bytes); nibble-heuristic triplet alignment sync;
  partial-frame carry across USB transfers (`fx2_partial` widened to 48 bytes);
  `V = vmin + raw/255 × (vmax−vmin)`; per-channel `SR_DF_ANALOG` packets.
- **SERDES settling**: first 128 USB transfers (~2 s) of analog data discarded.
- **Receive path**: FX2 branch dispatches digital → existing converter, analog
  → new converter, so mixed capture is structurally in place.

## Known gaps / review items for the resume (in rough priority order)

1. **Analog sample rate reporting.** The session meta samplerate is the digital
   rate; the actual per-channel analog rate (function of 0x0a/0x0d/0x14 —
   Logic 2 uses 625 k/1.25 M/2.5 M/5 M/10 M per the `.cal` calibrationSets keys)
   is never computed or reported, so PulseView/sigrok-cli time axes will be
   wrong for analog data. Determine rate per config from Logic 2 captures and
   attach it to the analog packets / SR_CONF_SAMPLERATE handling.
2. **Mixed analog+digital register config incomplete.** Memory table says
   2a+2d capture uses `0x0a=0x08, 0x0d=0x06, 0x0e=0x14(20), 0x14=0x03` — the
   WIP always writes `0x0e=dig_channel_cnt` and never the mixed-mode digital
   mux value (0x14=20 for 2 digital @100 MHz). Mixed-mode frame *parsing* is
   also unimplemented (digital and analog interleave in one stream; format
   undocumented — needs a Logic 2 USB capture of a mixed session to reverse).
3. **Triplet alignment heuristic** (byte-1 low-nibble consistency over 4
   triplets) — fragile; the per-channel framing constants in analog-format.md
   (e.g. CH0 0x900229) could give a deterministic sync instead.
4. **Multi-channel analog only lightly tested**; single-channel was the
   verified path in March. Verify channel ordering against the framing
   constants (memory notes CH2/CH4 share a pattern — confirm identity mapping).
5. **`config_list`/`config_get` for analog**: channel-group requests return
   `SR_ERR_NA`; PulseView may want per-group samplerate/vdiv info.
6. **Buffer sizing sanity**: `ANA_CONV_BUFFER_SIZE` is 16384 floats; max
   samples per 16 KB transfer is 16384/3 ≈ 5461 (1ch) — fine, but re-check for
   the mixed-mode format.
7. **Optional fidelity**: `.cal` also carries per-rate biquad correction
   filters (`calibrationSets.{rate}[8].df1SosCoefficients`, groupDelay,
   impulseLength) and `hittiteAdcGainRegisterValue`. Logic 2 applies these as
   DSP post-processing. Skipping them costs accuracy but is acceptable
   initially; document the limitation.
8. **Startup transient**: fixed 128-transfer skip is crude; could instead gate
   on the sync heuristic + settled variance, or timestamp-trim.
9. **`sr_analog_init(…, 2)`** — 2 significant digits; bump if calibrated
   output deserves more.

## Calibration file format (confirmed against this unit's file)

`~/.config/Logic/calibrations/{decimal-serial}-{epoch-ms}-1.cal`, JSON:

    data.deviceId                      "11775469402856028454"
    data.fullScaleVoltageRanges[8]     {minimumVoltage, maximumVoltage} per ch
                                       (e.g. ch0: −0.498883 … 5.237675)
    data.calibrationSets.{625000,1250000,2500000,5000000,10000000}[8]
                                       {groupDelay, impulseLength,
                                        df1SosCoefficients[]: {b0,b1,b2,a1,a2}}
    data.hittiteAdcGainRegisterValue   0

Five .cal files are present locally (several Saleae units). The EEPROM stores
only serial + revision — calibration comes solely from these files (Logic 2
downloads them per serial from Saleae's servers).

## Test signal source (from Zephyr session 2ffd649f…, transcript gone;
## work preserved as `zephyr-dac-testgen.patch`)

Modified `samples/drivers/dac` in `/mnt/foo/zephyrproject/zephyr/` (uncommitted
there; diff also saved here as **`zephyr-dac-testgen.patch`**, 211 lines).
Adds `CONFIG_SHELL=y` and shell commands on the board's 12-bit DAC (3.3 V ref;
build tree was last configured for `nucleo_u575zi_q`):

    dac mv <0-3300>       # set output in millivolts
    dac raw <0-4095>      # set raw DAC code
    dac ramp <step>       # sawtooth up, 1 ms/step (step 1 → ~4 s period)
    dac ramp_down <step>  # sawtooth down
    dac stop

Precise DC levels beat the RPi GPIO 0/3.3 V method for calibration checks, and
the slow sawtooth sweeps the full ADC input range for linearity/monotonicity.

## Validation plan when resuming

1. `git apply saleae-logic8-analog-wip.patch`, build, `--scan` shows D0-D7+A0-A7.
2. Single-channel: DAC test generator on A0 (`dac mv 1000` etc.) →
   `sigrok-cli -d saleae-logic-pro -C A0 --config samplerate=25m --samples ...`
   → measured voltage matches commanded mV within calibration accuracy; then
   `dac ramp 1` → clean 0→3.3 V sawtooth, no wraps/steps (alignment check).
   (March polarity table in analog-format.md predates the byte2 format —
   re-verify signs.)
3. All-8: `parse_analog_capture.py` against a Logic 2 capture of the same
   signals (`analog_capture.pcap`, `mixed_analog_capture*.pcap` in repo root
   are existing references).
4. Mixed 2a+2d capture vs Logic 2 (needs item 2 solved).
5. Confirm digital-only capture is bit-identical to pre-patch behavior
   (regression guard — the dual-SPI deglitch workflow must keep working).

## Interaction with committed work

- The deglitch transform commit (`c09d7129`) is independent of the driver.
- Current HEAD has plain "0".."15" channel names; the D-naming arrives with
  this patch. sigrok-cli commands in docs/memory that use `-C D0=...` assume
  the patch is applied; with a clean tree use `-C 0=...`.
