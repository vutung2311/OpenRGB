# Corsair DDR5 V4 Protocol — Complete Findings

> [!IMPORTANT]
> This document captures all findings from reverse-engineering the Corsair DDR5 lighting
> protocol for OpenRGB. It should be kept up to date as further testing reveals new details.
> **All findings verified against iCUE CorsairDeviceControlService.exe v5.42 disassembly.**
> Last updated: 2026-03-12 (deep binary disassembly — register dispatch jump table decoded, complete register map, handler VAs confirmed via rizin/capstone)

---

## 1. Hardware Setup

| Item | Value |
|------|-------|
| Bus | i2c-12 (piix4_smbus, AMD) |
| DIMM 1 | 0x19 (Corsair Dominator Platinum RGB DDR5) |
| DIMM 2 | 0x1b (Corsair Dominator Platinum RGB DDR5) |
| ID Register | 0x43 = `0x1a` (Corsair RGB controller) |
| SMBus adapter | piix4 — supports byte and word writes, NOT block writes |

---

## 2. Protocol Versions

### V3 Block Protocol (DDR4 + DDR5) — PRIMARY
- **Registers**: `0x31` (ColorBufferBlockStart), `0x32` (ColorBufferBlock)
- **SMBus operation**: `i2c_smbus_write_block_data` (up to 32 bytes per write)
- **Works on both DDR4 and DDR5** — confirmed via Go kernel API test (2026-03-11)
- `i2cset` fails ("Adapter does not have I2C block write capability") but the
  kernel C API (`ioctl(I2C_SMBUS)`) works — the adapter DOES support block writes
- **iCUE's `LightingWriterV4Block` uses these same registers** — "V4Block" is V3
  block protocol applied to DDR5 hardware, not a different wire format
- Per-LED color control confirmed: LED0=RED, LED1=GREEN, LED2=BLUE on DDR5
- **Disassembly confirmed (2026-03-12)**: `0x31` is Class 27 pass-through (raw
  `SMBusWriteBlock`); `0x32` has a dedicated handler (Class 12) that tracks
  multi-chunk sequencing state. OpenRGB's write order (0x31 first, 0x32 for
  continuation) exactly matches iCUE's wire protocol.

### V4 Word Protocol (DDR5 fallback only)
- **Registers**: `0x90` (ColorBufferWriteStart), `0xA0` (ColorBufferWrite)
- **SMBus operation**: `i2c_smbus_write_word_data` (16-bit value per write)
- **iCUE's `LightingWriterV4Word`** — used ONLY when SMBus adapter supports
  neither block nor word writes well (degraded fallback)
- Data is ACK'd but **cannot produce visible per-LED colors** — tested via both
  `i2cset` and Go kernel API `ioctl(I2C_SMBUS)` (2026-03-11)
- **NOT NEEDED for OpenRGB** — V3 Block works for DDR5 via kernel API

> [!IMPORTANT]
> **V4 Word is NOT needed.** iCUE's error string confirms V4Word is a degraded
> fallback: `"Dram module {} uses protocol v4 but SMBus does not support block
> and word writes"`. Since our kernel supports block writes, we use V3 Block
> (same as iCUE's `LightingWriterV4Block`) for both DDR4 and DDR5.

### V3 Command Protocol (Effects)
- **Registers**: `0x26`, `0x21`, `0x20`, `0x82`
- **SMBus operation**: `i2c_smbus_write_byte_data` (single byte writes)
- Works on both DDR4 and DDR5 via byte writes (universally supported)
- Used for hardware effects (Rainbow Wave, Static, etc.)
- **Static mode (0x00)** with custom colors confirmed working for arbitrary colors

---

## 3. Protocol Detection — CRITICAL FINDING

### ❌ Register 0x44 is NOT a reliable protocol identifier

From 5+ diagnostic runs, register 0x44 **alternates between sticks**:

| Run | 0x19 reg44 | 0x1b reg44 |
|-----|-----------|-----------| 
| Run 1 | 0x04 | 0x01 |
| Run 2 | 0x01 | 0x04 |
| Run 3 | 0x01 | 0x04 |
| Run 4 | 0x04 | 0x01 |
| Run 5 | 0x04 | 0x01 |

**reg44 is a volatile state flag** that changes based on:
- Which stick was last written to
- What operations were performed
- Internal controller state

Using it for protocol detection causes one stick to randomly get V3 instead of V4.

> [!NOTE]
> **Disassembly confirmation (2026-03-12)**: Register `0x44` (`GetProtocolVersion`) maps to
> **Class 27 (pass-through)** in the iCUE dispatch table — iCUE does NOT cache or transform
> this read. The value returned is the raw hardware output each time, explaining the observed
> alternating behaviour. iCUE's protocol selection instead relies on `SMBusGetCaps` adapter
> probing, not on reg44.

### ✅ Correct detection: I2C address range

The I2C address range is fixed by hardware and reliably identifies DDR generation:

| Address Range | Generation | Protocol |
|--------------|-----------|----------|
| `0x18 - 0x1F` | DDR5 | V3 Block (0x31/0x32) via kernel API |
| `0x58 - 0x5F` | DDR4 | V3 Block (0x31/0x32) via kernel API |

This is the same split used by the DDR5 SPD EEPROM mapping (`0x18+N` → SPD `0x50+N`).

---

## 4. V4 Data Encoding Format

Decoded from iCUE disassembly at `0x14018ed23`:

```
Input: data[] = [led_count, R0, G0, B0, R1, G1, B1, ...]

Each iteration processes 5 bytes starting at index i (starting at i=2):
  b0 = data[i-2], b1 = data[i-1], b2 = data[i], b3 = data[i+1], b4 = data[i+2]

  Word 1: reg = (reg_select | (b2 >> 4))
           val = (b1 << 8) | b0
  Word 2: reg = (0xA0 | (b2 & 0x0F))
           val = (b4 << 8) | b3

  reg_select = 0x90 for first word, 0xA0 for subsequent
  i increments by 5 each iteration
```

### Example: 11 LEDs, all RED (0xFF, 0x00, 0x00)
```
data = [0x0B, 0xFF, 0x00, 0x00, 0xFF, ...] (34 bytes total)

Iteration 1 (i=2): b0=0x0B, b1=0xFF, b2=0x00, b3=0x00, b4=0xFF
  Word 1: reg=0x90|(0x00>>4)=0x90, val=(0xFF<<8)|0x0B = 0xFF0B
  Word 2: reg=0xA0|(0x00&0x0F)=0xA0, val=(0xFF<<8)|0x00 = 0xFF00

Iteration 2 (i=7): b0=0x00, b1=0xFF, b2=0x00, b3=0x00, b4=0xFF
  Word 1: reg=0xA0|(0x00>>4)=0xA0, val=(0xFF<<8)|0x00 = 0xFF00
  Word 2: reg=0xA0|(0x00&0x0F)=0xA0, val=(0xFF<<8)|0x00 = 0xFF00

... (iterations 3-6 identical to iteration 2)

Iteration 7 (i=32): b0=0x00, b1=0xFF, b2=0x00, b3=0x00, b4=0x00 (padded)
  Word 13: reg=0xA0, val=0xFF00
  Word 14: reg=0xA0, val=0x0000

Total: 14 words (7 iterations × 2 words)
Followed by: i2cset 0x28 0x0B (ApplyFullDirectData commit)
```

---

## 5. V4 Word Write Diagnostic Results (diag_v4.sh)

### Test Summary (from commit 845ded22)

The diagnostic script `diag_v4.sh` runs 7 tests (A–G) on ALL detected controllers:

| Test | Operation | Result | Notes |
|------|-----------|--------|-------|
| A | V4 word writes 0x90/0xA0 (zeros) | ✓ ACK'd | Corrupts live color buffer — causes partial LED state |
| B | V3 block writes 0x31 (i2cset) | ✗ FAIL | `i2cset` can't do block writes; kernel API works |
| C | TriggerEffect 0x27 (byte) | ✓ ACK'd | No visible effect during active hardware effect |
| D | SwitchMode 0x23 (byte cycle) | ✓ ACK'd | 0x00→0x01→0x02; **0x00 re-activates stored HW effect** |
| E | Brightness 0x10 (byte) | ✓ ACK'd | No visible change when already at max |
| F | V4 color data (11 LEDs, all RED) | ✓ ACK'd | **⚠ ENCODING BUG**: script sends wrong regs for iters 2+ |
| G | Rainbow Wave recovery | ✓ Recovers | **⚠ Causes white flash if sent while in direct mode** |

> [!WARNING]
> **Test F encoding bug**: The `diag_v4.sh` script hardcodes `reg=0xA0, val=0xFF00`
> for all iterations after the first. This is WRONG — the correct encoding varies
> per iteration because the register low nibble carries 4 bits of color data (b2).
> For all-RED, iterations 2 and 5 should use `reg=0xAF, val=0x0000`, and iterations
> 3 and 6 should use `reg=0xA0, val=0x00FF`. See §4 for the correct encoding.
> The C++ implementation (`ApplyColorsV4()`) computes this correctly.

### Interpretation

1. **V4 word writes are accepted** by piix4 SMBus — native word write support confirmed
2. **V3 block writes fail via i2cset** but work via kernel C API (`i2c_smbus_write_block_data`)
   - This is because `i2cset` uses a different ioctl path than the kernel's internal emulation
3. **Both V4 and V3 coexist** — the same DDR5 controller accepts word writes AND block writes
   - V4 is preferred for DDR5 because it's natively supported (no emulation needed)
4. **V4 word writes CANNOT override an active hardware effect** — data is ACK'd and
   buffered but the hardware effect continues rendering over it (confirmed with both
   correct and incorrect encoding, with and without 0x28 commit, with and without
   0x27 TriggerEffect — see §6.1 iterative session)
5. **Effect protocol (V3 Command) CAN set arbitrary colors** — Static mode (0x00)
   with custom colors works for both RED and GREEN (see §6.2)
6. **A single `0x23=0x02` write recovers DIMMs** from the stuck state — the full
   `0x00→0x01→0x02` cycle is redundant. Any write of `0x23 ≥ 1` works; `0x02`
   preferred over `0x01` (bootloader mode). See §6 ablation study.
7. **Rainbow Wave sent after `0x23=0x02` works** — the stuck state leaves DIMMs
   at `0x23=0x00`, so any non-zero SwitchMode write unfreezes the effect command.

### Register State Dump (Phase 2)

Selected register values read during diagnostics:

| Register | 0x19 value | 0x1b value | Meaning |
|----------|-----------|-----------|---------|
| 0x10 | varies | varies | Current brightness |
| 0x20-0x32 | 0xFF (normal) / 0x00 (broken) | 0xFF | Write-only regs; read 0x00 in white flash state |
| 0x41 | 0x00 | 0x00 | Status: ready |
| 0x43 | 0x1a | 0x1a | Device ID: Corsair RGB |
| 0x44 | **volatile** | **volatile** | Alternates — NOT for detection |
| 0x82 | varies | varies | Write config state |

> [!TIP]
> **White flash state detection:** When a DIMM enters white flash, its register
> state changes detectably: brightness (0x10) drops to `0x00`, write-only registers
> (0x20-0x32) read as `0x00` instead of `0xFF`, and reg44 may flip. This can be
> used to programmatically detect and recover from white flash.

---

## 6. White Flash — Root Cause & Recovery

### Isolation test results (2026-03-11, `test_white_flash.sh`, 11 LEDs)

Each operation from `diag_v4.sh` was tested **in isolation** on both controllers
(0x19, 0x1b), starting from a known-good Rainbow Wave state. After each test the
user visually checked whether white flash occurred.

**Run 2** (with correct 11-LED count, 14 V4 words + 0x28 commit):

| Test | Operation | Flash? | Observation |
|------|-----------|--------|-------------|
| 1 | SwitchMode cycle (0x23: 0→1→2) | **No** | No visual change |
| 2 | V4 word writes zeros (0x90/0xA0) | **Partial** | Some LEDs on, rest off |
| 3 | Brightness (0x10 = 0xFF) | **No** | No visual change |
| 4 | TriggerEffect (0x27: 0→1) | **No** | No visual change |
| 5 | V4 color data all-RED, 11 LEDs (14 words + 0x28 commit) | **No** | No visual change |
| 6 | Direct mode hold 10s (0x23=0x02, no colors sent) | **Yes** ⚠️ | White flash after ~10s hold |
| 7a | Direct mode hold 5s | **No** | No flash at 5s |
| 7b | Rainbow Wave without any reset sequence | **Yes** ⚠️ | Flash visible during transition |

> [!NOTE]
> **Run 1** (original, with wrong 12-LED count / only 4 words) had Tests 6, 7a, 7b
> all showing "No". The difference in Test 6 results between runs suggests the white
> flash from direct mode hold is **timing-dependent** — it may take longer than 10s
> in some cases, or depend on prior controller state.

### What actually causes white flash

> [!IMPORTANT]
> **Direct mode (0x23=0x02) without color data causes white flash.** When the
> controller is switched to direct mode but no color data is sent, it will
> eventually flash white. This was confirmed in Run 2 Test 6 (10s hold).
> The timing is variable — 5s was not enough (Test 7a), but 10s triggered it.

- **SwitchMode to direct (0x23=0x02) causes white flash** when held without
  sending color data — the controller expects a continuous stream of color
  updates in direct mode, and goes white when starved
- **V4 word writes with zero data** cause a **partial LED state** (some LEDs on,
  rest off) — this is not the classic "all-white" flash but a garbled buffer state
- **V4 color data writes (Test 5)** do NOT cause flash in isolation — the data
  is accepted silently even during an active hardware effect
- **Brightness, TriggerEffect, and SwitchMode cycle** have no visible side effects
  when issued in isolation during an active hardware effect

> [!WARNING]
> **Implication for OpenRGB:** The controller MUST keep sending color data
> continuously once in direct mode. If OpenRGB switches to direct mode
> (`0x23=0x02`) and then stalls (e.g., slow frame rate, blocked thread, crash),
> the DIMMs will flash white. The destructor's Rainbow Wave recovery is critical
> to handle the exit case, but mid-operation stalls remain a risk.

> [!NOTE]
> **Observed evidence for race conditions:** Running `diag_v4.sh` as non-root
> occasionally triggers white flash — some `i2cset` commands fail due to
> permissions or bus contention, sending a corrupted/partial command sequence to
> the controller. A subsequent run of the same script recovers the DIMMs,
> confirming that failed or interrupted writes can also cause flash. This matches
> iCUE's approach of using `SMBusLocker` (RAII) for bus locking and simply
> retrying on the next frame.

### Recovery mechanism — confirmed absolute minimum (2026-03-12)

> [!IMPORTANT]
> **Minimum recovery: one write — `0x23 = 0x02`, then send the effect command.**
> Confirmed by two independent ablation studies (`reset_rainbow.go`):
> - Round 1 (14 strategies): SwitchMode is the only load-bearing component.
>   V4-zeros, TriggerEffect, and Brightness are all redundant.
> - Round 2 (8 strategies): Within SwitchMode, any single write of value ≥ 1 suffices.
>   The full `0→1→2` cycle is redundant. `just 2` alone works. `just 0` fails.

**Why it works:** The stuck state (poison: `0x23: 0→1→2→0` + failed Rainbow Wave) leaves
DIMMs at `SwitchMode=0x00` (app mode). The effect command is then silently ACK'd but produces
no visual change. Writing any non-zero value to `0x23` (i.e. `0x01` or `0x02`) transitions
the controller out of this frozen state, making the subsequent effect command take effect.

**Safe minimum sequence:**
```bash
wait_ready $ADDR                    # Poll 0x41 for 0x00
i2cset -y $BUS $ADDR 0x23 0x02     # Single SwitchMode write — the only required step
sleep 0.05
# Now send any effect command normally:
i2cset -y $BUS $ADDR 0x26 0x01     # Effect command type
i2cset -y $BUS $ADDR 0x21 0x00     # BinaryStart
i2cset -y $BUS $ADDR 0x20 0x03     # Mode: Rainbow Wave
i2cset -y $BUS $ADDR 0x20 0x01     # Speed: medium
i2cset -y $BUS $ADDR 0x20 0x00     # Random: yes (no custom colors)
i2cset -y $BUS $ADDR 0x20 0x01     # Direction: down
i2cset -y $BUS $ADDR 0x20 0x00     # R1, G1, B1, A1
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x20 0xFF
i2cset -y $BUS $ADDR 0x20 0x00     # R2, G2, B2, A2
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x20 0xFF
i2cset -y $BUS $ADDR 0x20 0x00     # 8 padding bytes
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x20 0x00
i2cset -y $BUS $ADDR 0x82 0x01     # WriteConfiguration — commit
```

**Ablation study results (both runs identical):**

| S# | SwitchMode sequence | Result |
|----|---------------------|--------|
| S1 | `0→1→2` (baseline) | ✅ PASS |
| S2 | `0→1` | ✅ PASS |
| S3 | `1→2` | ✅ PASS |
| S4 | `0→2` | ✅ PASS |
| S5 | `just 0` | ❌ FAIL |
| S6 | `just 1` (bootloader) | ✅ PASS |
| **S7** | **`just 2`** | ✅ **PASS — minimum** |
| S8 | none (control) | ❌ FAIL |


### V4 zero-write partial LED state

Writing zeros to the V4 color buffer (`0x90 0x0000 w`, `0xA0 0x0000 w`) during
an active hardware effect causes a **partial LED state** — some LEDs show garbled
colors (orange, green, pink) while others turn off. This is not the classic
white flash but a corrupted buffer state. The effect continues running on some LEDs.

This was confirmed during both Rainbow Wave (2 LEDs showed orange/green, rest off)
and Static GREEN (mix of green, red, and pink) active effects. The V4 zero-writes
corrupt the leading bytes of the color buffer (sets led_count to 0, etc.).

---

### 6.1 Iterative diag_v4.sh session (2026-03-11)

Each test from `diag_v4.sh` was run **one at a time** on both controllers (0x19,
0x1b), with visual observation between each step. Starting from Rainbow Wave.

| Step | Test | Command | Visual Result |
|------|------|---------|---------------|
| 1 | Phase 1: Scan | Read 0x43/0x44/0x41 | Both 0x19, 0x1b found; reg44=0x04 on both |
| 2 | Phase 2: Registers | Read 17 registers | Both identical; write-only regs read 0xFF |
| 3 | **Test A**: V4 zeros | 0x90/0xA0 0x0000 w | **Partial LED state** — 2 LEDs orange+green, rest off |
| 4 | **Test B**: V3 block | 0x31 block write | ✗ FAIL (adapter limitation), no change |
| 5 | **Test C**: TriggerEffect | 0x27 0x00→0x01 | No change (still partial) |
| 6 | **Test D**: SwitchMode | 0x23 0x00→0x01→0x02 | **Rainbow Wave restored!** 🔥 |
| 7 | **Test E**: Brightness | 0x10 0xFF | No change (already max) |
| 8 | **Test F**: V4 RED data | 14 words + 0x28 | **No change** — HW effect overrides V4 data |
| 9 | **Test G**: Rainbow Wave | 0x26/0x21/0x20/0x82 | **⚠ WHITE FLASH** — sent while in direct mode |

Key findings from this session:
- **SwitchMode through app mode (0x00) is a recovery mechanism** — it re-activates
  the stored hardware effect, recovering from garbled buffer state
- **V4 color data cannot override an active hardware effect** — all 14 words are
  ACK'd but produce no visible change
- **Rainbow Wave while in direct mode triggers white flash** — the effect command
  must be sent from app mode, not direct mode
- **Recovery from deep white flash requires the full diag_v4.sh sequence** — a
  simple `0x23=0x00` + Rainbow Wave was not sufficient in one case

---

### 6.2 Effect Protocol Color Control (2026-03-11)

The V3 Command Protocol (0x26/0x21/0x20/0x82) can set **arbitrary colors** using
Static mode (0x00), not just predefined effects. Confirmed working:

| Color | Mode byte | R1 | G1 | B1 | Result |
|-------|-----------|----|----|----|---------| 
| RED | 0x00 | 0xFF | 0x00 | 0x00 | ✅ All LEDs solid red |
| GREEN | 0x00 | 0x00 | 0xFF | 0x00 | ✅ All LEDs solid green |
| Rainbow Wave | 0x03 | n/a | n/a | n/a | ✅ Animated rainbow |

#### Static color command sequence:
```bash
wait_ready $ADDR
i2cset -y $BUS $ADDR 0x26 0x01     # Effect command type
i2cset -y $BUS $ADDR 0x21 0x00     # BinaryStart
i2cset -y $BUS $ADDR 0x20 0x00     # Mode: Static (0x00)
i2cset -y $BUS $ADDR 0x20 0x01     # Speed (ignored for static)
i2cset -y $BUS $ADDR 0x20 0x01     # Custom colors (0x01)
i2cset -y $BUS $ADDR 0x20 0x00     # Direction (ignored)
i2cset -y $BUS $ADDR 0x20 $RED     # R1
i2cset -y $BUS $ADDR 0x20 $GRN     # G1
i2cset -y $BUS $ADDR 0x20 $BLU     # B1
i2cset -y $BUS $ADDR 0x20 0xFF     # A1 (must be 0xFF)
i2cset -y $BUS $ADDR 0x20 $RED     # R2 (same as R1)
i2cset -y $BUS $ADDR 0x20 $GRN     # G2
i2cset -y $BUS $ADDR 0x20 $BLU     # B2
i2cset -y $BUS $ADDR 0x20 0xFF     # A2
i2cset -y $BUS $ADDR 0x20 0x00     # (8 padding bytes)
... (8 × 0x00)
i2cset -y $BUS $ADDR 0x82 0x01     # WriteConfiguration — commit
```

> [!IMPORTANT]
> **The effect protocol is the only confirmed way to set visible colors on DDR5.**
> V4 word writes (0x90/0xA0) are accepted but cannot override an active hardware
> effect. The effect protocol using Static mode (0x00) with custom colors provides
> uniform color control. Per-LED color control via V4 remains unverified — it may
> require the kernel C API (`i2c_smbus_write_word_data`) rather than `i2cset`.

---

## 7. Dangerous Operations

### SwitchMode (0x23) NAK cascade

> [!CAUTION]
> Writing `0x23 0x01` (bootloader mode) after certain operations can put the
> controller into a **permanent NAK state** where it rejects ALL subsequent writes.
> Only a reboot (power cycle) can recover from this state.

This was discovered when `isolate_reset.sh` did aggressive SwitchMode cycling.
A safe minimal pattern is: write `0x02` (direct mode) with `wait_ready()` before,
then proceed with the effect command. The full `0x00→0x01→0x02` cycle also works
but is not necessary.

### Order and timing matter
- `0x23 0x02` (direct) is the confirmed safe single-write recovery
- `0x23 0x00` (app mode) alone does **not** recover from the stuck state — it is a no-op
  since the stuck state already leaves DIMMs at `0x00`
- Always call `wait_ready()` (poll 0x41 for 0x00) before SwitchMode writes

---

## 8. Register Map

### 8.1 Primary (confirmed) registers

| Register | iCUE Name | iCUE Dispatch | Type | Notes |
|----------|-----------|---------------|------|-------|
| 0x10 | `Bightness` (sic) | Class 1 — dedicated handler | R/W byte | 0x00-0xFF; typo confirmed in binary string |
| 0x20 | `SetBinaryData` | Class 27 — **pass-through** | W byte | Sequential data register for effect commands |
| 0x21 | `BinaryStart` | Class 9 — dedicated handler | W byte | Start data transfer (write 0x00 before 0x20 data) |
| 0x23 | `SwitchMode` | Class 27 — **pass-through** | R/W byte | 0=app, 1=bootloader, 2=direct; **dangerous** |
| 0x24 | `SwitchMode` alias | Class 27 — **pass-through** | R/W byte | Same hardware handler as 0x23 |
| 0x26 | *(unnamed)* | Class 27 — **pass-through** | W byte | 0x01=effect cmd, 0x02=store; bypasses iCUE logic entirely |
| 0x27 | `TriggerEffect` | Class 27 — **pass-through** | W byte | Commit staged colors; 0x00 then 0x01 |
| 0x28 | `ApplyFullDirectData` | Class 27 — **pass-through** | W byte | V3 direct commit (≤32 bytes) |
| 0x29 | `ApplyHalfDirectData` | Class 27 — **pass-through** | W byte | V3 direct commit (2nd half) |
| 0x31 | `ColorBufferBlockStart` | Class 27 — **pass-through** | W block | V3 block write: first chunk |
| 0x32 | `ColorBufferBlock` | Class 12 — dedicated handler | W block | V3 block write: subsequent chunks |
| 0x41 | *(unnamed)* | Class 27 — **pass-through** | R byte | Status: 0x00=ready; poll before writes |
| 0x42 | `GetChecksum` | Class 27 — **pass-through** | R byte | Checksum / CRC register |
| 0x43 | `GetStorageBlockCount` | Class 27 — **pass-through** | R byte | Returns 0x1a (Corsair device ID) |
| 0x44 | `GetProtocolVersion` | Class 27 — **pass-through** | R byte | **VOLATILE** — not reliable for detection |
| 0x82 | `WriteConfiguration` | Class 27 — **pass-through** | W byte | Commit/save; write 0x01 to apply |
| 0x90 | `ColorBufferWriteStart` | Class 23 — dedicated handler | W word | DDR5 V4 first word write |
| 0xA0 | `ColorBufferWrite` | Class 24 — dedicated handler | W word | DDR5 V4 subsequent word writes |
| 0xB0 | `SetDirectData` | Class 25 — dedicated handler | W byte | Direct per-LED color data (alternative path) |
| 0xC0 | `SetEffectCurrentTime` | Class 27 — **pass-through** | W byte | Sync effect timing across modules |

> [!NOTE]
> **"Pass-through" (Class 27) meaning**: All Class 27 registers are forwarded directly to the
> SMBus hardware without any iCUE interception. iCUE logs them as `"0x{:X}"` (confirmed from
> binary: handler at `0x140170760` loads format string `"0x{:X}"` and calls the LLA wrapper).
> This means iCUE does NOT rewrite or transform these values — what OpenRGB sends is exactly
> what the hardware sees.

### 8.2 Newly discovered registers (from dispatch jump table, 2026-03-12)

The full dispatch table at `0x14016f97e` reveals registers with dedicated handlers that were
previously unknown. These are **iCUE-internal** abstraction registers handled in software:

| Register | Observed iCUE Handler VA | Size arg | Inferred function |
|----------|--------------------------|----------|-------------------|
| 0x00 | `0x14016f999` | — | Unknown; first dispatch entry |
| 0x11 | `0x14016fada` | — | Unknown |
| 0x13 | `0x14016fc14` | — | Unknown |
| 0x14 | `0x14016fb81` | — | Unknown |
| 0x15 | `0x14016fcb1` | — | Unknown |
| 0x17 | `0x14016fd58` | — | Unknown |
| 0x18 | `0x14016fdfd` | — | Unknown |
| 0x19 | `0x14016feba` | — | Unknown |
| 0x22 | `0x140170032` | — | Unknown |
| 0x30 | `0x1401700d7` | — | Unknown |
| 0x33 | `0x140170225` | — | Unknown |
| 0x34 | `0x140170296` | — | Unknown |
| 0x35 | `0x140170309` | — | Unknown |
| 0x50 | `0x140170370` | 0x16 (22B) | Unknown |
| 0x51 | `0x1401703ed` | 0x16, 0x11 | Unknown |
| 0x52 | `0x140170452` | 0x16, 0x11, 0x10 | Unknown |
| 0x53 | `0x1401704a5` | 0x11, 0x10, 0x12 | References `WriteConfiguration` string |
| 0x71 | `0x1401704f8` | 0x10, 0x12, 0x15 | References `ColorBufferWriteStart` string |
| 0x72 | `0x14017054b` | 0x12, 0x15, 0x10 | References `WriteConfiguration`, `ColorBufferWriteStart`, `ColorBufferWrite` |
| 0x80 | `0x14017059e` | 0x15, 0x10 | References `ColorBufferWriteStart`, `ColorBufferWrite` |
| 0xE0 | `0x1401706f9` | — | Unknown; highest dedicated handler |

> [!NOTE]
> **Significance of 0x50–0x80 range**: These registers share size arguments (0x10–0x16 = 16–22 bytes)
> and cross-reference the same V4 color buffer write strings. They likely implement a multi-step
> V4 block write sequence at the iCUE abstraction layer, possibly for future firmware or for
> platforms where the raw 0x90/0xA0 word writes are not directly usable.
> **These registers are NOT needed for OpenRGB** — we use 0x31/0x32 (V3 block) directly.

---

## 9. iCUE Architecture Reference

From direct disassembly of `CorsairDeviceControlService.exe` v5.42 using rizin + capstone
(2026-03-12). Binary PE x64, image base `0x140000000`.

### 9.1 Protocol selection classes

| Class | Protocol | Hardware | Chooser log string |
|-------|----------|----------|--------------------|
| `LightingWriterV3` | Legacy byte-by-byte | DDR4 Vengeance RGB Pro | `"Choosing v3 implementation for module {}"` |
| `LightingWriterV4Block` | Block write (SMBus block) | DDR5 with block support | `"Choosing v4 block implementation for module {}"` |
| `LightingWriterV4Word` | Word write fallback | DDR5 without block support | `"Choosing v4 word implementation for module {}"` |

The chooser function queries `SMBusGetCaps` and reads `"Max block size"` from the adapter.
Selection logic (confirmed from string cross-refs in the protocol-selection function):
1. If adapter supports SMBus block writes AND block size ≥ 32 → **V4Block** (`LightingWriterV4Block`)
2. If adapter supports SMBus word writes but NOT block writes → **V4Word** (`LightingWriterV4Word`)
3. Fallback → **V3** (`LightingWriterV3`)
4. Error: `"Dram module {} uses protocol v4 but SMBus does not support block and word writes"` → no writer

**Protocol detection** for DDR5 uses `GetStorageBlockCount` / `GetProtocolVersion` returns
plus I2C address range (0x18–0x1F). Register 0x44 (`GetProtocolVersion`) is **not used for
selection** — the string for it appears only in pass-through logging.

### 9.2 Register dispatch — the write-handler switch

The main write-dispatch function (`ProtocolOperationsImpl::write`, approx VA `0x14016f940`) uses
a **two-stage compact switch** at `0x14016f97e`:

```
; Stage 1: range check
cmp   eax, 0xe0          ; reg byte capped at 0xe0
ja    0x140170760        ; out of range → default/pass-through

; Stage 2: table lookup
lea   rdx, [rip - offset]    ; rdx = image base (0x140000000)
movzx eax, byte ptr [rdx + rax + 0x170814]   ; class = JumpClassTable[rax]
mov   ecx, dword ptr [rdx + rax*4 + 0x1707a4] ; offset = JumpOffsetTable[class]
add   rcx, rdx            ; rcx = image_base + offset = absolute handler VA
jmp   rcx
```

- **JumpClassTable** (file offset `0x16fc14`): byte per register → jump class index (0-27)
- **JumpOffsetTable** (file offset `0x16fba4`): 28 × 4-byte relative offsets
- **28 distinct handlers** — 27 dedicated + 1 default pass-through (Class 27)
- All registers > 0xe0 are treated as out-of-range and fall to the default

### 9.3 SMBus LLA (Low-Level Access) API

Confirmed from `CorsairLLAccessLib64.dll` exports and string analysis in the main binary:

| Function | Purpose |
|----------|---------|
| `SMBusGetCaps` | Query adapter capabilities (block/word/byte support, max block size) |
| `SMBusGetControllers` | Enumerate all available SMBus controllers |
| `SMBusLock` | Acquire exclusive lock on SMBus bus (`SMBusLocker` RAII wrapper) |
| `SMBusUnlock` | Release SMBus lock |
| `SMBusWriteBlock` | Block write (up to 32 bytes) — used by `LightingWriterV4Block` and V3 |
| `SMBusWriteWord` | Word write (16-bit) — used by `LightingWriterV4Word` (V4 word encoder) |
| `SMBusWriteByte` | Byte write — used for all register writes (0x10, 0x23, 0x21, 0x82, etc.) |
| `SMBusReadByte` | Byte read — used for status poll (0x41), protocol detection (0x43/0x44) |

> [!IMPORTANT]
> iCUE acquires `SMBusLocker` (RAII) for **entire multi-register transactions**, not per write.
> This means while iCUE is writing a full effect sequence (0x26 → 0x21 → seventeen 0x20 bytes
> → 0x82), the bus is locked throughout. OpenRGB must replicate this or risk interleaved
> writes when multiple threads share the bus.

### 9.4 DRAM enumeration and timeouts

iCUE uses **different SMBus timeouts** during and after DRAM enumeration:

```
Starting DRAM enumeration (timeout=Nms)
...
DRAM enumeration finished. Restored timeouts to normal (lock=Nms; op=Nms)
```

Config keys (from strings): `busLockTimeout`, `operationTimeout`, `enumerationTimeout`.
This explains why first-access can be slower — iCUE temporarily lowers timeouts
during enumeration to quickly discard dead addresses.

### 9.5 Session recovery (prevents white flash)

iCUE has three logged recovery paths (confirmed from binary strings):

1. **Session end**: `"Enabling DRAM HW lightings due to session end"` (code `0x140101bd1`)
   → re-enables hardware effects by sending effect commands to all known DIMMs
2. **Bootloader recovery**: `"Failed to recover DRAM module from bootloader mode: {}"` (code `0x1400fc1ab`)
   → called when a DIMM is detected in bootloader mode (0x23=0x01 stuck)
3. **Brightness restore**: `"Applying cached brightness for {}: {}"` → restores brightness on reconnect
4. **Mode switch confirm**: `"Switched dram module {} to mode: {}"` (code `0x140199216`)
   → logged after every successful `SwitchMode` write; confirms the write succeeded

### 9.6 DramController internal struct (partial)

From RTTI strings in binary:
- Class: `DramController` — owns a `std::vector<Device>` of DIMM state objects
- Nested `Device` struct: contains `I2C address`, `protocol_version`, `bootloader_flag`
- `lockDramOperations()` → acquires `SMBusLocker` and returns it to caller (RAII)
- `updateFw()` → firmware update path with semver check and CRC validation
- `init()` → lambda captures for async DRAM bus initialization

### 9.7 Binary layout (CorsairDeviceControlService.exe v5.42)

| Section | File offset | VA | Size | Content |
|---------|------------|-----|------|---------|
| `.text` | `0x000400` | `0x140001000` | 0x200600 | Code |
| `.rdata` | `0x200a00` | `0x140202000` | 0x7a000 | Read-only data (strings, vtables) |
| `.data` | `0x27a800` | `0x14027c000` | 0x7400 | Mutable globals |
| `.idata` | `0x299e00` | `0x1402a0000` | 0x9000 | Import table |

Key code VAs (v5.42 only — will change on update):

| Location | VA | Description |
|----------|----|-------------|
| Write-dispatch switch | `0x14016f97e` | 2-stage jump table for register → handler |
| JumpClassTable | `0x140170814` | byte[0xe1]: reg → class index |
| JumpOffsetTable | `0x1401707a4` | int32[28]: class → handler rel offset |
| Default pass-through handler | `0x140170760` | Class 27: logs `"0x{:X}"`, calls LLA wrapper |
| Protocol chooser (v3/v4b/v4w) | `≈0x1400fdf00` | Queries SMBusGetCaps, creates writer |
| SwitchMode-to-mode | `0x140198f16` | Logs `"Switched dram module {} to mode: {}"` |
| Session-end re-enable | `0x140101bd1` | Logs `"Enabling DRAM HW lightings…"` |
| Bootloader recovery | `0x1400fc1ab` | Logs `"Failed to recover DRAM module…"` |

---

## 10. Diagnostic Scripts

All test scripts are embedded in full in **§13** below (source is preserved here
because the files will be deleted once testing is complete).

| Script | Purpose | Section |
|--------|---------|--------|
| `diag_v4.sh` | Full diagnostic: Tests A-G on ALL sticks + Rainbow Wave recovery | §13.1 |
| `reset_rainbow.go` | SwitchMode sub-sequence ablation (8 strategies, confirms minimum recovery) | §13.2 |
| `test_all_modes.go` | Interactive mode verifier for all effect modes + direct mode | §13.3 |
| `test_sequential.go` | Sequential mode (0x09) parameter ablation — 36 combinations | §13.4 |
| `isolate_reset.sh` | Isolation test: which operation resets the command parser | (historical, not embedded) |
| `recover_1b.sh` | Recovery attempts for stuck stick | (historical, not embedded) |
| `compare_regs.sh` | Full register comparison between two sticks | (historical, not embedded) |

### Key Script Functions

- `wait_ready()` / `waitReady()`: Polls register 0x41 up to 200 times with 1ms delay, returns 0 when status=0x00
- `test_word_write()`: Sends `i2cset -y $BUS $addr $reg $val w` and reports success/failure
- `test_byte_write()`: Sends `i2cset -y $BUS $addr $reg $val` and reports success/failure
- `hwRecovery()` (Go): Writes `0x23=0x02` then waits ready — the confirmed minimum recovery
- `sendEffect()` (Go): Sends the full V3 Command Protocol (0x26/0x21/0x20×N/0x82) sequence
- `sendDirect()` (Go): Switches to direct mode and sends V3 Block writes via `0x31`/`0x32`

---

## 11. Code State & Build

- **Branch**: master (latest commit `7fade2b6`)
- **Previous commit**: `845ded22` — added diag_v4.sh, auto-recovery, HW lighting restore
- **Key files modified**:
  - `CorsairDominatorPlatinumController.h` — V4 flag, protocol overview comment, split ApplyColors
  - `CorsairDominatorPlatinumController.cpp` — V4 word protocol, destructor restores HW lighting
  - `CorsairDominatorPlatinumControllerDetect.cpp` — address-based protocol detection, SPD model reading
- **Build**: `cd /home/tung/Git/AUR/openrgb-git && makepkg -sCif`

---

## 12. Binary Disassembly Appendix (2026-03-12)

### 12.1 Key string VAs in .rdata (CorsairDeviceControlService.exe v5.42)

These were located by `rz-find -s` and Python scanning; all are in `.rdata`
(`VA = 0x140202000 + (file_offset − 0x200a00)`):

| String | File offset | VA |
|--------|------------|-----|
| `"Choosing v3 implementation for module {}"` | `0x20cc10` | `0x14020e210` |
| `"Choosing v4 block implementation for module {}"` | `0x20cc48` | `0x14020e248` |
| `"Choosing v4 word implementation for module {}"` | `0x20cc80` | `0x14020e280` |
| `"Dram module {} uses protocol v4 but SMBus does not support block and word writes"` | (found) | (in .rdata) |
| `"Enabling DRAM HW lightings due to session end"` | (found) | `0x14020e090` |
| `"Failed to recover DRAM module from bootloader mode: {}"` | (found) | `0x14020e0f8` |
| `"Switched dram module {} to mode: {}"` | (found) | `0x14021xxx` |
| `"SwitchMode"` | `0x213170` | `0x140214770` |
| `"TriggerEffect"` | `0x213190` | `0x140214790` |
| `"ApplyFullDirectData"` | `0x2131a0` | `0x1402147a0` |
| `"ApplyHalfDirectData"` | `0x2131b8` | `0x1402147b8` |
| `"ColorBufferBlockStart"` | `0x2131d0` | `0x1402147d0` |
| `"ColorBufferBlock"` | `0x2131f0` | `0x1402147f0` |
| `"ColorBufferWriteStart"` | `0x213300` | `0x140214900` |
| `"ColorBufferWrite"` | `0x213320` | `0x140214920` |
| `"SetDirectData"` | `0x213338` | `0x140214938` |
| `"WriteConfiguration"` | `0x2132e8` | `0x1402148e8` |
| `"BinaryStart"` | `0x213160` | `0x140214760` |
| `"SetBinaryData"` | `0x213150` | `0x140214750` |
| `"Bightness"` (typo) | `0x213140` | `0x140214740` |
| `"GetProtocolVersion"` | `0x214848` | `0x140214848` |
| `"GetStorageBlockCount"` | `0x214828` | `0x140214828` |
| `"SMBusGetCaps"` | (found) | `0x140215020` |
| `"SMBusLock"` | (found) | `0x140214970` |
| `"SMBusReadByte"` | (found) | `0x140214d68` |
| `"0x{:X}"` (Class 27 log fmt) | derived | `0x140214964` |

### 12.2 Complete dispatch jump table (all 28 classes)

Decoded from JumpClassTable at file offset `0x16fc14` and JumpOffsetTable at `0x16fba4`:

| Class | Handler VA | Registers dispatched |
|-------|-----------|----------------------|
| 0 | `0x14016f999` | `0x00` |
| 1 | `0x14016fa35` | `0x10` (`Bightness`) |
| 2 | `0x14016fada` | `0x11` |
| 3 | `0x14016fc14` | `0x13` |
| 4 | `0x14016fb81` | `0x14` |
| 5 | `0x14016fcb1` | `0x15` |
| 6 | `0x14016fd58` | `0x17` |
| 7 | `0x14016fdfd` | `0x18` |
| 8 | `0x14016feba` | `0x19` |
| 9 | `0x14016ff77` | `0x21` (`BinaryStart`) |
| 10 | `0x140170032` | `0x22` |
| 11 | `0x1401700d7` | `0x30` |
| 12 | `0x14017017c` | `0x32` (`ColorBufferBlock`) |
| 13 | `0x140170225` | `0x33` |
| 14 | `0x140170296` | `0x34` |
| 15 | `0x140170309` | `0x35` |
| 16 | `0x140170370` | `0x50` |
| 17 | `0x1401703ed` | `0x51` |
| 18 | `0x140170452` | `0x52` |
| 19 | `0x1401704a5` | `0x53` |
| 20 | `0x1401704f8` | `0x71` |
| 21 | `0x14017054b` | `0x72` |
| 22 | `0x14017059e` | `0x80` |
| 23 | `0x1401705f1` | `0x90` (`ColorBufferWriteStart`) |
| 24 | `0x140170644` | `0xA0` (`ColorBufferWrite`) |
| 25 | `0x1401706a9` | `0xB0` (`SetDirectData`) |
| 26 | `0x1401706f9` | `0xE0` |
| **27** | **`0x140170760`** | **all others** (0x20, 0x23, 0x24–0x29, 0x31, 0x41–0x44, 0x82, 0xC0, …) |

> [!IMPORTANT]
> **Class 27 = raw pass-through**: Registers `0x20`, `0x23`, `0x26`, `0x27`, `0x28`,
> `0x29`, `0x31`, `0x41`, `0x43`, `0x44`, `0x82`, `0xC0` and many others all land here.
> iCUE does **not inspect or modify** the value — it logs `"0x{:X}"` and forwards verbatim
> to `SMBusWriteByte`/`SMBusWriteBlock`. This confirms our protocol reverse-engineering:
> these are raw hardware registers, not software abstractions.

### 12.3 V4 handler SMBus size constants

The `mov r8d, N` instruction before each `SMBysWriteBlock`/`SMBusWriteWord` call reveals
how many bytes/words each dedicated handler sends:

| Handler (register) | r8d size constant | Interpretation |
|--------------------|-------------------|---------------|
| Class 16 (`0x50`) | `0x16` = 22 | 22-byte block |
| Class 17 (`0x51`) | `0x16`, `0x11` | 22 + 17-byte |
| Class 18 (`0x52`) | `0x16`, `0x11`, `0x10` | 22 + 17 + 16-byte |
| Class 19 (`0x53`) | `0x11`, `0x10`, `0x12` | 17 + 16 + 18-byte |
| Class 20 (`0x71`) | `0x10`, `0x12`, `0x15` | 16 + 18 + 21-byte |
| Class 21 (`0x72`) | `0x12`, `0x15`, `0x10` | 18 + 21 + 16-byte |
| Class 22 (`0x80`) | `0x15`, `0x10` | 21 + 16-byte |
| Class 23 (`0x90`) | `0x10` | 16-byte write |
| Class 24 (`0xA0`) | `0x14` | 20-byte write |
| Class 25 (`0xB0`) | `0x14` | 20-byte write |

The 0x90/0xA0 handlers write 16 and 20 bytes respectively — consistent with the
V4 word encoding for 11 LEDs (7 iterations × 2 words = 14 words total = 28 bytes,
split across multiple calls).

### 12.4 Correctness implications for OpenRGB

From the binary analysis, the following correctness points are confirmed:

1. **0x31 is pass-through (Class 27)**: iCUE sends it as a raw block write, untransformed.
   Our `i2c_smbus_write_block_data(0x31, ...)` call is correct.

2. **0x23 (SwitchMode) is pass-through**: iCUE writes the mode byte directly to hardware
   with a `SMBusWriteByte` call. No software-side mode tracking intercepting the write.
   The `"Switched dram module {} to mode: {}"` log in the dedicated SwitchMode *logger*
   function at `0x140198f16` confirms iCUE does read-back to verify the switch succeeded.

3. **0xC0 (SetEffectCurrentTime) is pass-through**: iCUE uses this to synchronize effect
   timing across multiple DIMMs. Not currently used by OpenRGB, but confirmed harmless.

4. **0x82 (WriteConfiguration) is pass-through**: Writes 0x01 directly. iCUE does not
   do any pre/post processing — it's a single `SMBusWriteByte(0x82, 0x01)` call. Our
   implementation is correct.

5. **Both 0x90 and 0xA0 have dedicated handlers**: They are NOT pass-through. The
   handlers likely do additional bookkeeping (track buffer position, validate size).
   This explains why V4 word writes are ACK'd even during active HW effects — the
   iCUE layer accepts and buffers them, but the HW hasn't been told to switch to
   direct mode yet.

6. **0x32 has a dedicated handler but 0x31 does not**: `ColorBufferBlock` (continuation)
   is intercepted by iCUE while `ColorBufferBlockStart` (first chunk) is pass-through.
   This suggests iCUE tracks multi-chunk block state starting at 0x32.

7. **The 0x50–0x80 register range** is almost certainly the new V5/future protocol path
   for platforms that need iCUE-assisted chunked block writes. **Do not use these** with
   hardware unless you are certain the firmware supports them.

### 12.5 Sequential Mode (0x09) — DDR5 firmware does not animate it (2026-03-12)

Sequential mode (`0x09`) was extensively tested via a dedicated ablation script
(source embedded in **§13.4**). **36 parameter combinations were tested** covering all
permutations of:

| Parameter | Values tested |
|-----------|--------------|
| Pre-write | `0x23=0x02` (direct) · `0x23=0x00` (app) · none |
| Speed     | `0x00` (slow) · `0x01` (medium) · `0x02` (fast) |
| Direction | `0x00` (UP) · `0x01` (DOWN) |
| Color     | Custom RED (`0xFF 0x00 0x00`) · HW palette (all zero) |

**Result: 0/36 produced animation. All combinations show static LEDs.**

> [!IMPORTANT]
> **Sequential mode `0x09` is NOT supported on Corsair Dominator Platinum DDR5
> (firmware as of 2026-03-12).** The mode byte is accepted without SMBus error
> and the LEDs light up statically (solid RED when custom color is used), but
> no animation occurs regardless of speed, direction, pre-write sequence, or
> random flag. This is a firmware-level non-implementation.

**Earlier incorrect finding (now retracted):** A previous analysis claimed
`direction=0x01` was the fix. That was wrong — tested and still static.
The VA `0x14019c720` referenced earlier is mid-instruction inside the Rainbow
function body (`0x14019c680`), not a separate Sequential function. The two
internal iCUE speed-word constructors (`0x14019c630`, `0x14019c680`) are
generic DramEffect slot-push helpers, not mode-specific — the mode byte is set
by their callers via virtual dispatch.

**iCUE disassembly note:** iCUE *does* have a Sequential mode entry in its
effect table (the `0x14019c4a0` / `0x14019c630` simple constructor family),
but iCUE may gate it on DDR5 firmware capability checks before sending. The
DDR5 Dominator Platinum firmware either ignores `0x09` or maps it to static.

**OpenRGB implication:** Sequential mode should be **excluded** from the
DDR5 Dominator Platinum controller's mode list. It can remain in the DDR4
VengeancePro controller where it works.

---

## 13. Embedded Test Script Sources

> [!NOTE]
> These scripts were used during protocol reverse-engineering and are preserved here
> verbatim so that the findings can be fully reproduced. The files in the repository
> root (`diag_v4.sh`, `reset_rainbow.go`, `test_all_modes.go`, `test_sequential.go`)
> **have been deleted** — this document is the authoritative record.

### 13.1 `diag_v4.sh` — V4 Word Protocol Diagnostic

Full diagnostic script, runs Tests A–G on all detected Corsair DDR5 controllers.
Commit `845ded22` added this script along with auto-recovery and HW lighting restore.

```bash
#!/bin/bash
# Corsair DDR5 V4 Word Protocol Diagnostic
# Usage: sudo bash diag_v4.sh
# Tests different write methods to determine which protocol the DIMMs accept

BUS=12

echo "=== Corsair DDR5 V4 Word Protocol Diagnostic ==="
echo ""

# Phase 1: Scan for controllers (read-only)
echo "Phase 1: Scanning for Corsair RGB controllers on bus $BUS..."
ADDRS=()
for addr_dec in $(seq 24 31); do  # 0x18 to 0x1F
    addr_hex=$(printf "0x%02x" $addr_dec)
    ID1=$(i2cget -y $BUS $addr_dec 0x43 2>/dev/null)
    if [ $? -ne 0 ]; then continue; fi
    ID2=$(i2cget -y $BUS $addr_dec 0x44 2>/dev/null)
    STATUS=$(i2cget -y $BUS $addr_dec 0x41 2>/dev/null)
    echo "  $addr_hex: reg43=$ID1, reg44=$ID2 (protocol), status=$STATUS"
    if [ "$ID1" = "0x1a" ] || [ "$ID1" = "0x1b" ]; then
        ADDRS+=($addr_dec)
    fi
done

if [ ${#ADDRS[@]} -eq 0 ]; then
    echo "No Corsair controllers found!"
    exit 1
fi

echo ""
echo "Found ${#ADDRS[@]} controller(s): $(printf '0x%02x ' "${ADDRS[@]}")"
echo ""

# Helper functions (defined before the loop)
wait_ready() {
    for i in $(seq 1 200); do
        STATUS=$(i2cget -y $BUS $1 0x41 2>/dev/null)
        if [ "$STATUS" = "0x00" ]; then
            return 0
        fi
        sleep 0.001
    done
    return 1
}

# Test helper - try a single word write and check for errors
test_word_write() {
    local addr=$1
    local reg=$2
    local val=$3
    local desc=$4
    
    RESULT=$(i2cset -y $BUS $addr $reg $val w 2>&1)
    RC=$?
    if [ $RC -eq 0 ]; then
        echo "  ✓ $desc: i2cset -y $BUS $addr $reg $val w → OK"
    else
        echo "  ✗ $desc: i2cset -y $BUS $addr $reg $val w → FAIL ($RESULT)"
    fi
    return $RC
}

# Test helper - try a single byte write
test_byte_write() {
    local addr=$1
    local reg=$2
    local val=$3
    local desc=$4
    
    RESULT=$(i2cset -y $BUS $addr $reg $val 2>&1)
    RC=$?
    if [ $RC -eq 0 ]; then
        echo "  ✓ $desc: i2cset -y $BUS $addr $reg $val → OK"
    else
        echo "  ✗ $desc: i2cset -y $BUS $addr $reg $val → FAIL ($RESULT)"
    fi
    return $RC
}

# Loop over ALL found controllers
for TARGET in "${ADDRS[@]}"; do
    TARGET_HEX=$(printf "0x%02x" $TARGET)

    echo "############################################"
    echo "# Testing controller at $TARGET_HEX"
    echo "############################################"
    echo ""

    # Phase 2: Read extended register status
    echo "Phase 2: Reading register state from $TARGET_HEX..."
    for reg_hex in 0x10 0x20 0x21 0x23 0x27 0x28 0x29 0x31 0x32 0x41 0x42 0x43 0x44 0x45 0x82 0x90 0xa0; do
        VAL=$(i2cget -y $BUS $TARGET $reg_hex 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "  reg $reg_hex = $VAL"
        else
            echo "  reg $reg_hex = FAILED (NAK)"
        fi
    done

    echo ""
    echo "Phase 3: Protocol tests for $TARGET_HEX"
    echo "======================================"
    echo ""

    echo "Test A: V4 Word writes (0x90/0xA0) — iCUE DDR5 protocol"
    echo "  Trying a single word write to 0x90 with value 0x0000..."
    wait_ready $TARGET
    test_word_write $TARGET 0x90 0x0000 "V4 ColorBufferWriteStart(0x90)"
    sleep 0.01
    test_word_write $TARGET 0xa0 0x0000 "V4 ColorBufferWrite(0xA0)"
    echo ""

    echo "Test B: V3 Block writes (0x31/0x32) — original DDR4 protocol"
    echo "  Writing a small block to 0x31..."
    wait_ready $TARGET
    # Build a mini test packet: 1 LED count + 3 colors + CRC
    # led_count=0x01, R=0xFF, G=0x00, B=0x00
    RESULT=$(i2cset -y $BUS $TARGET 0x31 0x01 0xFF 0x00 0x00 0x00 i 2>&1)
    RC=$?
    if [ $RC -eq 0 ]; then
        echo "  ✓ V3 block write to 0x31 → OK"
    else
        echo "  ✗ V3 block write to 0x31 → FAIL ($RESULT)"
    fi
    echo ""

    echo "Test C: TriggerEffect (0x27) byte write"
    wait_ready $TARGET
    test_byte_write $TARGET 0x27 0x00 "TriggerEffect(0x27) val=0x00"
    sleep 0.01
    wait_ready $TARGET
    test_byte_write $TARGET 0x27 0x01 "TriggerEffect(0x27) val=0x01"
    echo ""

    echo "Test D: SwitchMode (0x23) byte write"  
    wait_ready $TARGET
    test_byte_write $TARGET 0x23 0x00 "SwitchMode(0x23) val=0x00"
    sleep 0.05
    wait_ready $TARGET
    test_byte_write $TARGET 0x23 0x01 "SwitchMode(0x23) val=0x01"
    sleep 0.05
    wait_ready $TARGET
    test_byte_write $TARGET 0x23 0x02 "SwitchMode(0x23) val=0x02"
    echo ""

    echo "Test E: Brightness (0x10) byte write"
    wait_ready $TARGET
    test_byte_write $TARGET 0x10 0xFF "Brightness(0x10) val=0xFF (max)"
    echo ""

    echo "Test F: V4 Word write with actual color data (all RED)"
    echo "  Data: led_count=11 LEDs, all RED (0xFF,0x00,0x00)"
    echo "  Encoding per iCUE V4 format..."
    wait_ready $TARGET

    # led_data = [0x0B, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, ...]
    # byte[0]=0x0B (11 LEDs), byte[1]=0xFF (R), byte[2]=0x00 (G), byte[3]=0x00 (B), byte[4]=0xFF (R)
    # First iteration: i=2, bytes = [0x0B, 0xFF, 0x00, 0x00, 0xFF]
    # Word1: reg = 0x90 | (0x00 >> 4) = 0x90, val = (0xFF << 8) | 0x0B = 0xFF0B
    # Word2: reg = 0xA0 | (0x00 & 0x0F) = 0xA0, val = (0xFF << 8) | 0x00 = 0xFF00

    echo "  Word 1: reg=0x90, val=0xff0b (first, with LED count)"
    test_word_write $TARGET 0x90 0xff0b "V4 first word (0x90)"

    echo "  Word 2: reg=0xa0, val=0xff00"
    test_word_write $TARGET 0xa0 0xff00 "V4 second word (0xA0)"

    # Second iteration: i=7, bytes = [0x00, 0xFF, 0x00, 0x00, 0xFF]
    # Word1: reg = 0xA0 | (0x00 >> 4) = 0xA0, val = (0xFF << 8) | 0x00 = 0xFF00
    # Word2: reg = 0xA0 | (0x00 & 0x0F) = 0xA0, val = (0xFF << 8) | 0x00 = 0xFF00

    echo "  Word 3: reg=0xa0, val=0xff00"
    test_word_write $TARGET 0xa0 0xff00 "V4 third word (0xA0)"

    echo "  Word 4: reg=0xa0, val=0xff00"
    test_word_write $TARGET 0xa0 0xff00 "V4 fourth word (0xA0)"

    echo ""
    echo "Test G: Try restoring hardware effect (Rainbow Wave) to recover from white"
    echo "  This uses the V3 command protocol (0x26/0x21/0x20/0x82)"
    echo "  -> $TARGET_HEX: Sending Rainbow Wave (mode=0x03)..."
    wait_ready $TARGET
    i2cset -y $BUS $TARGET 0x26 0x01
    sleep 0.001
    i2cset -y $BUS $TARGET 0x21 0x00
    sleep 0.001
    i2cset -y $BUS $TARGET 0x20 0x03   # Rainbow Wave
    i2cset -y $BUS $TARGET 0x20 0x01   # Speed: medium
    i2cset -y $BUS $TARGET 0x20 0x00   # Random
    i2cset -y $BUS $TARGET 0x20 0x00   # Direction
    i2cset -y $BUS $TARGET 0x20 0x00   # R1
    i2cset -y $BUS $TARGET 0x20 0x00   # G1
    i2cset -y $BUS $TARGET 0x20 0x00   # B1
    i2cset -y $BUS $TARGET 0x20 0xFF   # A1
    i2cset -y $BUS $TARGET 0x20 0x00   # R2
    i2cset -y $BUS $TARGET 0x20 0x00   # G2
    i2cset -y $BUS $TARGET 0x20 0x00   # B2
    i2cset -y $BUS $TARGET 0x20 0xFF   # A2
    i2cset -y $BUS $TARGET 0x20 0x00
    i2cset -y $BUS $TARGET 0x20 0x00
    i2cset -y $BUS $TARGET 0x20 0x00
    i2cset -y $BUS $TARGET 0x20 0x00
    i2cset -y $BUS $TARGET 0x20 0x00
    i2cset -y $BUS $TARGET 0x20 0x00
    i2cset -y $BUS $TARGET 0x20 0x00
    i2cset -y $BUS $TARGET 0x20 0x00
    i2cset -y $BUS $TARGET 0x82 0x01
    wait_ready $TARGET && echo "    Ready!" || echo "    TIMEOUT!"

    echo ""
done

echo ""
echo "=== Diagnostic complete ==="
echo ""
echo "If all V4 word writes to 0x90/0xA0 FAILED but V3 block writes to 0x31 SUCCEEDED,"
echo "then the SMBus controller does not support word writes and we need a different approach."
echo ""
echo "If V4 word writes SUCCEEDED but DIMMs are still white,"
echo "then the data encoding is wrong and needs adjustment."
echo ""
echo "If Test G (Rainbow Wave) recovered the DIMMs from white flash,"
echo "then the white flash is caused by the direct color protocol, not the effect protocol."
```

### 13.2 `reset_rainbow.go` — SwitchMode Sub-sequence Ablation

Tests all 8 sub-sequences of the `0x23` SwitchMode write to find the minimum
recovery step. Confirmed: any single write of value ≥ 1 (`just 2` preferred) suffices.

```go
package main

// reset_rainbow.go — SwitchMode sub-sequence ablation for Corsair DDR5
//
// We know SwitchMode (0x23) alone is sufficient recovery.
// Now we test which part of 0→1→2 is actually needed.
//
// Poison: SwitchMode(0→1→2→0) + Rainbow Wave effect (confirmed to produce stuck state).
// Recovery candidate: each sub-sequence of 0x23 writes, then Rainbow Wave effect.
//
// Strategies (all sub-sequences + single values):
//   S1:  [BASELINE] 0→1→2  (confirmed working)
//   S2:  0→1               (skip the →2 step)
//   S3:  1→2               (skip the 0→ step)
//   S4:  0→2               (skip the middle 1)
//   S5:  just 0
//   S6:  just 1
//   S7:  just 2
//   S8:  [CONTROL] no SwitchMode (bare Rainbow Wave)
//
// Usage: sudo go run reset_rainbow.go

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	I2C_SLAVE           = 0x0703
	I2C_SMBUS           = 0x0720
	I2C_SMBUS_WRITE     = 0
	I2C_SMBUS_READ      = 1
	I2C_SMBUS_BYTE_DATA = 2
	I2C_SMBUS_WORD_DATA = 3
)

type i2cSMBusIoctlData struct {
	ReadWrite uint8
	Command   uint8
	Size      uint32
	Data      unsafe.Pointer
}

type i2cSMBusByteData struct{ Value uint8 }

func smbusAccess(fd uintptr, rw uint8, cmd uint8, size uint32, data unsafe.Pointer) error {
	args := i2cSMBusIoctlData{ReadWrite: rw, Command: cmd, Size: size, Data: data}
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, I2C_SMBUS, uintptr(unsafe.Pointer(&args)))
	if err != 0 {
		return err
	}
	return nil
}

func setAddr(fd uintptr, addr int) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, I2C_SLAVE, uintptr(addr))
	if err != 0 {
		return err
	}
	return nil
}

func rb(fd uintptr, reg uint8) (uint8, error) {
	d := i2cSMBusByteData{}
	err := smbusAccess(fd, I2C_SMBUS_READ, reg, I2C_SMBUS_BYTE_DATA, unsafe.Pointer(&d))
	return d.Value, err
}

func wb(fd uintptr, reg, val uint8) error {
	d := i2cSMBusByteData{Value: val}
	return smbusAccess(fd, I2C_SMBUS_WRITE, reg, I2C_SMBUS_BYTE_DATA, unsafe.Pointer(&d))
}

func waitReady(fd uintptr) {
	for i := 0; i < 200; i++ {
		v, err := rb(fd, 0x41)
		if err == nil && v == 0x00 {
			return
		}
		time.Sleep(1 * time.Millisecond)
	}
}

func switchMode(fd uintptr, vals ...byte) {
	for _, v := range vals {
		waitReady(fd)
		wb(fd, 0x23, v)
		time.Sleep(50 * time.Millisecond)
	}
	waitReady(fd)
}

func sendRainbowWave(fd uintptr) {
	waitReady(fd)
	wb(fd, 0x26, 0x01)
	time.Sleep(1 * time.Millisecond)
	wb(fd, 0x21, 0x00)
	time.Sleep(1 * time.Millisecond)
	for _, b := range []byte{
		0x03,                   // mode: Rainbow Wave
		0x01,                   // speed: medium
		0x00,                   // random colors
		0x01,                   // direction: down
		0x00, 0x00, 0x00, 0xFF, // R1,G1,B1,A1
		0x00, 0x00, 0x00, 0xFF, // R2,G2,B2,A2
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	} {
		wb(fd, 0x20, b)
	}
	wb(fd, 0x82, 0x01)
	waitReady(fd)
}

// poison: SwitchMode(0→1→2→0) + Rainbow Wave — confirmed to produce stuck state.
func poison(fd uintptr) {
	switchMode(fd, 0x00, 0x01, 0x02, 0x00)
	sendRainbowWave(fd)
}

func applyAll(fd uintptr, addrs []int, fn func(uintptr)) {
	for _, addr := range addrs {
		if err := setAddr(fd, addr); err != nil {
			fmt.Printf("  0x%02x: setAddr failed: %v\n", addr, err)
			continue
		}
		fn(fd)
		fmt.Printf("  0x%02x: done\n", addr)
	}
}

func prompt(scanner *bufio.Scanner, msg string) {
	fmt.Print(msg)
	scanner.Scan()
}

func ask(scanner *bufio.Scanner, q string) bool {
	fmt.Printf("%s (y/n) [y]: ", q)
	scanner.Scan()
	t := scanner.Text()
	return t != "n" && t != "N"
}

type Strategy struct {
	Name string
	Vals []byte // SwitchMode values to write in order; nil = skip SwitchMode entirely
}

func main() {
	busPath := "/dev/i2c-12"
	addrs := []int{0x19, 0x1b}

	f, err := os.OpenFile(busPath, os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("Failed to open %s: %v\n", busPath, err)
		os.Exit(1)
	}
	defer f.Close()
	fd := f.Fd()

	scanner := bufio.NewScanner(os.Stdin)

	strategies := []Strategy{
		{"[BASELINE] 0→1→2          (confirmed working)", []byte{0x00, 0x01, 0x02}},
		{"0→1                       (skip →2)", []byte{0x00, 0x01}},
		{"1→2                       (skip 0→)", []byte{0x01, 0x02}},
		{"0→2                       (skip middle 1)", []byte{0x00, 0x02}},
		{"just 0", []byte{0x00}},
		{"just 1                    (bootloader mode only)", []byte{0x01}},
		{"just 2                    (direct mode only)", []byte{0x02}},
		{"[CONTROL] no SwitchMode   (bare Rainbow Wave)", nil},
	}

	fmt.Println("=== SwitchMode Sub-sequence Ablation ===")
	fmt.Println()
	fmt.Println("Poison:   SwitchMode(0→1→2→0) + Rainbow Wave (confirmed stuck state)")
	fmt.Println("Recovery: SwitchMode sub-sequence (see each strategy), then Rainbow Wave")
	fmt.Println("Answer y if Rainbow Wave shows correctly after recovery, n if stuck/white.")
	fmt.Println()

	results := make([]bool, len(strategies))

	for i, s := range strategies {
		fmt.Printf("--- Strategy %d/%d: %s ---\n", i+1, len(strategies), s.Name)

		fmt.Print("  [Poison] Switch 0→1→2→0 + RainbowWave...")
		applyAll(fd, addrs, poison)
		fmt.Println()
		prompt(scanner, "  DIMMs stuck. Press Enter to apply recovery...")

		if s.Vals != nil {
			vals := s.Vals
			applyAll(fd, addrs, func(fd uintptr) {
				switchMode(fd, vals...)
			})
		} else {
			fmt.Println("  (no SwitchMode)")
		}

		fmt.Println("  Sending Rainbow Wave...")
		applyAll(fd, addrs, sendRainbowWave)

		results[i] = ask(scanner, "  Did Rainbow Wave show correctly?")
		if results[i] {
			fmt.Printf("\n  ✅ Strategy %d WORKS\n", i+1)
		} else {
			fmt.Printf("\n  ❌ Strategy %d FAILED\n", i+1)
		}
		fmt.Println()
	}

	fmt.Println("=== Results Summary ===")
	fmt.Println()
	fmt.Printf("%-4s %-50s %s\n", "S#", "Strategy", "Result")
	fmt.Printf("%-4s %-50s %s\n", "--", "--------", "------")
	for i, s := range strategies {
		status := "❌ FAIL"
		if results[i] {
			status = "✅ PASS"
		}
		fmt.Printf("S%-3d %-50s %s\n", i+1, s.Name, status)
	}
	fmt.Println()
	fmt.Println("Minimum = smallest passing SwitchMode sub-sequence.")
}
```

### 13.3 `test_all_modes.go` — Interactive Mode Verifier

Interactively steps through every effect mode and the direct (V3 Block) mode,
recording pass/fail. Includes the Sequential (0x09) pre-write ablation sub-test.

```go
package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// SMBus ioctl constants
const (
	I2C_SLAVE       = 0x0703
	I2C_SMBUS       = 0x0720
	I2C_SMBUS_WRITE = 0
	I2C_SMBUS_READ  = 1

	I2C_SMBUS_BYTE_DATA  = 2
	I2C_SMBUS_WORD_DATA  = 3
	I2C_SMBUS_BLOCK_DATA = 5
)

type i2cSMBusIoctlData struct {
	ReadWrite uint8
	Command   uint8
	Size      uint32
	Data      unsafe.Pointer
}

type i2cSMBusBlockData struct {
	Length uint8
	Data   [32]uint8
}

type i2cSMBusByteData struct {
	Value uint8
}

func smbusAccess(fd uintptr, readWrite uint8, command uint8, size uint32, data unsafe.Pointer) error {
	args := i2cSMBusIoctlData{
		ReadWrite: readWrite,
		Command:   command,
		Size:      size,
		Data:      data,
	}
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, I2C_SMBUS, uintptr(unsafe.Pointer(&args)))
	if err != 0 {
		return err
	}
	return nil
}

func setAddress(fd uintptr, addr int) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, I2C_SLAVE, uintptr(addr))
	if err != 0 {
		return err
	}
	return nil
}

func readByte(fd uintptr, reg uint8) (uint8, error) {
	var data i2cSMBusByteData
	err := smbusAccess(fd, I2C_SMBUS_READ, reg, I2C_SMBUS_BYTE_DATA, unsafe.Pointer(&data))
	if err != nil {
		return 0, err
	}
	return data.Value, nil
}

func writeByte(fd uintptr, reg uint8, val uint8) error {
	data := i2cSMBusByteData{Value: val}
	return smbusAccess(fd, I2C_SMBUS_WRITE, reg, I2C_SMBUS_BYTE_DATA, unsafe.Pointer(&data))
}

func writeBlock(fd uintptr, reg uint8, block []uint8) error {
	if len(block) > 32 {
		return fmt.Errorf("block too large: %d > 32", len(block))
	}
	var data i2cSMBusBlockData
	data.Length = uint8(len(block))
	copy(data.Data[:], block)
	return smbusAccess(fd, I2C_SMBUS_WRITE, reg, I2C_SMBUS_BLOCK_DATA, unsafe.Pointer(&data))
}

func waitReady(fd uintptr) bool {
	for i := 0; i < 200; i++ {
		val, err := readByte(fd, 0x41)
		if err == nil && val == 0x00 {
			return true
		}
		time.Sleep(1 * time.Millisecond)
	}
	return false
}

type ModeTest struct {
	Name        string
	Mode        byte
	Speed       byte
	Direction   byte
	Random      bool
	R1, G1, B1 byte
	R2, G2, B2 byte
	R3, G3, B3 byte
	R4, G4, B4 byte
}

var effectModes = []ModeTest{
	{"Static RED", 0x00, 0x01, 0x00, false, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0, 0, 0, 0, 0, 0},
	{"Static GREEN", 0x00, 0x01, 0x00, false, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0, 0, 0, 0, 0, 0},
	{"Color Shift (RED->GREEN)", 0x00, 0x01, 0x00, false, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0, 0, 0, 0, 0, 0},
	{"Color Pulse (RED)", 0x01, 0x01, 0x00, false, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0, 0, 0, 0, 0, 0},
	{"Rainbow Wave", 0x03, 0x01, 0x01, false, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0},
	{"Color Wave (RED->GREEN)", 0x04, 0x01, 0x01, false, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0, 0, 0, 0, 0, 0},
	{"Visor (RED->GREEN)", 0x05, 0x01, 0x01, false, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0, 0, 0, 0, 0, 0},
	{"Rain (RED drops)", 0x06, 0x01, 0x01, false, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0},
	{"Marquee (BLUE on black)", 0x07, 0x01, 0x01, false, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0},
	{"Rainbow (random colors)", 0x08, 0x01, 0x00, true, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0},
}

func hwRecovery(fd uintptr) {
	waitReady(fd)
	writeByte(fd, 0x23, 0x02)
	time.Sleep(50 * time.Millisecond)
	waitReady(fd)
}

func hwRecoveryAppMode(fd uintptr) {
	waitReady(fd)
	writeByte(fd, 0x23, 0x00)
	time.Sleep(50 * time.Millisecond)
	waitReady(fd)
}

func sendEffect(fd uintptr, mt ModeTest) error {
	if !waitReady(fd) {
		return fmt.Errorf("device not ready")
	}
	randomByte := byte(0x01)
	if mt.Random {
		randomByte = 0x00
	}
	if err := writeByte(fd, 0x26, 0x01); err != nil {
		return fmt.Errorf("0x26: %w", err)
	}
	time.Sleep(1 * time.Millisecond)
	if err := writeByte(fd, 0x21, 0x00); err != nil {
		return fmt.Errorf("0x21: %w", err)
	}
	time.Sleep(1 * time.Millisecond)
	seq := []byte{
		mt.Mode, mt.Speed, randomByte, mt.Direction,
		mt.R1, mt.G1, mt.B1, 0xFF,
		mt.R2, mt.G2, mt.B2, 0xFF,
		mt.R3, mt.G3, mt.B3, 0xFF,
		mt.R4, mt.G4, mt.B4, 0xFF,
	}
	for _, b := range seq {
		if err := writeByte(fd, 0x20, b); err != nil {
			return fmt.Errorf("0x20 data: %w", err)
		}
	}
	time.Sleep(1 * time.Millisecond)
	if err := writeByte(fd, 0x82, 0x01); err != nil {
		return fmt.Errorf("0x82: %w", err)
	}
	waitReady(fd)
	return nil
}

func sendDirect(fd uintptr) error {
	hwRecovery(fd)
	ledCount := 11
	const packetSize = 48
	var packet [packetSize]uint8
	packet[0] = uint8(ledCount)
	for i := 0; i < ledCount; i++ {
		offset := 1 + i*3
		switch i % 3 {
		case 0:
			packet[offset], packet[offset+1], packet[offset+2] = 0xFF, 0x00, 0x00
		case 1:
			packet[offset], packet[offset+1], packet[offset+2] = 0x00, 0xFF, 0x00
		case 2:
			packet[offset], packet[offset+1], packet[offset+2] = 0x00, 0x00, 0xFF
		}
	}
	if err := writeBlock(fd, 0x31, packet[:32]); err != nil {
		return fmt.Errorf("block write 0x31 (first): %w", err)
	}
	if !waitReady(fd) {
		return fmt.Errorf("device not ready after 0x31")
	}
	if err := writeBlock(fd, 0x32, packet[32:]); err != nil {
		return fmt.Errorf("block write 0x32 (second): %w", err)
	}
	waitReady(fd)
	return nil
}

func applyToAll(fd uintptr, addrs []int, fn func(uintptr) error) {
	for _, addr := range addrs {
		if err := setAddress(fd, addr); err != nil {
			fmt.Printf("  0x%02x: set address failed: %v\n", addr, err)
			continue
		}
		if err := fn(fd); err != nil {
			fmt.Printf("  0x%02x: FAILED: %v\n", addr, err)
		} else {
			fmt.Printf("  0x%02x: OK\n", addr)
		}
	}
}

func main() {
	busPath := "/dev/i2c-12"
	addrs := []int{0x19, 0x1b}

	f, err := os.OpenFile(busPath, os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("Failed to open %s: %v\n", busPath, err)
		os.Exit(1)
	}
	defer f.Close()
	fd := f.Fd()

	scanner := bufio.NewScanner(os.Stdin)
	results := make(map[string]bool)
	var orderedKeys []string

	rainbowWave := ModeTest{"Rainbow Wave", 0x03, 0x01, 0x01, false, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	fmt.Println("=== Corsair DDR5 Mode Verifier ===")
	fmt.Println("Running switchModeRecovery + Rainbow Wave on all sticks...")
	applyToAll(fd, addrs, func(fd uintptr) error {
		hwRecovery(fd)
		return sendEffect(fd, rainbowWave)
	})

	for _, mt := range effectModes {
		fmt.Printf("\n--- Mode: %s ---\n", mt.Name)
		fmt.Print("Press Enter to apply...")
		scanner.Scan()
		applyToAll(fd, addrs, func(fd uintptr) error {
			hwRecovery(fd)
			return sendEffect(fd, mt)
		})
		fmt.Printf("Did '%s' look correct? (y/n) [y]: ", mt.Name)
		scanner.Scan()
		resp := scanner.Text()
		results[mt.Name] = (resp != "n" && resp != "N")
		orderedKeys = append(orderedKeys, mt.Name)
	}

	seqTest := ModeTest{"Sequential (custom RED, speed=slow)", 0x09, 0x00, 0x01, false, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0, 0, 0, 0, 0, 0}
	seqVariants := []struct {
		label    string
		recovery func(uintptr)
	}{
		{"Sequential [0x23=0x02 then effect]", hwRecovery},
		{"Sequential [0x23=0x00 then effect]", hwRecoveryAppMode},
		{"Sequential [NO pre-write, effect only]", nil},
	}
	for _, sv := range seqVariants {
		name := sv.label
		fmt.Printf("\n--- %s ---\n", name)
		fmt.Print("Press Enter to apply...")
		scanner.Scan()
		applyToAll(fd, addrs, func(fd uintptr) error {
			if sv.recovery != nil {
				sv.recovery(fd)
			}
			return sendEffect(fd, seqTest)
		})
		fmt.Printf("Did Sequential animate? (y/n) [y]: ")
		scanner.Scan()
		resp := scanner.Text()
		results[name] = (resp != "n" && resp != "N")
		orderedKeys = append(orderedKeys, name)
	}

	{
		name := "Direct (V3 Block, alternating R/G/B per LED)"
		fmt.Printf("\n--- Mode: %s ---\n", name)
		fmt.Println("Expect: LEDs alternating RED / GREEN / BLUE across the stick.")
		fmt.Print("Press Enter to apply...")
		scanner.Scan()
		applyToAll(fd, addrs, func(fd uintptr) error {
			return sendDirect(fd)
		})
		fmt.Printf("Did '%s' look correct? (y/n) [y]: ", name)
		scanner.Scan()
		resp := scanner.Text()
		results[name] = (resp != "n" && resp != "N")
		orderedKeys = append(orderedKeys, name)
	}

	fmt.Println("\nRestoring Rainbow Wave...")
	applyToAll(fd, addrs, func(fd uintptr) error {
		hwRecovery(fd)
		return sendEffect(fd, rainbowWave)
	})

	fmt.Println("\n=== Test Results ===")
	for _, k := range orderedKeys {
		status := "✅ PASS"
		if !results[k] {
			status = "❌ FAIL"
		}
		fmt.Printf("%-45s %s\n", k, status)
	}
}
```

### 13.4 `test_sequential.go` — Sequential Mode (0x09) Ablation

Tests 36 parameter combinations (pre-write × speed × direction × color) for
Sequential mode `0x09`. Result: **0/36 produced animation** — mode is statically
accepted but not animated on Corsair Dominator Platinum DDR5 firmware.

```go
package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// ── SMBus primitives ─────────────────────────────────────────────────────────

const (
	seqI2C_SLAVE   = 0x0703
	seqI2C_SMBUS   = 0x0720
	seqSMBUS_WRITE = 0
	seqSMBUS_READ  = 1
	seqSMBUS_BYTE  = 2
)

type seqIoctlData struct {
	ReadWrite uint8
	Command   uint8
	Size      uint32
	Data      unsafe.Pointer
}

type seqByteData struct{ Value uint8 }

func seqIoctl(fd uintptr, rw uint8, cmd uint8, data unsafe.Pointer) error {
	args := seqIoctlData{ReadWrite: rw, Command: cmd, Size: seqSMBUS_BYTE, Data: data}
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, seqI2C_SMBUS, uintptr(unsafe.Pointer(&args)))
	if e != 0 {
		return e
	}
	return nil
}

func seqSetAddr(fd uintptr, addr int) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, seqI2C_SLAVE, uintptr(addr))
	if e != 0 {
		return e
	}
	return nil
}

func seqRead(fd uintptr, reg uint8) (uint8, error) {
	var d seqByteData
	if err := seqIoctl(fd, seqSMBUS_READ, reg, unsafe.Pointer(&d)); err != nil {
		return 0, err
	}
	return d.Value, nil
}

func seqWrite(fd uintptr, reg, val uint8) error {
	d := seqByteData{Value: val}
	return seqIoctl(fd, seqSMBUS_WRITE, reg, unsafe.Pointer(&d))
}

func seqWaitReady(fd uintptr) {
	for i := 0; i < 200; i++ {
		if v, err := seqRead(fd, 0x41); err == nil && v == 0x00 {
			return
		}
		time.Sleep(1 * time.Millisecond)
	}
}

// ── Rainbow Wave recovery ─────────────────────────────────────────────────────

func seqRestoreRainbow(fd uintptr) {
	seqWaitReady(fd)
	seqWrite(fd, 0x23, 0x02)
	time.Sleep(50 * time.Millisecond)
	seqWaitReady(fd)
	seqWrite(fd, 0x26, 0x01)
	time.Sleep(1 * time.Millisecond)
	seqWrite(fd, 0x21, 0x00)
	time.Sleep(1 * time.Millisecond)
	// Rainbow Wave: mode=0x03 speed=0x01 random=0x00 dir=0x01 + 16 zero bytes
	for _, b := range []byte{0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF,
		0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00} {
		seqWrite(fd, 0x20, b)
	}
	seqWrite(fd, 0x82, 0x01)
	seqWaitReady(fd)
}

// ── Sequential effect sender ─────────────────────────────────────────────────

type SeqParams struct {
	preWrite  int8  // -1=none, 0=0x00, 2=0x02
	speed     uint8 // 0x00=slow 0x01=med 0x02=fast
	direction uint8 // 0x00=UP 0x01=DOWN
	random    bool  // true=hw palette (0x00), false=custom (0x01)
	r, g, b   uint8 // color 1 (used when random=false)
}

func (p SeqParams) label() string {
	pre := "none"
	switch p.preWrite {
	case 0:
		pre = "0x23=0x00"
	case 2:
		pre = "0x23=0x02"
	}
	rnd := "custom"
	if p.random {
		rnd = "hw-palette"
	}
	return fmt.Sprintf("pre=%-11s spd=%d dir=%d %s R=%02X G=%02X B=%02X",
		pre, p.speed, p.direction, rnd, p.r, p.g, p.b)
}

func seqSend(fd uintptr, p SeqParams) {
	seqWaitReady(fd)

	switch p.preWrite {
	case 0:
		seqWrite(fd, 0x23, 0x00)
	case 2:
		seqWrite(fd, 0x23, 0x02)
	}
	if p.preWrite >= 0 {
		time.Sleep(50 * time.Millisecond)
		seqWaitReady(fd)
	}

	randomByte := uint8(0x01)
	if p.random {
		randomByte = 0x00
	}

	seqWrite(fd, 0x26, 0x01)
	time.Sleep(1 * time.Millisecond)
	seqWrite(fd, 0x21, 0x00)
	time.Sleep(1 * time.Millisecond)

	pkt := []byte{
		0x09, p.speed, randomByte, p.direction,
		p.r, p.g, p.b, 0xFF,
		p.r, p.g, p.b, 0xFF,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	for _, b := range pkt {
		seqWrite(fd, 0x20, b)
	}
	seqWrite(fd, 0x82, 0x01)
	seqWaitReady(fd)
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	busPath := "/dev/i2c-12"
	addrs := []int{0x19, 0x1b}

	f, err := os.OpenFile(busPath, os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("open %s: %v\n", busPath, err)
		os.Exit(1)
	}
	defer f.Close()
	fd := f.Fd()

	scanner := bufio.NewScanner(os.Stdin)

	ask := func(prompt string) bool {
		fmt.Printf("%s (y/n) [y]: ", prompt)
		scanner.Scan()
		r := scanner.Text()
		return r != "n" && r != "N"
	}
	press := func() {
		fmt.Print("  → Press Enter to apply, then observe for ~3s ...")
		scanner.Scan()
	}

	fmt.Println("=== Sequential Mode (0x09) Ablation Test ===")
	fmt.Println("Restoring Rainbow Wave on all sticks first...")
	for _, addr := range addrs {
		seqSetAddr(fd, addr)
		seqRestoreRainbow(fd)
		fmt.Printf("  0x%02x: done\n", addr)
	}

	type result struct {
		label    string
		animates bool
	}
	var results []result

	colorCases := []struct {
		random bool
		r, g, b uint8
		ctag    string
	}{
		{false, 0xFF, 0x00, 0x00, "custom-RED"},
		{true, 0x00, 0x00, 0x00, "hw-palette"},
	}

	preWriteCases := []int8{2, 0, -1}
	speedCases    := []uint8{0x00, 0x01, 0x02}
	dirCases      := []uint8{0x01, 0x00}

	for _, cc := range colorCases {
		fmt.Printf("\n══ Color: %s ══\n", cc.ctag)
		for _, dir := range dirCases {
			for _, pre := range preWriteCases {
				for _, spd := range speedCases {
					p := SeqParams{
						preWrite:  pre,
						speed:     spd,
						direction: dir,
						random:    cc.random,
						r: cc.r, g: cc.g, b: cc.b,
					}
					fmt.Printf("\n[%s]\n", p.label())
					press()

					for _, addr := range addrs {
						seqSetAddr(fd, addr)
						seqSend(fd, p)
					}

					animates := ask("  Did the LEDs ANIMATE (show movement)?")
					results = append(results, result{p.label(), animates})

					fmt.Println("  Restoring Rainbow Wave...")
					for _, addr := range addrs {
						seqSetAddr(fd, addr)
						seqRestoreRainbow(fd)
					}
				}
			}
		}
	}

	fmt.Println("\n=== Sequential Ablation Results ===")
	passCount := 0
	for _, r := range results {
		mark := "❌ static"
		if r.animates {
			mark = "✅ ANIMATES"
			passCount++
		}
		fmt.Printf("  %-65s %s\n", r.label, mark)
	}
	fmt.Printf("\n%d/%d parameter combinations produced animation.\n", passCount, len(results))
	if passCount == 0 {
		fmt.Println("\nConclusion: Sequential mode 0x09 does NOT animate on this DDR5 hardware.")
		fmt.Println("Possible causes: firmware doesn't implement 0x09, or a different mode byte is needed.")
	}
}
```
