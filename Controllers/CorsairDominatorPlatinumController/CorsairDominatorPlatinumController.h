/*---------------------------------------------------------*\
| CorsairDominatorPlatinumController.h                      |
|                                                           |
|   Driver for Corsair Dominator Platinum RAM               |
|   Supports both DDR4 and DDR5 via V3 Block protocol      |
|                                                           |
|   Erik Gilling (konkers)                      25 Sep 2020 |
|                                                           |
|   This file is part of the OpenRGB project                |
|   SPDX-License-Identifier: GPL-2.0-or-later               |
\*---------------------------------------------------------*/

/*---------------------------------------------------------*\
| =========================================================|
| CORSAIR DDR5 PROTOCOL — COMPLETE FINDINGS                |
| (from iCUE v5.42 reverse engineering + diag_v4.sh)       |
| =========================================================|
|                                                           |
| HARDWARE SETUP:                                           |
|   Bus:     i2c-12 (piix4_smbus, AMD)                     |
|   DIMM 1:  0x19 (Corsair Dominator Platinum RGB DDR5)    |
|   DIMM 2:  0x1b (Corsair Dominator Platinum RGB DDR5)    |
|   ID Reg:  0x43 = 0x1a (Corsair RGB controller)          |
|   Adapter: piix4 — byte+word+block writes OK via kernel   |
|                                                           |
| ---------------------------------------------------------|
| PROTOCOL VERSIONS:                                        |
| ---------------------------------------------------------|
|                                                           |
| V3 Block Protocol (DDR4 + DDR5):                          |
|   Registers: 0x31 (ColorBufferBlockStart),                |
|              0x32 (ColorBufferBlock)                      |
|   SMBus op:  i2c_smbus_write_block_data (32 bytes/write) |
|   i2cset fails, but kernel ioctl(I2C_SMBUS) C API works  |
|   iCUE class: LightingWriterV4Block (same wire format)   |
|   Per-LED color control confirmed on DDR5 (2026-03-11)   |
|                                                           |
| V3 Command Protocol (Effects — both DDR4+DDR5):          |
|   Registers: 0x26, 0x21, 0x20, 0x82                      |
|   SMBus op:  i2c_smbus_write_byte_data (universally OK)  |
|   Used for HW effects (Rainbow Wave, Static, etc.)       |
|                                                           |
| ---------------------------------------------------------|
| PROTOCOL DETECTION — CRITICAL:                            |
| ---------------------------------------------------------|
|                                                           |
| DO NOT use reg 0x44 for detection! It is a volatile state |
| flag that alternates between sticks across runs.          |
| iCUE uses SMBusGetCaps adapter probing, not reg44.        |
|                                                           |
| DDR generation by I2C address (fixed by hardware):        |
|   0x18-0x1F = DDR5   (SPD at 0x50+N)                     |
|   0x58-0x5F = DDR4   (SPD at 0x50+N)                     |
| Both use V3 Block protocol (0x31/0x32) for color writes. |
|                                                           |
| ---------------------------------------------------------|
| DIAG TEST RESULTS (commit 845ded22):                      |
| ---------------------------------------------------------|
|                                                           |
| V3 block writes via kernel C API (0x31/0x32) → WORKS     |
|   (i2cset fails, but ioctl(I2C_SMBUS) succeeds)          |
| Effect protocol (0x26/0x21/0x20/0x82)       → WORKS      |
| Rainbow Wave recovery from white flash      → WORKS      |
|                                                           |
| Key findings:                                             |
|   1. V3 Block works for DDR5 via kernel API               |
|   2. Effect protocol works on both DDR4 and DDR5          |
|   3. Rainbow Wave ALWAYS recovers from white flash       |
|                                                           |
| ---------------------------------------------------------|
| WHITE FLASH — ROOT CAUSE & RECOVERY:                      |
| ---------------------------------------------------------|
|                                                           |
| CAUSE: DIMM enters direct mode (software-controlled) and |
| software stops sending color updates. Controller has no   |
| stored colors → defaults to white.                        |
|                                                           |
| Triggers:                                                 |
|   - SwitchMode (0x23) cycling, esp. leaving in mode 0x02 |
|   - V4 word writes followed by no further updates        |
|   - Brightness changes can also trigger it               |
|                                                           |
| RECOVERY — CONFIRMED ABSOLUTE MINIMUM (2026-03-12):       |
| Sub-sequence ablation (8 strategies, 2 runs):              |
|   1. Write SwitchMode: 0x23 = 0x02  (one write, 50ms)     |
|   2. Send effect command (0x26/0x21/0x20×20/0x82)          |
|                                                           |
|   Any write of 0x23 ≥ 1 works (S6:just1, S7:just2 both   |
|   pass). 0x02 preferred; 0x01 (bootloader) is dangerous.  |
|   Stuck state has DIMMs at 0x00 already — repeating 0x00  |
|   is a no-op (S5 fails). The 0→1→2 cycle is redundant.   |
|                                                           |
| ---------------------------------------------------------|
| DANGEROUS OPERATIONS:                                     |
| ---------------------------------------------------------|
|                                                           |
| SwitchMode (0x23) NAK cascade:                            |
|   Writing 0x23 0x01 (bootloader) after certain ops can   |
|   put the controller into PERMANENT NAK state — rejects  |
|   ALL subsequent writes. Only power cycle recovers.       |
|   Safe pattern: 0x00→0x01→0x02 with wait_ready() between.|
|                                                           |
| ---------------------------------------------------------|
| iCUE ARCHITECTURE REFERENCE:                              |
| ---------------------------------------------------------|
|                                                           |
| Protocol classes (CorsairDeviceControlService.exe v5.42): |
|   LightingWriterV3     → DDR4 Vengeance RGB Pro          |
|   LightingWriterV4Block → DDR5 with block support        |
|   LightingWriterV4Word → DDR5 without block support      |
|                                                           |
| Session recovery (prevents white flash):                  |
|   1. Session end: re-enables HW effects                   |
|   2. Crash recovery: handles stuck bootloader mode        |
|   3. Brightness caching: restores on reconnect            |
|                                                           |
| SMBus locking: iCUE uses SMBusLocker (RAII) to lock bus  |
| for entire transactions — OpenRGB should do the same.     |
|                                                           |
| ---------------------------------------------------------|
| REGISTER MAP:                                             |
| ---------------------------------------------------------|
|                                                           |
| 0x10  Bightness(sic)   R/W byte  0x00-0xFF              |
| 0x20  SetBinaryData     W byte    Effect command data     |
| 0x21  BinaryStart       W byte    Start data transfer     |
| 0x23  SwitchMode        R/W byte  0=app,1=boot,2=direct  |
| 0x24  SwitchMode(alias) R/W byte  Same handler as 0x23    |
| 0x26  *(pass-thru)*     W byte    0x01=effect,0x02=store  |
| 0x27  TriggerEffect     W byte    Commit staged colors    |
| 0x28  ApplyFullDirect   W byte    V3 direct (≤32 bytes)  |
| 0x29  ApplyHalfDirect   W byte    V3 direct (2nd half)   |
| 0x31  ColorBufBlockStart W block  V3 first 32 bytes       |
| 0x32  ColorBufBlock     W block   V3 remaining bytes      |
| 0x41  *(pass-thru)*     R byte    0x00=ready, poll this   |
| 0x42  GetChecksum       R byte    Checksum / ext status   |
| 0x43  GetStorageBlkCnt  R byte    0x1a=Corsair RGB        |
| 0x44  GetProtocolVer    R byte    VOLATILE — don't use!   |
| 0x82  WriteConfig       W byte    Commit/save to device   |
| 0xB0  SetDirectData     W byte    Direct per-LED data     |
| 0xC0  SetEffectCurTime  W byte    Sync effect timing      |
\*---------------------------------------------------------*/

#pragma once

#include <mutex>
#include <string>
#include "i2c_smbus.h"

#define CORSAIR_DOMINATOR_PLATINUM_DATA_SIZE 64

typedef unsigned char corsair_dev_id;

/*---------------------------------------------------------*\
| Register definitions                                       |
| Confirmed via disassembly of CorsairDeviceControlService   |
| command dispatch at 0x14016f940 (225-case switch table)    |
\*---------------------------------------------------------*/
enum
{
    CORSAIR_DOMINATOR_REG_BRIGHTNESS     = 0x10,     /* Bightness (sic) — R/W brightness     */
    CORSAIR_DOMINATOR_REG_COMMAND        = 0x20,     /* SetBinaryData — command data register */
    CORSAIR_DOMINATOR_REG_BINARY_START   = 0x21,     /* BinaryStart — start data transfer    */
    CORSAIR_DOMINATOR_REG_SWITCH_MODE    = 0x23,     /* SwitchMode — App/Bootloader/Direct   */
    CORSAIR_DOMINATOR_REG_COMMAND_TYPE   = 0x26,     /* HW pass-through: 0x01=effect, 0x02=store */
    CORSAIR_DOMINATOR_REG_TRIGGER        = 0x27,     /* TriggerEffect — commit staged colors */
    CORSAIR_DOMINATOR_REG_APPLY_FULL     = 0x28,     /* ApplyFullDirectData                  */
    CORSAIR_DOMINATOR_REG_APPLY_HALF     = 0x29,     /* ApplyHalfDirectData                  */
    CORSAIR_DOMINATOR_REG_DIRECT1        = 0x31,     /* ColorBufferBlockStart V3 (1st half)  */
    CORSAIR_DOMINATOR_REG_DIRECT2        = 0x32,     /* ColorBufferBlock V3 (2nd half)       */
    CORSAIR_DOMINATOR_REG_STATUS         = 0x41,     /* Status — R-only, 0x00=ready          */
    CORSAIR_DOMINATOR_REG_VERSION        = 0x44,     /* GetProtocolVersion — VOLATILE, don't use for detection */
    CORSAIR_DOMINATOR_REG_WRITE_CONFIG   = 0x82,     /* WriteConfiguration — save to device  */
};

/*---------------------------------------------------------*\
| Mode definitions                                           |
\*---------------------------------------------------------*/
enum
{
    CORSAIR_DOMINATOR_MODE_DIRECT        = 0xDD,     /* Direct mode (arbitrary value)        */
    CORSAIR_DOMINATOR_MODE_COLOR_SHIFT   = 0x00,     /* Color Shift mode                     */
    CORSAIR_DOMINATOR_MODE_COLOR_PULSE   = 0x01,     /* Color Pulse mode                     */
    CORSAIR_DOMINATOR_MODE_RAINBOW_WAVE  = 0x03,     /* Rainbow Wave mode                    */
    CORSAIR_DOMINATOR_MODE_COLOR_WAVE    = 0x04,     /* Color Wave mode                      */
    CORSAIR_DOMINATOR_MODE_VISOR         = 0x05,     /* Visor mode                           */
    CORSAIR_DOMINATOR_MODE_RAIN          = 0x06,     /* Rain mode                            */
    CORSAIR_DOMINATOR_MODE_MARQUEE       = 0x07,     /* Marquee mode                         */
    CORSAIR_DOMINATOR_MODE_RAINBOW       = 0x08,     /* Rainbow mode                         */
    CORSAIR_DOMINATOR_MODE_SEQUENTIAL    = 0x09,     /* Sequential mode                      */
    CORSAIR_DOMINATOR_MODE_STATIC        = 0x10,     /* Static mode (→ sent as HW mode 0x00 via effect protocol) */
};

/*---------------------------------------------------------*\
| Speed definitions                                          |
\*---------------------------------------------------------*/
enum
{
    CORSAIR_DOMINATOR_SPEED_SLOW         = 0x00,     /* Slow speed                           */
    CORSAIR_DOMINATOR_SPEED_MEDIUM       = 0x01,     /* Medium speed                         */
    CORSAIR_DOMINATOR_SPEED_FAST         = 0x02,     /* Fast speed                           */
};

/*---------------------------------------------------------*\
| Color type definitions                                     |
\*---------------------------------------------------------*/
enum
{
    CORSAIR_DOMINATOR_EFFECT_RANDOM      = 0x00,     /* Random colors                        */
    CORSAIR_DOMINATOR_EFFECT_CUSTOM      = 0x01,     /* Custom colors                        */
};

/*---------------------------------------------------------*\
| Direction definitions                                      |
\*---------------------------------------------------------*/
enum
{
    CORSAIR_DOMINATOR_DIR_UP             = 0x00,     /* Up direction                         */
    CORSAIR_DOMINATOR_DIR_DOWN           = 0x01,     /* Down direction                       */
    CORSAIR_DOMINATOR_DIR_LEFT           = 0x02,     /* Left direction                       */
    CORSAIR_DOMINATOR_DIR_RIGHT          = 0x03,     /* Right direction                      */
    CORSAIR_DOMINATOR_DIR_VERTICAL       = 0x01,     /* Vertical direction                   */
    CORSAIR_DOMINATOR_DIR_HORIZONTAL     = 0x03,     /* Horizontal direction                 */
};

class CorsairDominatorPlatinumController
{
public:
    CorsairDominatorPlatinumController(i2c_smbus_interface *bus, corsair_dev_id dev, unsigned int leds_count, std::string dev_name);
    ~CorsairDominatorPlatinumController();

    std::string GetDeviceLocation();
    std::string GetDeviceName();
    unsigned int GetLEDCount();

    void SetAllColors(unsigned char red, unsigned char green, unsigned char blue);
    void SetLEDColor(unsigned int led, unsigned char red, unsigned char green, unsigned char blue);
    void ApplyColors();
    void SaveStoredColors();
    bool WaitReady();

    void SetDirect(bool direct);
    void SetEffect(unsigned char mode,
                   unsigned char speed,
                   unsigned char direction,
                   bool          random,
                   unsigned char red1,
                   unsigned char grn1,
                   unsigned char blu1,
                   unsigned char red2,
                   unsigned char grn2,
                   unsigned char blu2);

private:
    unsigned char           led_data[CORSAIR_DOMINATOR_PLATINUM_DATA_SIZE];
    i2c_smbus_interface*    bus;
    corsair_dev_id          dev;
    unsigned int            leds_count;
    std::string             name;
    bool                    direct_mode;
    unsigned char           effect_mode;
    std::mutex              bus_mutex;      /* Transaction-level SMBus lock (mirrors iCUE SMBusLocker RAII, §9.3) */

    static unsigned char crc8(unsigned char init, unsigned char poly, unsigned char *data, unsigned int len);
    bool SmbusWriteByte(unsigned char reg, unsigned char value);
    bool SmbusWriteBlock(unsigned char reg, unsigned char length, const unsigned char *data);
    void SendEffectCommand(unsigned char mode, unsigned char speed, unsigned char direction, bool random,
                           unsigned char red1, unsigned char grn1, unsigned char blu1,
                           unsigned char red2, unsigned char grn2, unsigned char blu2);
};
