/*---------------------------------------------------------*\
| CorsairDominatorPlatinumController.cpp                    |
|                                                           |
|   Driver for Corsair Dominator Platinum RAM               |
|   Supports both DDR4 and DDR5 via V3 Block protocol      |
|                                                           |
|   Erik Gilling (konkers)                      25 Sep 2020 |
|                                                           |
|   This file is part of the OpenRGB project                |
|   SPDX-License-Identifier: GPL-2.0-or-later               |
|                                                           |
|   For the complete protocol reference including register  |
|   map, diag test results, white flash recovery sequence,  |
|   and dangerous ops, see the comment block in the .h file.|
\*---------------------------------------------------------*/

#include <cstring>
#include <chrono>
#include "CorsairDominatorPlatinumController.h"
#include "LogManager.h"

using namespace std::chrono_literals;

CorsairDominatorPlatinumController::CorsairDominatorPlatinumController(i2c_smbus_interface *bus, corsair_dev_id dev, unsigned int leds_count, std::string dev_name)
{
    this->bus           = bus;
    this->dev           = dev;
    this->leds_count    = leds_count;
    this->name          = dev_name;

    direct_mode = false;
    effect_mode = CORSAIR_DOMINATOR_MODE_STATIC;

    memset(led_data, 0x00, sizeof(led_data));
    led_data[0] = leds_count;
}

CorsairDominatorPlatinumController::~CorsairDominatorPlatinumController()
{
    /*---------------------------------------------------------*\
    | Restore hardware lighting on exit to prevent white flash. |
    |                                                           |
    | This matches iCUE's behavior: "Enabling DRAM HW lightings |
    | due to session end". Without this, DIMMs stay in direct   |
    | mode with no color source and flash white.                 |
    |                                                           |
    | From diag_v4.sh (commit 845ded22):                         |
    |   Test G confirmed that Rainbow Wave effect (byte writes  |
    |   to 0x26/0x21/0x20/0x82) always recovers DIMMs from     |
    |   white flash. The effect command uses the V3 Command     |
    |   Protocol which works on both DDR4 and DDR5.             |
    |                                                           |
    | WARNING: If DIMMs are in a stuck state, the effect may    |
    | fail silently (ACK'd but no visual change). See the full  |
    | reset sequence (Tests A-F) documented in the .h file.      |
    \*---------------------------------------------------------*/
    std::lock_guard<std::mutex> guard(bus_mutex);

    WaitReady();

    SendEffectCommand(
        CORSAIR_DOMINATOR_MODE_RAINBOW_WAVE,
        CORSAIR_DOMINATOR_SPEED_MEDIUM,
        CORSAIR_DOMINATOR_DIR_UP,
        false,
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00
    );
}

unsigned int CorsairDominatorPlatinumController::GetLEDCount()
{
    return leds_count;
}

std::string CorsairDominatorPlatinumController::GetDeviceLocation()
{
    std::string return_string(bus->device_name);
    char addr[5];
    snprintf(addr, 5, "0x%02X", dev);
    return_string.append(", address ");
    return_string.append(addr);
    return("I2C: " + return_string);
}

std::string CorsairDominatorPlatinumController::GetDeviceName()
{
    return(name);
}

void CorsairDominatorPlatinumController::SetAllColors
    (
    unsigned char   red,
    unsigned char   green,
    unsigned char   blue
    )
{
    for(unsigned int led = 0; led < leds_count; led++)
    {
        SetLEDColor(led, red, green, blue);
    }
}

void CorsairDominatorPlatinumController::SetLEDColor
    (
    unsigned int    led,
    unsigned char   red,
    unsigned char   green,
    unsigned char   blue
    )
{
    if(led >= leds_count)
    {
        return;
    }

    unsigned int offset     = (led * 3) + 1;
    led_data[offset]        = red;
    led_data[offset + 1]    = green;
    led_data[offset + 2]    = blue;
}

unsigned char CorsairDominatorPlatinumController::crc8
    (
    unsigned char   init,
    unsigned char   poly,
    unsigned char*  data,
    unsigned int    len
    )
{
    unsigned char crc = init;

    for(unsigned int i = 0; i < len; i++)
    {
        unsigned char val = data[i];
        for(unsigned char mask = 0x80; mask != 0; mask >>= 1)
        {
            unsigned char bit;
            if ((val & mask) != 0)
            {
                bit = (crc & 0x80) ^ 0x80;
            }
            else
            {
                bit = crc & 0x80;
            }

            if (bit == 0)
            {
                crc <<= 1;
            }
            else
            {
                crc = (crc << 1) ^ poly;
            }
        }
    }

    return crc;
}

/*---------------------------------------------------------*\
| ApplyColors                                                |
|                                                            |
| Sends color data using V3 Block protocol (0x31/0x32).     |
| Works on both DDR4 and DDR5 via kernel SMBus block writes. |
|                                                            |
| A SwitchMode write (0x23=0x02) is sent before every color  |
| update to ensure the DIMM is in direct mode. This also     |
| serves as white flash recovery — per §6 of the protocol    |
| findings, a single 0x23=0x02 write is the confirmed        |
| minimum recovery from any stuck/white-flash state.         |
|                                                            |
| From §2 of corsair_ddr5_protocol_findings.md:              |
|   V3 Block works on DDR5 via kernel ioctl(I2C_SMBUS).     |
|   i2cset fails but the kernel C API works natively.        |
|   Per-LED color control confirmed on DDR5 (2026-03-11).   |
\*---------------------------------------------------------*/
void CorsairDominatorPlatinumController::ApplyColors()
{
    std::lock_guard<std::mutex> guard(bus_mutex);

    WaitReady();

    /*---------------------------------------------------------*\
    | SwitchMode to direct (0x23=0x02) before sending colors.   |
    |                                                           |
    | iCUE reads the current mode first and SKIPS the write if  |
    | the DIMM is already in the target mode (disassembly at    |
    | 0x140199128: cmp current_mode, target; je skip).          |
    | Writing 0x23 when already in mode 0x02 can trigger a      |
    | spurious mode transition, causing a brief white flash.    |
    \*---------------------------------------------------------*/
    s32 current_mode = bus->i2c_smbus_read_byte_data(dev, CORSAIR_DOMINATOR_REG_SWITCH_MODE);
    if(current_mode != 0x02)
    {
        SmbusWriteByte(CORSAIR_DOMINATOR_REG_SWITCH_MODE, 0x02);
    }

    unsigned int packet_size = 1 + (leds_count * 3) + 1;
    unsigned char data[CORSAIR_DOMINATOR_PLATINUM_DATA_SIZE];

    memcpy(data, led_data, packet_size - 1);
    data[packet_size - 1] = crc8(0x0, 0x7, data, packet_size - 1);

    if(packet_size <= 32)
    {
        SmbusWriteBlock(CORSAIR_DOMINATOR_REG_DIRECT1, packet_size, data);
    }
    else
    {
        SmbusWriteBlock(CORSAIR_DOMINATOR_REG_DIRECT1, 0x20, data);
        SmbusWriteBlock(CORSAIR_DOMINATOR_REG_DIRECT2, packet_size - 0x20, data + 0x20);
    }
}

void CorsairDominatorPlatinumController::SaveStoredColors()
{
    std::lock_guard<std::mutex> guard(bus_mutex);

    WaitReady();

    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND_TYPE, 0x02);
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_BINARY_START, 0x00);

    for(unsigned int i = 0; i < leds_count; i++)
    {
        unsigned int offset = (i * 3) + 1;
        SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, led_data[offset]);       // Red
        SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, led_data[offset + 1]);   // Green
        SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, led_data[offset + 2]);   // Blue
        SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0xFF);
    }

    SmbusWriteByte(CORSAIR_DOMINATOR_REG_WRITE_CONFIG, 0x02);
}

void CorsairDominatorPlatinumController::SetDirect(bool direct)
{
    direct_mode = direct;
}

void CorsairDominatorPlatinumController::SetEffect
    (
    unsigned char   mode,
    unsigned char   speed,
    unsigned char   direction,
    bool            random,
    unsigned char   red1,
    unsigned char   grn1,
    unsigned char   blu1,
    unsigned char   red2,
    unsigned char   grn2,
    unsigned char   blu2
    )
{
    bool entering_direct = (mode == CORSAIR_DOMINATOR_MODE_DIRECT);

    LOG_INFO("[Corsair Dominator] SetEffect: mode=0x%02X speed=%d dir=%d random=%d colors=(%d,%d,%d)/(%d,%d,%d) entering_direct=%d",
             mode, speed, direction, random, red1, grn1, blu1, red2, grn2, blu2, entering_direct);

    if(entering_direct)
    {
        /*---------------------------------------------------------*\
        | Entering Direct mode: just set the flag and return. No    |
        | hardware effect command is sent — the direct color writes |
        | (V3 block to 0x31/0x32) will take over naturally.         |
        \*---------------------------------------------------------*/
        direct_mode = true;
        effect_mode = mode;
        return;
    }

    std::lock_guard<std::mutex> guard(bus_mutex);

    direct_mode = false;
    effect_mode = mode;

    unsigned char hw_mode = mode;

    if(mode == CORSAIR_DOMINATOR_MODE_STATIC)
    {
        /*---------------------------------------------------------*\
        | Static mode: use HW mode 0x00 (Color Shift) with both    |
        | color slots set to the same color. This produces a        |
        | uniform static color on all LEDs.                         |
        |                                                           |
        | Confirmed in §6.2 of corsair_ddr5_protocol_findings.md:  |
        |   Static RED and GREEN tested via effect protocol on      |
        |   both DDR4 and DDR5 controllers.                         |
        \*---------------------------------------------------------*/
        hw_mode = CORSAIR_DOMINATOR_MODE_COLOR_SHIFT;
        red2 = red1;
        grn2 = grn1;
        blu2 = blu1;
        random = false;
    }

    SendEffectCommand(hw_mode, speed, direction, random, red1, grn1, blu1, red2, grn2, blu2);
}

/*---------------------------------------------------------*\
| SMBus write wrappers with retry logic.                     |
|                                                            |
| Modeled after Kingston Fury's SmbusWrite() which retries   |
| up to 5 times with linear backoff on NACK/bus errors.      |
| iCUE also checks byte write return codes and logs          |
| "Byte write failed: dram={} offset={} data={}" on failure. |
|                                                            |
| Return: true if the write succeeded, false if all retries  |
| were exhausted.                                            |
|                                                            |
| LOCKING: These do NOT acquire bus_mutex — the caller must  |
| already hold it. They only wrap the raw SMBus call.        |
\*---------------------------------------------------------*/
bool CorsairDominatorPlatinumController::SmbusWriteByte(unsigned char reg, unsigned char value)
{
    for(int attempt = 1; attempt <= 5; attempt++)
    {
        s32 res = bus->i2c_smbus_write_byte_data(dev, reg, value);

        if(res >= 0)
        {
            return true;
        }

        LOG_WARNING("[Corsair Dominator] addr=0x%02X byte write failed: reg=0x%02X val=0x%02X attempt=%d/5 res=%d",
                    dev, reg, value, attempt, res);
        std::this_thread::sleep_for(std::chrono::milliseconds(3 * attempt));
    }

    LOG_ERROR("[Corsair Dominator] addr=0x%02X byte write FAILED after 5 retries: reg=0x%02X val=0x%02X",
              dev, reg, value);
    return false;
}

bool CorsairDominatorPlatinumController::SmbusWriteBlock(unsigned char reg, unsigned char length, const unsigned char *data)
{
    for(int attempt = 1; attempt <= 5; attempt++)
    {
        s32 res = bus->i2c_smbus_write_block_data(dev, reg, length, data);

        if(res >= 0)
        {
            return true;
        }

        LOG_WARNING("[Corsair Dominator] addr=0x%02X block write failed: reg=0x%02X len=%d attempt=%d/5 res=%d",
                    dev, reg, length, attempt, res);
        std::this_thread::sleep_for(std::chrono::milliseconds(3 * attempt));
    }

    LOG_ERROR("[Corsair Dominator] addr=0x%02X block write FAILED after 5 retries: reg=0x%02X len=%d",
              dev, reg, length);
    return false;
}

void CorsairDominatorPlatinumController::SendEffectCommand
    (
    unsigned char   mode,
    unsigned char   speed,
    unsigned char   direction,
    bool            random,
    unsigned char   red1,
    unsigned char   grn1,
    unsigned char   blu1,
    unsigned char   red2,
    unsigned char   grn2,
    unsigned char   blu2
    )
{
    /*---------------------------------------------------------*\
    | Effect command protocol (V3 Command Protocol)             |
    | Uses byte writes — works on BOTH DDR4 and DDR5.           |
    | Confirmed by diag_v4.sh Test G on 0x19 and 0x1b.          |
    |                                                           |
    | LOCKING: Caller must hold bus_mutex. This is a private    |
    | method called from SetEffect() and ~destructor(), both    |
    | of which acquire the lock before calling us.              |
    |                                                           |
    | Register sequence:                                        |
    |   0x26 = 0x01    CommandType (effect command)              |
    |   0x21 = 0x00    BinaryStart (reset data pointer)         |
    |   0x20 × 20      SetBinaryData (sequential):              |
    |     [0] mode     (e.g. 0x03 = Rainbow Wave)               |
    |     [1] speed    (0x00=slow, 0x01=med, 0x02=fast)         |
    |     [2] random   (0x00=random, 0x01=custom colors)        |
    |     [3] direction (0x00=up, 0x01=down, etc.)              |
    |     [4-6] R1, G1, B1                                      |
    |     [7] 0xFF     (alpha 1)                                |
    |     [8-10] R2, G2, B2                                     |
    |     [11] 0xFF    (alpha 2)                                |
    |     [12-19] 0x00 (padding — 8 zero bytes)                 |
    |   0x82 = 0x01    WriteConfiguration (commit & save)       |
    |                                                           |
    | This is the WHITE FLASH RECOVERY mechanism:                |
    | Sending Rainbow Wave switches the DIMM from direct mode   |
    | back to hardware-controlled mode. Called from destructor   |
    | to prevent DIMMs from staying white when OpenRGB exits.    |
    |                                                           |
    | From diag_v4.sh Test G (commit 845ded22):                  |
    |   Rainbow Wave effect ALWAYS recovers DIMMs from white    |
    |   flash. However, if DIMMs are in a deeply stuck state,   |
    |   the full reset sequence (Tests A-F) may be needed first |
    |   for the effect command to take visual effect. Without   |
    |   the reset, commands are ACK'd but produce no change.    |
    |                                                           |
    | diag_v4.sh Test G exact sequence:                          |
    |   wait_ready(), 0x26=0x01, 0x21=0x00,                     |
    |   0x20=0x03 (Rainbow), 0x20=0x01 (speed), 0x20=0x00 (rnd),|
    |   0x20=0x00 (dir), R1,G1,B1=0, 0xFF, R2,G2,B2=0, 0xFF,   |
    |   8×0x00 padding, 0x82=0x01                                |
    \*---------------------------------------------------------*/
    LOG_INFO("[Corsair Dominator] SendEffectCommand: addr=0x%02X mode=0x%02X speed=%d dir=%d random=%d R1=%d G1=%d B1=%d R2=%d G2=%d B2=%d",
             dev, mode, speed, direction, random, red1, grn1, blu1, red2, grn2, blu2);

    WaitReady();

    /*---------------------------------------------------------*\
    | SwitchMode recovery: write 0x23=0x02 only if needed.      |
    |                                                           |
    | Per §6 ablation study (reset_rainbow.go):                 |
    |   S7 "just 2" PASSES; S5 "just 0" FAILS; S8 none FAILS.  |
    | iCUE reads the current mode first and skips the write if  |
    | the DIMM is already in mode 0x02 (avoids spurious mode    |
    | transition which can cause white flash).                  |
    \*---------------------------------------------------------*/
    s32 current_mode = bus->i2c_smbus_read_byte_data(dev, CORSAIR_DOMINATOR_REG_SWITCH_MODE);
    if(current_mode != 0x02)
    {
        SmbusWriteByte(CORSAIR_DOMINATOR_REG_SWITCH_MODE, 0x02);
    }

    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND_TYPE, 0x01);
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_BINARY_START, 0x00);

    unsigned char random_byte;

    if(random)
    {
        random_byte = CORSAIR_DOMINATOR_EFFECT_RANDOM;
    }
    else
    {
        random_byte = CORSAIR_DOMINATOR_EFFECT_CUSTOM;
    }

    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, mode);          // [0]  Mode
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, speed);         // [1]  Speed
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, random_byte);   // [2]  Custom/Random
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, direction);     // [3]  Direction
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, red1);          // [4]  Color 1 red
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, grn1);          // [5]  Color 1 green
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, blu1);          // [6]  Color 1 blue
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0xFF);          // [7]  Alpha 1
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, red2);          // [8]  Color 2 red
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, grn2);          // [9]  Color 2 green
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, blu2);          // [10] Color 2 blue
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0xFF);          // [11] Alpha 2
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0x00);          // [12] Padding
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0x00);          // [13] Padding
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0x00);          // [14] Padding
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0x00);          // [15] Padding
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0x00);          // [16] Padding
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0x00);          // [17] Padding
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0x00);          // [18] Padding
    SmbusWriteByte(CORSAIR_DOMINATOR_REG_COMMAND, 0x00);          // [19] Padding

    SmbusWriteByte(CORSAIR_DOMINATOR_REG_WRITE_CONFIG, 0x01);     // Commit & save
    WaitReady();
}

bool CorsairDominatorPlatinumController::WaitReady()
{
    int i = 0;
    while(bus->i2c_smbus_read_byte_data(dev, CORSAIR_DOMINATOR_REG_STATUS) != 0x00)
    {
        i++;
        std::this_thread::sleep_for(1ms);

        /*---------------------------------------------------------*\
        | Timeout after 1000ms to avoid infinite loop                |
        \*---------------------------------------------------------*/
        if(i > 1000)
        {
            return false;
        }
    }

    return true;
}
