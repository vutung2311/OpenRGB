/*---------------------------------------------------------*\
| CorsairDominatorPlatinumControllerDetect.cpp              |
|                                                           |
|   Detector for Corsair Dominator Platinum RAM             |
|   Supports both DDR4 and DDR5 via V3 Block protocol      |
|                                                           |
|   Erik Gilling (konkers)                      25 Sep 2020 |
|                                                           |
|   This file is part of the OpenRGB project                |
|   SPDX-License-Identifier: GPL-2.0-or-later               |
|                                                           |
|   For the complete protocol reference, see the comment    |
|   block in CorsairDominatorPlatinumController.h            |
\*---------------------------------------------------------*/

#include <cstdio>
#include <cstring>
#include <vector>
#include "Detector.h"
#include "CorsairDominatorPlatinumController.h"
#include "RGBController_CorsairDominatorPlatinum.h"
#include "SettingsManager.h"
#include "LogManager.h"
#include "i2c_smbus.h"
#include "pci_ids.h"

using namespace std::chrono_literals;

json corsair_dominator_models =
{
    {
        "CMT",
        {
            {"name",  "Corsair Dominator Platinum"},
            {"leds",  12}
        }
    },
    {
        "CMH",
        {
            {"name",  "Corsair Vengeance Pro SL"},
            {"leds",  10}
        }
    },
    {
        "CMN",
        {
            {"name",  "Corsair Vengeance RGB RT"},
            {"leds",  10}
        }
    },
    {
        "CMG",
        {
            {"name",  "Corsair Vengeance RGB RS"},
            {"leds",  6}
        }
    },
    {
        "CMP",
        {
            {"name",  "Corsair Dominator Titanium"},
            {"leds",  11}
        }
    }
};

#define CORSAIR_DOMINATOR_PLATINUM_NAME "Corsair Dominator Platinum"

/*---------------------------------------------------------*\
| DDR5 SPD EEPROM part number offset                        |
| The module part number starts at byte 0x209 in the SPD    |
| EEPROM and is up to 30 bytes long (null-padded).          |
\*---------------------------------------------------------*/
#define SPD5_PART_NUMBER_OFFSET 0x209
#define SPD5_PART_NUMBER_LENGTH 30

/*---------------------------------------------------------*\
| ReadModelFromSPD                                          |
|                                                           |
| Read the Corsair model prefix (e.g. CMT, CMP) from the   |
| DDR5 SPD EEPROM via sysfs. Returns an empty string if     |
| the SPD data is unavailable or not a Corsair module.      |
|                                                           |
|   bus_id  - I2C bus number                                |
|   rgb_addr - RGB controller I2C address (0x18-0x1F)       |
\*---------------------------------------------------------*/
static std::string ReadModelFromSPD(int bus_id, unsigned char rgb_addr)
{
    /*---------------------------------------------------------*\
    | Compute the SPD address from the RGB controller address.  |
    | DDR5: RGB 0x18+N maps to SPD 0x50+N                      |
    | DDR4: RGB 0x58+N maps to SPD 0x50+N                      |
    \*---------------------------------------------------------*/
    unsigned char spd_addr;

    if(rgb_addr >= 0x18 && rgb_addr <= 0x1F)
    {
        spd_addr = rgb_addr - 0x18 + 0x50;
    }
    else if(rgb_addr >= 0x58 && rgb_addr <= 0x5F)
    {
        spd_addr = rgb_addr - 0x58 + 0x50;
    }
    else
    {
        return "";
    }

    /*---------------------------------------------------------*\
    | Try DDR5 SPD (spd5118 driver) first, then DDR4 (ee1004)  |
    \*---------------------------------------------------------*/
    const char* drivers[] = { "spd5118", "ee1004" };

    for(const char* driver : drivers)
    {
        char path[256];
        snprintf(path, sizeof(path),
                 "/sys/bus/i2c/drivers/%s/%d-%04x/eeprom",
                 driver, bus_id, spd_addr);

        FILE* f = fopen(path, "rb");

        if(f == nullptr)
        {
            continue;
        }

        char part_number[SPD5_PART_NUMBER_LENGTH + 1] = {};

        if(fseek(f, SPD5_PART_NUMBER_OFFSET, SEEK_SET) == 0)
        {
            size_t bytes_read = fread(part_number, 1, SPD5_PART_NUMBER_LENGTH, f);
            part_number[bytes_read] = '\0';
        }

        fclose(f);

        /*-----------------------------------------------------*\
        | Verify this is a Corsair module (starts with "CM")    |
        \*-----------------------------------------------------*/
        if(strlen(part_number) >= 3 && part_number[0] == 'C' && part_number[1] == 'M')
        {
            std::string model(part_number, 3);

            LOG_DEBUG("[%s] Auto-detected model %s from SPD at %s",
                      CORSAIR_DOMINATOR_PLATINUM_NAME, model.c_str(), path);

            return model;
        }
    }

    return "";
}

/*---------------------------------------------------------*\
| TestForCorsairDominatorPlatinumController                  |
|                                                           |
| Detection method (from diag_v4.sh Phase 1):               |
|   1. Read reg 0x43 — must be 0x1A or 0x1B (Corsair RGB)  |
|   2. Read reg 0x44 — accept 0x04 (DDR4) or 0x01 (DDR5)   |
|                                                           |
| Uses read_byte_data instead of write_quick because on     |
| DDR5, write_quick to non-RGB addresses (e.g. SPD hub at   |
| 0x18) can disrupt the bus and cause white flashing.        |
| read_byte_data calls NAK safely if no device responds.    |
|                                                           |
| NOTE: reg 0x44 is VOLATILE (alternates between sticks):   |
|   Run 1: 0x19=0x04, 0x1b=0x01                             |
|   Run 2: 0x19=0x01, 0x1b=0x04                             |
| It is used here ONLY for detection (is this a Corsair     |
| controller at all?), NOT for protocol version selection.   |
| Protocol version is determined by I2C address range in     |
| DetectCorsairDominatorPlatinumControllers() below.         |
\*---------------------------------------------------------*/
bool TestForCorsairDominatorPlatinumController(i2c_smbus_interface *bus, unsigned char address)
{
    LOG_DEBUG("[%s] Trying address %02X", CORSAIR_DOMINATOR_PLATINUM_NAME, address);

    /*---------------------------------------------------------*\
    | Read identification registers directly instead of using   |
    | write_quick. On DDR5, write_quick to non-RGB addresses    |
    | (e.g. SPD hub at 0x18) can disrupt the bus and cause      |
    | white flashing. The read_byte_data calls will NAK safely  |
    | if the address does not respond.                          |
    \*---------------------------------------------------------*/
    int res = bus->i2c_smbus_read_byte_data(address, 0x43);

    if(res < 0 || !(res == 0x1A || res == 0x1B))
    {
        LOG_DEBUG("[%s] Failed: expected 0x1a or 0x1b at 0x43, got %04X", CORSAIR_DOMINATOR_PLATINUM_NAME, res);
        return false;
    }

    res = bus->i2c_smbus_read_byte_data(address, 0x44);

    /*---------------------------------------------------------*\
    | DDR4 returns 0x04 at register 0x44, DDR5 returns 0x01.    |
    | Accept both values for compatibility.                     |
    |                                                           |
    | WARNING: This value is VOLATILE and alternates between    |
    | sticks! Do NOT use it for protocol selection.              |
    | See the protocol detection comment block in the .h file   |
    | for detailed measurements from diag_v4.sh.                |
    \*---------------------------------------------------------*/
    if(!(res == 0x04 || res == 0x01))
    {
        LOG_DEBUG("[%s] Failed: expected 0x04 or 0x01 at 0x44, got %04X", CORSAIR_DOMINATOR_PLATINUM_NAME, res);
        return false;
    }

    return true;
}

/******************************************************************************************\
*                                                                                          *
*   DetectCorsairDominatorPlatinumControllers                                              *
*                                                                                          *
*       Detect Corsair Dominator Platinum controllers on the enumerated I2C busses.        *
*                                                                                          *
*           bus - pointer to i2c_smbus_interface where Aura device is connected            *
*           dev - I2C address of Aura device                                               *
*                                                                                          *
\******************************************************************************************/

void DetectCorsairDominatorPlatinumControllers(std::vector<i2c_smbus_interface *> &busses)
{
    /*---------------------------------------------------------*\
    | Read config model as fallback only                        |
    \*---------------------------------------------------------*/
    SettingsManager* settings_manager = ResourceManager::get()->GetSettingsManager();

    json corsair_dominator_settings = settings_manager->GetSettings("CorsairDominatorSettings");

    if(!corsair_dominator_settings.contains("model"))
    {
        corsair_dominator_settings["model"] = "CMT";
        settings_manager->SetSettings("CorsairDominatorSettings", corsair_dominator_settings);
        settings_manager->SaveSettings();
    }

    std::string fallback_model = corsair_dominator_settings["model"];

    for(unsigned int bus = 0; bus < busses.size(); bus++)
    {
        IF_DRAM_SMBUS(busses[bus]->pci_vendor, busses[bus]->pci_device)
        {
            LOG_DEBUG("[%s] Testing bus %d", CORSAIR_DOMINATOR_PLATINUM_NAME, bus);

            std::vector<unsigned char> addresses;

            for(unsigned char addr = 0x58; addr <= 0x5F; addr++)
            {
                addresses.push_back(addr);
            }

            for(unsigned char addr = 0x18; addr <= 0x1F; addr++)
            {
                addresses.push_back(addr);
            }

            for(unsigned char addr : addresses)
            {
                if(TestForCorsairDominatorPlatinumController(busses[bus], addr))
                {
                    unsigned int leds;
                    std::string name;
                    std::string model;

                    /*-------------------------------------------------*\
                    | Try to auto-detect model from SPD EEPROM          |
                    \*-------------------------------------------------*/
                    model = ReadModelFromSPD(busses[bus]->bus_id, addr);

                    /*-------------------------------------------------*\
                    | Fall back to config setting if SPD read fails     |
                    \*-------------------------------------------------*/
                    if(model.empty() || !corsair_dominator_models.contains(model))
                    {
                        if(!model.empty())
                        {
                            LOG_DEBUG("[%s] Unknown model %s from SPD, falling back to config",
                                      CORSAIR_DOMINATOR_PLATINUM_NAME, model.c_str());
                        }
                        else
                        {
                            LOG_DEBUG("[%s] Could not read SPD, falling back to config model %s",
                                      CORSAIR_DOMINATOR_PLATINUM_NAME, fallback_model.c_str());
                        }

                        model = fallback_model;
                    }

                    if(corsair_dominator_models.contains(model))
                    {
                        leds = corsair_dominator_models[model]["leds"];
                        name = corsair_dominator_models[model]["name"];
                    }
                    else
                    {
                        leds = corsair_dominator_models["CMT"]["leds"];
                        name = corsair_dominator_models["CMT"]["name"];
                    }

                    LOG_DEBUG("[%s] Model: %s, Leds: %d", CORSAIR_DOMINATOR_PLATINUM_NAME, name.c_str(), leds);

                    /*-------------------------------------------------*\
                    | Both DDR4 (0x58-0x5F) and DDR5 (0x18-0x1F) use   |
                    | V3 Block protocol (0x31/0x32) for color writes.   |
                    |                                                   |
                    | V4 Word (0x90/0xA0) is NOT used — confirmed in    |
                    | corsair_ddr5_protocol_findings.md §2: V3 Block    |
                    | works on DDR5 via kernel ioctl(I2C_SMBUS) and     |
                    | iCUE's LightingWriterV4Block uses the same regs.  |
                    \*-------------------------------------------------*/

                    LOG_DEBUG("[%s] Address 0x%02X → %s",
                              CORSAIR_DOMINATOR_PLATINUM_NAME, addr,
                              (addr >= 0x18 && addr <= 0x1F) ? "DDR5" : "DDR4");

                    CorsairDominatorPlatinumController*     controller    = new CorsairDominatorPlatinumController(busses[bus], addr, leds, name);
                    RGBController_CorsairDominatorPlatinum* rgbcontroller = new RGBController_CorsairDominatorPlatinum(controller);

                    ResourceManager::get()->RegisterRGBController(rgbcontroller);
                }

                std::this_thread::sleep_for(10ms);
            }
        }
        else
        {
            LOG_DEBUG("[%s] Bus %d is not a DRAM bus", CORSAIR_DOMINATOR_PLATINUM_NAME, bus);
        }
    }
}   /* DetectCorsairDominatorPlatinumControllers() */

REGISTER_I2C_DETECTOR(CORSAIR_DOMINATOR_PLATINUM_NAME, DetectCorsairDominatorPlatinumControllers);
