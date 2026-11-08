/*
 * ST M25P80 emulator. Emulate all SPI flash devices based on the m25p80 command
 * set. Known devices table current as of Jun/2012 and taken from linux.
 * See drivers/mtd/devices/m25p80.c.
 *
 * Copyright (C) 2011 Edgar E. Iglesias <edgar.iglesias@gmail.com>
 * Copyright (C) 2012 Peter A. G. Crosthwaite <peter.crosthwaite@petalogix.com>
 * Copyright (C) 2012 PetaLogix
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 or
 * (at your option) a later version of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/crc32c.h"
#include "qemu/cutils.h"
#include "qemu/bswap.h"
#include "crypto/hmac.h"
#include "system/block-backend.h"
#include "hw/block/block.h"
#include "hw/block/flash.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "hw/ssi/ssi.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "trace.h"
#include "qom/object.h"
#include "m25p80_sfdp.h"

/* 16 MiB max in 3 byte address mode */
#define MAX_3BYTES_SIZE 0x1000000
#define SPI_NOR_MAX_ID_LEN 6

/* Fields for FlashPartInfo->flags */
enum spi_flash_option_flags {
    ER_4K                  = BIT(0),
    ER_32K                 = BIT(1),
    EEPROM                 = BIT(2),
    HAS_SR_TB              = BIT(3),
    HAS_SR_BP3_BIT6        = BIT(4),
};

typedef struct FlashPartInfo {
    const char *part_name;
    /*
     * This array stores the ID bytes.
     * The first three bytes are the JEDIC ID.
     * JEDEC ID zero means "no ID" (mostly older chips).
     */
    uint8_t id[SPI_NOR_MAX_ID_LEN];
    uint8_t id_len;
    /*
     * there is confusion between manufacturers as to what a sector is. In this
     * device model, a "sector" is the size that is erased by the ERASE_SECTOR
     * command (opcode 0xd8).
     */
    uint32_t sector_size;
    uint32_t n_sectors;
    uint32_t page_size;
    uint16_t flags;
    /*
     * Big sized spi nor are often stacked devices, thus sometime
     * replace chip erase with die erase.
     * This field inform how many die is in the chip.
     */
    uint8_t die_cnt;
    uint8_t (*sfdp_read)(uint32_t sfdp_addr);
    /*
     * Number of JESD260 Replay Protected Monotonic Counters, 0 if the part
     * does not support RPMC. Must match the SFDP RPMC parameter table.
     */
    uint8_t rpmc_counters;
} FlashPartInfo;

/* adapted from linux */
/* Used when the "_ext_id" is two bytes at most */
#define INFO(_part_name, _jedec_id, _ext_id, _sector_size, _n_sectors, _flags)\
    .part_name = _part_name,\
    .id = {\
        ((_jedec_id) >> 16) & 0xff,\
        ((_jedec_id) >> 8) & 0xff,\
        (_jedec_id) & 0xff,\
        ((_ext_id) >> 8) & 0xff,\
        (_ext_id) & 0xff,\
          },\
    .id_len = (!(_jedec_id) ? 0 : (3 + ((_ext_id) ? 2 : 0))),\
    .sector_size = (_sector_size),\
    .n_sectors = (_n_sectors),\
    .page_size = 256,\
    .flags = (_flags),\
    .die_cnt = 0

#define INFO6(_part_name, _jedec_id, _ext_id, _sector_size, _n_sectors, _flags)\
    .part_name = _part_name,\
    .id = {\
        ((_jedec_id) >> 16) & 0xff,\
        ((_jedec_id) >> 8) & 0xff,\
        (_jedec_id) & 0xff,\
        ((_ext_id) >> 16) & 0xff,\
        ((_ext_id) >> 8) & 0xff,\
        (_ext_id) & 0xff,\
          },\
    .id_len = 6,\
    .sector_size = (_sector_size),\
    .n_sectors = (_n_sectors),\
    .page_size = 256,\
    .flags = (_flags),\
    .die_cnt = 0

#define INFO_STACKED(_part_name, _jedec_id, _ext_id, _sector_size, _n_sectors,\
                    _flags, _die_cnt)\
    .part_name = _part_name,\
    .id = {\
        ((_jedec_id) >> 16) & 0xff,\
        ((_jedec_id) >> 8) & 0xff,\
        (_jedec_id) & 0xff,\
        ((_ext_id) >> 8) & 0xff,\
        (_ext_id) & 0xff,\
          },\
    .id_len = (!(_jedec_id) ? 0 : (3 + ((_ext_id) ? 2 : 0))),\
    .sector_size = (_sector_size),\
    .n_sectors = (_n_sectors),\
    .page_size = 256,\
    .flags = (_flags),\
    .die_cnt = _die_cnt

#define JEDEC_NUMONYX 0x20
#define JEDEC_WINBOND 0xEF
#define JEDEC_SPANSION 0x01

/* Numonyx (Micron) Configuration register macros */
#define VCFG_DUMMY 0x1
#define VCFG_WRAP_SEQUENTIAL 0x2
#define NVCFG_XIP_MODE_DISABLED (7 << 9)
#define NVCFG_XIP_MODE_MASK (7 << 9)
#define VCFG_XIP_MODE_DISABLED (1 << 3)
#define CFG_DUMMY_CLK_LEN 4
#define NVCFG_DUMMY_CLK_POS 12
#define VCFG_DUMMY_CLK_POS 4
#define EVCFG_OUT_DRIVER_STRENGTH_DEF 7
#define EVCFG_VPP_ACCELERATOR (1 << 3)
#define EVCFG_RESET_HOLD_ENABLED (1 << 4)
#define NVCFG_DUAL_IO_MASK (1 << 2)
#define EVCFG_DUAL_IO_DISABLED (1 << 6)
#define NVCFG_QUAD_IO_MASK (1 << 3)
#define EVCFG_QUAD_IO_DISABLED (1 << 7)
#define NVCFG_4BYTE_ADDR_MASK (1 << 0)
#define NVCFG_LOWER_SEGMENT_MASK (1 << 1)

/* Numonyx (Micron) Flag Status Register macros */
#define FSR_4BYTE_ADDR_MODE_ENABLED 0x1
#define FSR_FLASH_READY (1 << 7)

/* Spansion configuration registers macros. */
#define SPANSION_QUAD_CFG_POS 0
#define SPANSION_QUAD_CFG_LEN 1
#define SPANSION_DUMMY_CLK_POS 0
#define SPANSION_DUMMY_CLK_LEN 4
#define SPANSION_ADDR_LEN_POS 7
#define SPANSION_ADDR_LEN_LEN 1

/*
 * Spansion read mode command length in bytes,
 * the mode is currently not supported.
 */

#define SPANSION_CONTINUOUS_READ_MODE_CMD_LEN 1
#define WINBOND_CONTINUOUS_READ_MODE_CMD_LEN 1

static const FlashPartInfo known_devices[] = {
    /* Atmel -- some are (confusingly) marketed as "DataFlash" */
    { INFO("at25fs010",   0x1f6601,      0,  32 << 10,   4, ER_4K) },
    { INFO("at25fs040",   0x1f6604,      0,  64 << 10,   8, ER_4K) },

    { INFO("at25df041a",  0x1f4401,      0,  64 << 10,   8, ER_4K) },
    { INFO("at25df321a",  0x1f4701,      0,  64 << 10,  64, ER_4K) },
    { INFO("at25df641",   0x1f4800,      0,  64 << 10, 128, ER_4K) },

    { INFO("at26f004",    0x1f0400,      0,  64 << 10,   8, ER_4K) },
    { INFO("at26df081a",  0x1f4501,      0,  64 << 10,  16, ER_4K) },
    { INFO("at26df161a",  0x1f4601,      0,  64 << 10,  32, ER_4K) },
    { INFO("at26df321",   0x1f4700,      0,  64 << 10,  64, ER_4K) },

    { INFO("at45db081d",  0x1f2500,      0,  64 << 10,  16, ER_4K) },

    /*
     * Atmel EEPROMS - it is assumed, that don't care bit in command
     * is set to 0. Block protection is not supported.
     */
    { INFO("at25128a-nonjedec", 0x0,     0,         1, 131072, EEPROM) },
    { INFO("at25256a-nonjedec", 0x0,     0,         1, 262144, EEPROM) },

    /* EON -- en25xxx */
    { INFO("en25f32",     0x1c3116,      0,  64 << 10,  64, ER_4K) },
    { INFO("en25p32",     0x1c2016,      0,  64 << 10,  64, 0) },
    { INFO("en25q32b",    0x1c3016,      0,  64 << 10,  64, 0) },
    { INFO("en25p64",     0x1c2017,      0,  64 << 10, 128, 0) },
    { INFO("en25q64",     0x1c3017,      0,  64 << 10, 128, ER_4K) },

    /* GigaDevice */
    { INFO("gd25q32",     0xc84016,      0,  64 << 10,  64, ER_4K) },
    { INFO("gd25q64",     0xc84017,      0,  64 << 10, 128, ER_4K) },

    /* Intel/Numonyx -- xxxs33b */
    { INFO("160s33b",     0x898911,      0,  64 << 10,  32, 0) },
    { INFO("320s33b",     0x898912,      0,  64 << 10,  64, 0) },
    { INFO("640s33b",     0x898913,      0,  64 << 10, 128, 0) },
    { INFO("n25q064",     0x20ba17,      0,  64 << 10, 128, 0) },

    /* ISSI */
    { INFO("is25lq040b",  0x9d4013,      0,  64 << 10,   8, ER_4K) },
    { INFO("is25lp080d",  0x9d6014,      0,  64 << 10,  16, ER_4K) },
    { INFO("is25lp016d",  0x9d6015,      0,  64 << 10,  32,
           ER_4K | HAS_SR_TB) },
    { INFO("is25lp032",   0x9d6016,      0,  64 << 10,  64, ER_4K) },
    { INFO("is25lp064",   0x9d6017,      0,  64 << 10, 128, ER_4K) },
    { INFO("is25lp128",   0x9d6018,      0,  64 << 10, 256, ER_4K) },
    { INFO("is25lp256",   0x9d6019,      0,  64 << 10, 512, ER_4K) },
    { INFO("is25wp032",   0x9d7016,      0,  64 << 10,  64, ER_4K) },
    { INFO("is25wp064",   0x9d7017,      0,  64 << 10, 128, ER_4K) },
    { INFO("is25wp128",   0x9d7018,      0,  64 << 10, 256, ER_4K) },
    { INFO("is25wp256",   0x9d7019,      0,  64 << 10, 512, ER_4K),
      .sfdp_read = m25p80_sfdp_is25wp256 },

    /* Macronix */
    { INFO("mx25l2005a",  0xc22012,      0,  64 << 10,   4, ER_4K) },
    { INFO("mx25l4005a",  0xc22013,      0,  64 << 10,   8, ER_4K) },
    { INFO("mx25l8005",   0xc22014,      0,  64 << 10,  16, 0) },
    { INFO("mx25l1606e",  0xc22015,      0,  64 << 10,  32, ER_4K) },
    { INFO("mx25l3205d",  0xc22016,      0,  64 << 10,  64, 0) },
    { INFO("mx25l6405d",  0xc22017,      0,  64 << 10, 128, 0) },
    { INFO("mx25l12805d", 0xc22018,      0,  64 << 10, 256, 0) },
    { INFO("mx25l12855e", 0xc22618,      0,  64 << 10, 256, 0) },
    { INFO6("mx25l25635e", 0xc22019,     0xc22019,  64 << 10, 512,
            ER_4K | ER_32K), .sfdp_read = m25p80_sfdp_mx25l25635e },
    { INFO6("mx25l25635f", 0xc22019,     0xc22019,  64 << 10, 512,
            ER_4K | ER_32K), .sfdp_read = m25p80_sfdp_mx25l25635f },
    { INFO("mx25l25655e", 0xc22619,      0,  64 << 10, 512, 0) },
    { INFO("mx66l51235f", 0xc2201a,      0,  64 << 10, 1024, ER_4K | ER_32K) },
    { INFO("mx66u51235f", 0xc2253a,      0,  64 << 10, 1024, ER_4K | ER_32K) },
    { INFO("mx66u1g45g",  0xc2253b,      0,  64 << 10, 2048, ER_4K | ER_32K) },
    { INFO("mx66l1g45g",  0xc2201b,      0,  64 << 10, 2048, ER_4K | ER_32K),
      .sfdp_read = m25p80_sfdp_mx66l1g45g },

    /* Micron */
    { INFO("n25q032a11",  0x20bb16,      0,  64 << 10,  64, ER_4K) },
    { INFO("n25q032a13",  0x20ba16,      0,  64 << 10,  64, ER_4K) },
    { INFO("n25q064a11",  0x20bb17,      0,  64 << 10, 128, ER_4K) },
    { INFO("n25q064a13",  0x20ba17,      0,  64 << 10, 128, ER_4K) },
    { INFO("n25q128a11",  0x20bb18,      0,  64 << 10, 256, ER_4K) },
    { INFO("n25q128a13",  0x20ba18,      0,  64 << 10, 256, ER_4K) },
    { INFO("n25q256a11",  0x20bb19,      0,  64 << 10, 512, ER_4K) },
    { INFO("n25q256a13",  0x20ba19,      0,  64 << 10, 512, ER_4K),
      .sfdp_read = m25p80_sfdp_n25q256a },
    { INFO("n25q512a11",  0x20bb20,      0,  64 << 10, 1024, ER_4K) },
    { INFO("n25q512a13",  0x20ba20,      0,  64 << 10, 1024, ER_4K) },
    { INFO("n25q128",     0x20ba18,      0,  64 << 10, 256, 0) },
    { INFO("n25q256a",    0x20ba19,      0,  64 << 10, 512,
           ER_4K | HAS_SR_BP3_BIT6 | HAS_SR_TB),
      .sfdp_read = m25p80_sfdp_n25q256a },
   { INFO("n25q512a",    0x20ba20,      0,  64 << 10, 1024, ER_4K) },
    { INFO("n25q512ax3",  0x20ba20,  0x1000,  64 << 10, 1024, ER_4K) },
    { INFO("mt25ql512ab", 0x20ba20, 0x1044, 64 << 10, 1024, ER_4K | ER_32K) },
    { INFO_STACKED("mt35xu01g", 0x2c5b1b, 0x104100, 128 << 10, 1024,
                   ER_4K | ER_32K, 2),
                   .sfdp_read = m25p80_sfdp_mt35xu01g },
    { INFO_STACKED("mt35xu02gbba", 0x2c5b1c, 0x104100, 128 << 10, 2048,
                   ER_4K | ER_32K, 4),
                   .sfdp_read = m25p80_sfdp_mt35xu02g },
    { INFO_STACKED("n25q00",    0x20ba21, 0x1000, 64 << 10, 2048, ER_4K, 4) },
    { INFO_STACKED("n25q00a",   0x20bb21, 0x1000, 64 << 10, 2048, ER_4K, 4) },
    { INFO_STACKED("mt25ql01g", 0x20ba21, 0x1040, 64 << 10, 2048, ER_4K, 2) },
    { INFO_STACKED("mt25qu01g", 0x20bb21, 0x1040, 64 << 10, 2048, ER_4K, 2) },
    { INFO_STACKED("mt25ql02g", 0x20ba22, 0x1040, 64 << 10, 4096,
                   ER_4K | ER_32K, 2) },
    { INFO_STACKED("mt25qu02g", 0x20bb22, 0x1040, 64 << 10, 4096,
                   ER_4K | ER_32K, 2) },

    /*
     * Spansion -- single (large) sector size only, at least
     * for the chips listed here (without boot sectors).
     */
    { INFO("s25sl032p",   0x010215, 0x4d00,  64 << 10,  64, ER_4K) },
    { INFO("s25sl064p",   0x010216, 0x4d00,  64 << 10, 128, ER_4K) },
    { INFO("s25fl256s0",  0x010219, 0x4d00, 256 << 10, 128, 0) },
    { INFO("s25fl256s1",  0x010219, 0x4d01,  64 << 10, 512, 0) },
    { INFO6("s25fl512s",  0x010220, 0x4d0080, 256 << 10, 256, 0) },
    { INFO6("s70fl01gs",  0x010221, 0x4d0080, 256 << 10, 512, 0) },
    { INFO("s25sl12800",  0x012018, 0x0300, 256 << 10,  64, 0) },
    { INFO("s25sl12801",  0x012018, 0x0301,  64 << 10, 256, 0) },
    { INFO("s25fl129p0",  0x012018, 0x4d00, 256 << 10,  64, 0) },
    { INFO("s25fl129p1",  0x012018, 0x4d01,  64 << 10, 256, 0) },
    { INFO("s25sl004a",   0x010212,      0,  64 << 10,   8, 0) },
    { INFO("s25sl008a",   0x010213,      0,  64 << 10,  16, 0) },
    { INFO("s25sl016a",   0x010214,      0,  64 << 10,  32, 0) },
    { INFO("s25sl032a",   0x010215,      0,  64 << 10,  64, 0) },
    { INFO("s25sl064a",   0x010216,      0,  64 << 10, 128, 0) },
    { INFO("s25fl016k",   0xef4015,      0,  64 << 10,  32, ER_4K | ER_32K) },
    { INFO("s25fl064k",   0xef4017,      0,  64 << 10, 128, ER_4K | ER_32K) },

    /* Spansion --  boot sectors support  */
    { INFO6("s25fs512s",    0x010220, 0x4d0081, 256 << 10, 256, 0) },
    { INFO6("s70fs01gs",    0x010221, 0x4d0081, 256 << 10, 512, 0) },

    /* SST -- large erase sizes are "overlays", "sectors" are 4<< 10 */
    { INFO("sst25vf040b", 0xbf258d,      0,  64 << 10,   8, ER_4K) },
    { INFO("sst25vf080b", 0xbf258e,      0,  64 << 10,  16, ER_4K) },
    { INFO("sst25vf016b", 0xbf2541,      0,  64 << 10,  32, ER_4K) },
    { INFO("sst25vf032b", 0xbf254a,      0,  64 << 10,  64, ER_4K) },
    { INFO("sst25wf512",  0xbf2501,      0,  64 << 10,   1, ER_4K) },
    { INFO("sst25wf010",  0xbf2502,      0,  64 << 10,   2, ER_4K) },
    { INFO("sst25wf020",  0xbf2503,      0,  64 << 10,   4, ER_4K) },
    { INFO("sst25wf040",  0xbf2504,      0,  64 << 10,   8, ER_4K) },
    { INFO("sst25wf080",  0xbf2505,      0,  64 << 10,  16, ER_4K) },

    /* ST Microelectronics -- newer production may have feature updates */
    { INFO("m25p05",      0x202010,      0,  32 << 10,   2, 0) },
    { INFO("m25p10",      0x202011,      0,  32 << 10,   4, 0) },
    { INFO("m25p20",      0x202012,      0,  64 << 10,   4, 0) },
    { INFO("m25p40",      0x202013,      0,  64 << 10,   8, 0) },
    { INFO("m25p80",      0x202014,      0,  64 << 10,  16, 0) },
    { INFO("m25p16",      0x202015,      0,  64 << 10,  32, 0) },
    { INFO("m25p32",      0x202016,      0,  64 << 10,  64, 0) },
    { INFO("m25p64",      0x202017,      0,  64 << 10, 128, 0) },
    { INFO("m25p128",     0x202018,      0, 256 << 10,  64, 0) },
    { INFO("n25q032",     0x20ba16,      0,  64 << 10,  64, 0) },

    { INFO("m45pe10",     0x204011,      0,  64 << 10,   2, 0) },
    { INFO("m45pe80",     0x204014,      0,  64 << 10,  16, 0) },
    { INFO("m45pe16",     0x204015,      0,  64 << 10,  32, 0) },

    { INFO("m25pe20",     0x208012,      0,  64 << 10,   4, 0) },
    { INFO("m25pe80",     0x208014,      0,  64 << 10,  16, 0) },
    { INFO("m25pe16",     0x208015,      0,  64 << 10,  32, ER_4K) },

    { INFO("m25px32",     0x207116,      0,  64 << 10,  64, ER_4K) },
    { INFO("m25px32-s0",  0x207316,      0,  64 << 10,  64, ER_4K) },
    { INFO("m25px32-s1",  0x206316,      0,  64 << 10,  64, ER_4K) },
    { INFO("m25px64",     0x207117,      0,  64 << 10, 128, 0) },

    /* Winbond -- w25x "blocks" are 64k, "sectors" are 4KiB */
    { INFO("w25x10",      0xef3011,      0,  64 << 10,   2, ER_4K) },
    { INFO("w25x20",      0xef3012,      0,  64 << 10,   4, ER_4K) },
    { INFO("w25x40",      0xef3013,      0,  64 << 10,   8, ER_4K) },
    { INFO("w25x80",      0xef3014,      0,  64 << 10,  16, ER_4K) },
    { INFO("w25x16",      0xef3015,      0,  64 << 10,  32, ER_4K) },
    { INFO("w25x32",      0xef3016,      0,  64 << 10,  64, ER_4K) },
    { INFO("w25q32",      0xef4016,      0,  64 << 10,  64, ER_4K) },
    { INFO("w25q32dw",    0xef6016,      0,  64 << 10,  64, ER_4K) },
    { INFO("w25q33pw",    0xef6016,      0,  64 << 10,  64, ER_4K | ER_32K),
      .sfdp_read = m25p80_sfdp_w25q33pw },
    { INFO("w25x64",      0xef3017,      0,  64 << 10, 128, ER_4K) },
    { INFO("w25q64",      0xef4017,      0,  64 << 10, 128, ER_4K) },
    { INFO("w25q80",      0xef5014,      0,  64 << 10,  16, ER_4K) },
    { INFO("w25q80bl",    0xef4014,      0,  64 << 10,  16, ER_4K),
      .sfdp_read = m25p80_sfdp_w25q80bl },
    { INFO("w25q256",     0xef4019,      0,  64 << 10, 512, ER_4K),
      .sfdp_read = m25p80_sfdp_w25q256 },
    { INFO("w25q512jv",   0xef4020,      0,  64 << 10, 1024, ER_4K),
      .sfdp_read = m25p80_sfdp_w25q512jv },
    { INFO("w25q01jvq",   0xef4021,      0,  64 << 10, 2048, ER_4K),
      .sfdp_read = m25p80_sfdp_w25q01jvq },
    { INFO("w25q02jvm",   0xef7022,      0,  64 << 10, 4096, ER_4K),
      .sfdp_read = m25p80_sfdp_w25q02jvm },
    { INFO("w25r256jv",   0xef4019,      0,  64 << 10, 512, ER_4K),
      .sfdp_read = m25p80_sfdp_w25r256jv, .rpmc_counters = 4 },

    /* Microchip */
    { INFO("25csm04",      0x29cc00,      0x100,  64 << 10,  8, 0) },
};

typedef enum {
    NOP = 0,
    WRSR = 0x1,
    WRDI = 0x4,
    RDSR = 0x5,
    WREN = 0x6,
    BRRD = 0x16,
    BRWR = 0x17,
    JEDEC_READ = 0x9f,
    BULK_ERASE_60 = 0x60,
    BULK_ERASE = 0xc7,
    READ_FSR = 0x70,
    RDCR = 0x15,
    RDSFDP = 0x5a,

    READ = 0x03,
    READ4 = 0x13,
    FAST_READ = 0x0b,
    FAST_READ4 = 0x0c,
    DOR = 0x3b,
    DOR4 = 0x3c,
    QOR = 0x6b,
    QOR4 = 0x6c,
    DIOR = 0xbb,
    DIOR4 = 0xbc,
    QIOR = 0xeb,
    QIOR4 = 0xec,

    PP = 0x02,
    PP4 = 0x12,
    PP4_4 = 0x3e,
    DPP = 0xa2,
    QPP = 0x32,
    QPP_4 = 0x34,
    RDID_90 = 0x90,
    RDID_AB = 0xab,
    AAI_WP = 0xad,

    ERASE_4K = 0x20,
    ERASE4_4K = 0x21,
    ERASE_32K = 0x52,
    ERASE4_32K = 0x5c,
    ERASE_SECTOR = 0xd8,
    ERASE4_SECTOR = 0xdc,

    EN_4BYTE_ADDR = 0xB7,
    EX_4BYTE_ADDR = 0xE9,

    EXTEND_ADDR_READ = 0xC8,
    EXTEND_ADDR_WRITE = 0xC5,

    RESET_ENABLE = 0x66,
    RESET_MEMORY = 0x99,

    /*
     * Micron: 0x35 - enable QPI
     * Spansion: 0x35 - read control register
     * Winbond: 0x35 - quad enable
     */
    RDCR_EQIO = 0x35,
    RSTQIO = 0xf5,

    /*
     * Winbond: 0x31 - write status register 2
     */
    WRSR2 = 0x31,

    RNVCR = 0xB5,
    WNVCR = 0xB1,

    RVCR = 0x85,
    WVCR = 0x81,

    REVCR = 0x65,
    WEVCR = 0x61,

    DIE_ERASE = 0xC4,

    /* JESD260 Replay Protected Monotonic Counter */
    RPMC_OP1 = 0x9B,
    RPMC_OP2 = 0x96,
} FlashCMD;

typedef enum {
    STATE_IDLE,
    STATE_PAGE_PROGRAM,
    STATE_READ,
    STATE_COLLECTING_DATA,
    STATE_COLLECTING_VAR_LEN_DATA,
    STATE_READING_DATA,
    STATE_READING_SFDP,
    STATE_RPMC_COLLECTING,
    STATE_RPMC_READING,
} CMDState;

typedef enum {
    MAN_SPANSION,
    MAN_MACRONIX,
    MAN_NUMONYX,
    MAN_WINBOND,
    MAN_SST,
    MAN_ISSI,
    MAN_GENERIC,
} Manufacturer;

typedef enum {
    MODE_STD = 0,
    MODE_DIO = 1,
    MODE_QIO = 2
} SPIMode;

#define M25P80_INTERNAL_DATA_BUFFER_SZ 16

/* JESD260 Replay Protected Monotonic Counter (RPMC) */
#define RPMC_MAX_COUNTERS           16
#define RPMC_HDR_LEN                4   /* opcode, cmd type, counter, rsvd */
#define RPMC_KEY_LEN                32
#define RPMC_SIG_LEN                32
#define RPMC_TRUNC_SIG_LEN          28
#define RPMC_KEY_DATA_LEN           4
#define RPMC_COUNTER_LEN            4
#define RPMC_TAG_LEN                12
#define RPMC_OP1_MAX_LEN            (RPMC_HDR_LEN + RPMC_KEY_LEN + \
                                     RPMC_TRUNC_SIG_LEN)
/* Tag, counter data and signature returned after the status byte by OP2 */
#define RPMC_RESP_LEN               (RPMC_TAG_LEN + RPMC_COUNTER_LEN + \
                                     RPMC_SIG_LEN)

/* OP1 command types */
#define RPMC_CMD_WRITE_ROOT_KEY     0x00
#define RPMC_CMD_UPDATE_HMAC_KEY    0x01
#define RPMC_CMD_INCREMENT_COUNTER  0x02
#define RPMC_CMD_REQUEST_COUNTER    0x03

/* Extended status, returned by OP2 */
#define RPMC_ES_BUSY                BIT(0)
/*
 * Write Root Key: root key overwrite or truncated signature mismatch.
 * Update HMAC Key: counter not initialized by a root key write.
 */
#define RPMC_ES_ROOT_KEY            BIT(1)
/* Signature mismatch, counter/cmd type out of range or bad payload size */
#define RPMC_ES_PAYLOAD             BIT(2)
#define RPMC_ES_HMAC_KEY_UNINIT     BIT(3)
#define RPMC_ES_COUNTER_MISMATCH    BIT(4)
#define RPMC_ES_FATAL               BIT(5)
#define RPMC_ES_SUCCESS             BIT(7)

/* Layout of the optional "rpmc-drive" backing store, all fields big endian */
#define RPMC_NV_MAGIC               0x52504d43 /* "RPMC" */
#define RPMC_NV_VERSION             1
#define RPMC_NV_HDR_LEN             16  /* magic, version, counters, crc32c */
#define RPMC_NV_COUNTER_LEN         (8 + RPMC_KEY_LEN) /* flags, value, key */
#define RPMC_NV_FLAG_ROOT_KEY       BIT(0)
#define RPMC_NV_FLAG_COUNTER        BIT(1)
#define RPMC_NV_SIZE                4096

typedef struct RPMCCounter {
    /* Non-volatile */
    bool root_key_valid;        /* locked by a non all-ones root key */
    uint8_t root_key[RPMC_KEY_LEN];
    bool counter_valid;         /* initialized by any root key write */
    uint32_t value;
    /* Volatile, lost on power cycle */
    bool hmac_key_valid;
    uint8_t hmac_key[RPMC_KEY_LEN];
} RPMCCounter;

struct Flash {
    SSIPeripheral parent_obj;

    BlockBackend *blk;

    uint8_t *storage;
    uint32_t size;
    int page_size;

    uint8_t state;
    uint8_t data[M25P80_INTERNAL_DATA_BUFFER_SZ];
    uint32_t len;
    uint32_t pos;
    bool data_read_loop;
    uint8_t needed_bytes;
    uint8_t cmd_in_progress;
    uint32_t cur_addr;
    uint32_t nonvolatile_cfg;
    /* Configuration register for Macronix */
    uint32_t volatile_cfg;
    uint32_t enh_volatile_cfg;
    /* Spansion cfg registers. */
    uint8_t spansion_cr1nv;
    uint8_t spansion_cr2nv;
    uint8_t spansion_cr3nv;
    uint8_t spansion_cr4nv;
    uint8_t spansion_cr1v;
    uint8_t spansion_cr2v;
    uint8_t spansion_cr3v;
    uint8_t spansion_cr4v;
    bool wp_level;
    bool write_enable;
    bool four_bytes_address_mode;
    bool reset_enable;
    bool quad_enable;
    bool aai_enable;
    bool block_protect0;
    bool block_protect1;
    bool block_protect2;
    bool block_protect3;
    bool top_bottom_bit;
    bool status_register_write_disabled;
    uint8_t ear;

    int64_t dirty_page;

    const FlashPartInfo *pi;

    /* RPMC state, only used when pi->rpmc_counters != 0 */
    BlockBackend *rpmc_blk;
    RPMCCounter rpmc[RPMC_MAX_COUNTERS];
    uint8_t rpmc_status;
    uint8_t rpmc_in[RPMC_OP1_MAX_LEN];
    /* May be RPMC_OP1_MAX_LEN + 1 to flag an oversized OP1 packet */
    uint32_t rpmc_in_len;
    uint8_t rpmc_resp[RPMC_RESP_LEN];
    uint32_t rpmc_out_pos;
};

struct M25P80Class {
    SSIPeripheralClass parent_class;
    const FlashPartInfo *pi;
};

OBJECT_DECLARE_TYPE(Flash, M25P80Class, M25P80)

static inline Manufacturer get_man(Flash *s)
{
    switch (s->pi->id[0]) {
    case 0x20:
        return MAN_NUMONYX;
    case 0xEF:
        return MAN_WINBOND;
    case 0x01:
        return MAN_SPANSION;
    case 0xC2:
        return MAN_MACRONIX;
    case 0xBF:
        return MAN_SST;
    case 0x9D:
        return MAN_ISSI;
    default:
        return MAN_GENERIC;
    }
}

static void blk_sync_complete(void *opaque, int ret)
{
    QEMUIOVector *iov = opaque;

    qemu_iovec_destroy(iov);
    g_free(iov);

    /*
     * do nothing. Masters do not directly interact with the backing store,
     * only the working copy so no mutexing required.
     */
}

static void flash_sync_page(Flash *s, int page)
{
    QEMUIOVector *iov;

    if (!s->blk || !blk_is_writable(s->blk)) {
        return;
    }

    iov = g_new(QEMUIOVector, 1);
    qemu_iovec_init(iov, 1);
    qemu_iovec_add(iov, s->storage + page * s->pi->page_size,
                   s->pi->page_size);
    blk_aio_pwritev(s->blk, page * s->pi->page_size, iov, 0,
                    blk_sync_complete, iov);
}

static inline void flash_sync_area(Flash *s, int64_t off, int64_t len)
{
    QEMUIOVector *iov;

    if (!s->blk || !blk_is_writable(s->blk)) {
        return;
    }

    assert(!(len % BDRV_SECTOR_SIZE));
    iov = g_new(QEMUIOVector, 1);
    qemu_iovec_init(iov, 1);
    qemu_iovec_add(iov, s->storage + off, len);
    blk_aio_pwritev(s->blk, off, iov, 0, blk_sync_complete, iov);
}

static void flash_erase(Flash *s, int offset, FlashCMD cmd)
{
    uint32_t len;
    uint8_t capa_to_assert = 0;

    switch (cmd) {
    case ERASE_4K:
    case ERASE4_4K:
        len = 4 * KiB;
        capa_to_assert = ER_4K;
        break;
    case ERASE_32K:
    case ERASE4_32K:
        len = 32 * KiB;
        capa_to_assert = ER_32K;
        break;
    case ERASE_SECTOR:
    case ERASE4_SECTOR:
        len = s->pi->sector_size;
        break;
    case BULK_ERASE:
        len = s->size;
        break;
    case DIE_ERASE:
        if (s->pi->die_cnt) {
            len = s->size / s->pi->die_cnt;
            offset = offset & (~(len - 1));
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: die erase is not supported"
                          " by device\n");
            return;
        }
        break;
    default:
        abort();
    }

    trace_m25p80_flash_erase(s, offset, len);

    if ((s->pi->flags & capa_to_assert) != capa_to_assert) {
        qemu_log_mask(LOG_GUEST_ERROR, "M25P80: %d erase size not supported by"
                      " device\n", len);
    }

    if (!s->write_enable) {
        qemu_log_mask(LOG_GUEST_ERROR, "M25P80: erase with write protect!\n");
        return;
    }
    memset(s->storage + offset, 0xff, len);
    flash_sync_area(s, offset, len);
}

static inline void flash_sync_dirty(Flash *s, int64_t newpage)
{
    if (s->dirty_page >= 0 && s->dirty_page != newpage) {
        flash_sync_page(s, s->dirty_page);
        s->dirty_page = newpage;
    }
}

static inline
void flash_write8(Flash *s, uint32_t addr, uint8_t data)
{
    uint32_t page = addr / s->pi->page_size;
    uint8_t prev = s->storage[s->cur_addr];
    uint32_t block_protect_value = (s->block_protect3 << 3) |
                                   (s->block_protect2 << 2) |
                                   (s->block_protect1 << 1) |
                                   (s->block_protect0 << 0);

    if (!s->write_enable) {
        qemu_log_mask(LOG_GUEST_ERROR, "M25P80: write with write protect!\n");
        return;
    }

    if (block_protect_value > 0) {
        uint32_t num_protected_sectors = 1 << (block_protect_value - 1);
        uint32_t sector = addr / s->pi->sector_size;

        /* top_bottom_bit == 0 means TOP */
        if (!s->top_bottom_bit) {
            if (s->pi->n_sectors <= sector + num_protected_sectors) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "M25P80: write with write protect!\n");
                return;
            }
        } else {
            if (sector < num_protected_sectors) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "M25P80: write with write protect!\n");
                return;
            }
        }
    }

    if ((prev ^ data) & data) {
        trace_m25p80_programming_zero_to_one(s, addr, prev, data);
    }

    if (s->pi->flags & EEPROM) {
        s->storage[s->cur_addr] = data;
    } else {
        s->storage[s->cur_addr] &= data;
    }

    flash_sync_dirty(s, page);
    s->dirty_page = page;
}

static inline int get_addr_length(Flash *s)
{
   /* check if eeprom is in use */
    if (s->pi->flags == EEPROM) {
        return 2;
    }

   switch (s->cmd_in_progress) {
   case RDSFDP:
       return 3;
   case PP4:
   case PP4_4:
   case QPP_4:
   case READ4:
   case QIOR4:
   case ERASE4_4K:
   case ERASE4_32K:
   case ERASE4_SECTOR:
   case FAST_READ4:
   case DOR4:
   case QOR4:
   case DIOR4:
       return 4;
   default:
       return s->four_bytes_address_mode ? 4 : 3;
   }
}

static void complete_collecting_data(Flash *s)
{
    int i, n;

    n = get_addr_length(s);
    s->cur_addr = (n == 3 ? s->ear : 0);
    for (i = 0; i < n; ++i) {
        s->cur_addr <<= 8;
        s->cur_addr |= s->data[i];
    }

    s->cur_addr &= s->size - 1;

    s->state = STATE_IDLE;

    trace_m25p80_complete_collecting(s, s->cmd_in_progress, n, s->ear,
                                     s->cur_addr);

    switch (s->cmd_in_progress) {
    case DPP:
    case QPP:
    case QPP_4:
    case PP:
    case PP4:
    case PP4_4:
        s->state = STATE_PAGE_PROGRAM;
        break;
    case AAI_WP:
        /* AAI programming starts from the even address */
        s->cur_addr &= ~BIT(0);
        s->state = STATE_PAGE_PROGRAM;
        break;
    case READ:
    case READ4:
    case FAST_READ:
    case FAST_READ4:
    case DOR:
    case DOR4:
    case QOR:
    case QOR4:
    case DIOR:
    case DIOR4:
    case QIOR:
    case QIOR4:
        s->state = STATE_READ;
        break;
    case ERASE_4K:
    case ERASE4_4K:
    case ERASE_32K:
    case ERASE4_32K:
    case ERASE_SECTOR:
    case ERASE4_SECTOR:
    case DIE_ERASE:
        flash_erase(s, s->cur_addr, s->cmd_in_progress);
        break;
    case WRSR:
        s->status_register_write_disabled = extract32(s->data[0], 7, 1);
        s->block_protect0 = extract32(s->data[0], 2, 1);
        s->block_protect1 = extract32(s->data[0], 3, 1);
        s->block_protect2 = extract32(s->data[0], 4, 1);
        if (s->pi->flags & HAS_SR_TB) {
            s->top_bottom_bit = extract32(s->data[0], 5, 1);
        }
        if (s->pi->flags & HAS_SR_BP3_BIT6) {
            s->block_protect3 = extract32(s->data[0], 6, 1);
        }

        switch (get_man(s)) {
        case MAN_SPANSION:
            s->quad_enable = !!(s->data[1] & 0x02);
            break;
        case MAN_ISSI:
            s->quad_enable = extract32(s->data[0], 6, 1);
            break;
        case MAN_MACRONIX:
            s->quad_enable = extract32(s->data[0], 6, 1);
            if (s->len > 1) {
                s->volatile_cfg = s->data[1];
                s->four_bytes_address_mode = extract32(s->data[1], 5, 1);
            }
            break;
        case MAN_WINBOND:
            if (s->len > 1) {
                s->quad_enable = !!(s->data[1] & 0x02);
            }
            break;
        default:
            break;
        }
        if (s->write_enable) {
            s->write_enable = false;
        }
        break;
    case WRSR2:
        switch (get_man(s)) {
        case MAN_WINBOND:
            s->quad_enable = !!(s->data[0] & 0x02);
            break;
        default:
            break;
        }
        break;
    case BRWR:
    case EXTEND_ADDR_WRITE:
        s->ear = s->data[0];
        break;
    case WNVCR:
        s->nonvolatile_cfg = s->data[0] | (s->data[1] << 8);
        break;
    case WVCR:
        s->volatile_cfg = s->data[0];
        break;
    case WEVCR:
        s->enh_volatile_cfg = s->data[0];
        break;
    case RDID_90:
    case RDID_AB:
        if (get_man(s) == MAN_SST) {
            if (s->cur_addr <= 1) {
                if (s->cur_addr) {
                    s->data[0] = s->pi->id[2];
                    s->data[1] = s->pi->id[0];
                } else {
                    s->data[0] = s->pi->id[0];
                    s->data[1] = s->pi->id[2];
                }
                s->pos = 0;
                s->len = 2;
                s->data_read_loop = true;
                s->state = STATE_READING_DATA;
            } else {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "M25P80: Invalid read id address\n");
            }
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "M25P80: Read id (command 0x90/0xAB) is not supported"
                          " by device\n");
        }
        break;

    case RDSFDP:
        s->state = STATE_READING_SFDP;
        break;

    default:
        break;
    }
}

static void reset_memory(Flash *s)
{
    s->cmd_in_progress = NOP;
    s->cur_addr = 0;
    s->ear = 0;
    s->four_bytes_address_mode = false;
    s->len = 0;
    s->needed_bytes = 0;
    s->pos = 0;
    s->state = STATE_IDLE;
    s->write_enable = false;
    s->reset_enable = false;
    s->quad_enable = false;
    s->aai_enable = false;

    switch (get_man(s)) {
    case MAN_NUMONYX:
        s->volatile_cfg = 0;
        s->volatile_cfg |= VCFG_DUMMY;
        s->volatile_cfg |= VCFG_WRAP_SEQUENTIAL;
        if ((s->nonvolatile_cfg & NVCFG_XIP_MODE_MASK)
                                == NVCFG_XIP_MODE_DISABLED) {
            s->volatile_cfg |= VCFG_XIP_MODE_DISABLED;
        }
        s->volatile_cfg |= deposit32(s->volatile_cfg,
                            VCFG_DUMMY_CLK_POS,
                            CFG_DUMMY_CLK_LEN,
                            extract32(s->nonvolatile_cfg,
                                        NVCFG_DUMMY_CLK_POS,
                                        CFG_DUMMY_CLK_LEN)
                            );

        s->enh_volatile_cfg = 0;
        s->enh_volatile_cfg |= EVCFG_OUT_DRIVER_STRENGTH_DEF;
        s->enh_volatile_cfg |= EVCFG_VPP_ACCELERATOR;
        s->enh_volatile_cfg |= EVCFG_RESET_HOLD_ENABLED;
        if (s->nonvolatile_cfg & NVCFG_DUAL_IO_MASK) {
            s->enh_volatile_cfg |= EVCFG_DUAL_IO_DISABLED;
        }
        if (s->nonvolatile_cfg & NVCFG_QUAD_IO_MASK) {
            s->enh_volatile_cfg |= EVCFG_QUAD_IO_DISABLED;
        }
        if (!(s->nonvolatile_cfg & NVCFG_4BYTE_ADDR_MASK)) {
            s->four_bytes_address_mode = true;
        }
        if (!(s->nonvolatile_cfg & NVCFG_LOWER_SEGMENT_MASK)) {
            s->ear = s->size / MAX_3BYTES_SIZE - 1;
        }
        break;
    case MAN_MACRONIX:
        s->volatile_cfg = 0x7;
        break;
    case MAN_SPANSION:
        s->spansion_cr1v = s->spansion_cr1nv;
        s->spansion_cr2v = s->spansion_cr2nv;
        s->spansion_cr3v = s->spansion_cr3nv;
        s->spansion_cr4v = s->spansion_cr4nv;
        s->quad_enable = extract32(s->spansion_cr1v,
                                   SPANSION_QUAD_CFG_POS,
                                   SPANSION_QUAD_CFG_LEN
                                   );
        s->four_bytes_address_mode = extract32(s->spansion_cr2v,
                SPANSION_ADDR_LEN_POS,
                SPANSION_ADDR_LEN_LEN
                );
        break;
    default:
        break;
    }

    trace_m25p80_reset_done(s);
}

static uint8_t numonyx_mode(Flash *s)
{
    if (!(s->enh_volatile_cfg & EVCFG_QUAD_IO_DISABLED)) {
        return MODE_QIO;
    } else if (!(s->enh_volatile_cfg & EVCFG_DUAL_IO_DISABLED)) {
        return MODE_DIO;
    } else {
        return MODE_STD;
    }
}

static uint8_t numonyx_extract_cfg_dummy_bytes(Flash *s)
{
    uint8_t dummy_bits;
    uint8_t mode;

    mode = numonyx_mode(s);
    dummy_bits = extract32(s->volatile_cfg, 4, 4);

    /*
     * The default nubmer of dummy cycles is only related to the SPI
     * protocol mode. For QSPI it is 10, otherwise it is 8.
     */
    if (dummy_bits == 0x0 || dummy_bits == 0xf) {
        dummy_bits = (mode == MODE_QIO) ? 10 : 8;
    }

    /*
     * Convert the number of dummy cycles to bytes.
     *
     * In the Dual I/O and Quad I/O protocols, all command phases use 2 or 4
     * lines. In standard/extended SPI mode the phase width depends on the
     * command sequence: output-only fast reads keep the dummy clocks on the
     * single address line, while input/output fast reads use the same 2-line
     * or 4-line phase as the address.
     */

    if (mode == MODE_QIO) {
        dummy_bits *= 4;
    } else if (mode == MODE_DIO) {
        dummy_bits *= 2;
    } else {
        switch (s->cmd_in_progress) {
        case QIOR:
        case QIOR4:
            dummy_bits *= 4;
            break;
        case DIOR:
        case DIOR4:
            dummy_bits *= 2;
            break;
         }
    }

    /*
     * Assert that the dummy bit count is byte-aligned
     * as SSI core can only consume whole dummy bytes.
     */
    assert(dummy_bits % 8 == 0);

    /* return the number of dummy bytes */
    return dummy_bits / 8;
}

static uint8_t macronix_extract_cfg_dummy_bytes(Flash *s, uint8_t bus_width)
{
    static const uint8_t dummy_cycles_fast[4] = { 8, 6, 8, 10 };
    static const uint8_t dummy_cycles_dio[4] = { 4, 6, 8, 10 };
    static const uint8_t dummy_cycles_qio[4] = { 6, 4, 8, 10 };
    const uint8_t *dummy_cycles = dummy_cycles_fast;
    uint8_t dummy_bits;

    switch (s->cmd_in_progress) {
    case DIOR:
    case DIOR4:
        dummy_cycles = dummy_cycles_dio;
        break;
    case QIOR:
    case QIOR4:
        dummy_cycles = dummy_cycles_qio;
        break;
    default:
        break;
    }

    dummy_bits = dummy_cycles[extract32(s->volatile_cfg, 6, 2)];
    dummy_bits *= bus_width;

    /*
     * Assert that the dummy bit count is byte-aligned
     * as SSI core can only consume whole dummy bytes.
     */
    assert(dummy_bits % 8 == 0);

    return dummy_bits / 8;
}

static uint8_t spansion_extract_cfg_dummy_bytes(Flash *s, uint8_t bus_width)
{
    uint8_t dummy_bits;

    dummy_bits = extract32(s->spansion_cr2v, SPANSION_DUMMY_CLK_POS,
                            SPANSION_DUMMY_CLK_LEN);
    dummy_bits *= bus_width;

    /*
     * Assert that the dummy bit count is byte-aligned
     * as SSI core can only consume whole dummy bytes.
     */
    assert(dummy_bits % 8 == 0);

    return dummy_bits / 8;
}

static void decode_fast_read_cmd(Flash *s)
{
    s->needed_bytes = get_addr_length(s);
    switch (get_man(s)) {
    /* Dummy cycles - modeled with bytes writes instead of bits */
    case MAN_SST:
        s->needed_bytes += 1;
        break;
    case MAN_WINBOND:
        s->needed_bytes += 1;
        break;
    case MAN_NUMONYX:
        s->needed_bytes += numonyx_extract_cfg_dummy_bytes(s);
        break;
    case MAN_MACRONIX:
        s->needed_bytes += macronix_extract_cfg_dummy_bytes(s, 1);
        break;
    case MAN_SPANSION:
        s->needed_bytes += spansion_extract_cfg_dummy_bytes(s, 1);
        break;
    case MAN_ISSI:
        /*
         * The Fast Read instruction code is followed by address bytes and
         * dummy cycles, transmitted via the SI line.
         *
         * The number of dummy cycles is configurable but this is currently
         * unmodeled, hence the default value 8 is used.
         *
         * QPI (Quad Peripheral Interface) mode has different default value
         * of dummy cycles, but this is unsupported at the time being.
         */
        s->needed_bytes += 1;
        break;
    default:
        break;
    }
    s->pos = 0;
    s->len = 0;
    s->state = STATE_COLLECTING_DATA;
}

static void decode_dio_read_cmd(Flash *s)
{
    s->needed_bytes = get_addr_length(s);
    /* Dummy cycles modeled with bytes writes instead of bits */
    switch (get_man(s)) {
    case MAN_WINBOND:
        s->needed_bytes += WINBOND_CONTINUOUS_READ_MODE_CMD_LEN;
        break;
    case MAN_SPANSION:
        s->needed_bytes += SPANSION_CONTINUOUS_READ_MODE_CMD_LEN;
        s->needed_bytes += spansion_extract_cfg_dummy_bytes(s, 2);
        break;
    case MAN_NUMONYX:
        s->needed_bytes += numonyx_extract_cfg_dummy_bytes(s);
        break;
    case MAN_MACRONIX:
        s->needed_bytes += macronix_extract_cfg_dummy_bytes(s, 2);
        break;
    case MAN_ISSI:
        /*
         * The Fast Read Dual I/O instruction code is followed by address bytes
         * and dummy cycles, transmitted via the IO1 and IO0 line.
         *
         * The number of dummy cycles is configurable but this is currently
         * unmodeled, hence the default value 4 is used.
         */
        s->needed_bytes += 1;
        break;
    default:
        break;
    }
    s->pos = 0;
    s->len = 0;
    s->state = STATE_COLLECTING_DATA;
}

static void decode_qio_read_cmd(Flash *s)
{
    s->needed_bytes = get_addr_length(s);
    /* Dummy cycles modeled with bytes writes instead of bits */
    switch (get_man(s)) {
    case MAN_WINBOND:
        s->needed_bytes += WINBOND_CONTINUOUS_READ_MODE_CMD_LEN;
        s->needed_bytes += 2;
        break;
    case MAN_SPANSION:
        s->needed_bytes += SPANSION_CONTINUOUS_READ_MODE_CMD_LEN;
        s->needed_bytes += spansion_extract_cfg_dummy_bytes(s, 4);
        break;
    case MAN_NUMONYX:
        s->needed_bytes += numonyx_extract_cfg_dummy_bytes(s);
        break;
    case MAN_MACRONIX:
        s->needed_bytes += macronix_extract_cfg_dummy_bytes(s, 4);
        break;
    case MAN_ISSI:
        /*
         * The Fast Read Quad I/O instruction code is followed by address bytes
         * and dummy cycles, transmitted via the IO3, IO2, IO1 and IO0 line.
         *
         * The number of dummy cycles is configurable but this is currently
         * unmodeled, hence the default value 6 is used.
         *
         * QPI (Quad Peripheral Interface) mode has different default value
         * of dummy cycles, but this is unsupported at the time being.
         */
        s->needed_bytes += 3;
        break;
    default:
        break;
    }
    s->pos = 0;
    s->len = 0;
    s->state = STATE_COLLECTING_DATA;
}

static bool is_valid_aai_cmd(uint32_t cmd)
{
    return cmd == AAI_WP || cmd == WRDI || cmd == RDSR;
}

/*
 * JESD260 Replay Protected Monotonic Counter (RPMC)
 *
 * OP1 carries a 4 byte header (opcode, command type, counter address,
 * reserved) followed by a command specific payload, and is executed when
 * CS# is deasserted. OP2 returns, after one dummy byte, the extended status
 * followed by the tag, counter data and signature staged by the last
 * successful Request Monotonic Counter command.
 *
 * Every counter has its own root key, HMAC key register and counter. The
 * root key and counter are non-volatile and can be backed by "rpmc-drive".
 * The HMAC key register is derived as HMAC-SHA256(root key, key data) and is
 * lost on power cycle. Commands complete immediately so the device is never
 * reported busy.
 */

static bool rpmc_hmac(const uint8_t *key, const uint8_t *data, size_t len,
                      uint8_t *out)
{
    g_autoptr(QCryptoHmac) hmac = NULL;
    size_t out_len = RPMC_SIG_LEN;
    Error *err = NULL;

    hmac = qcrypto_hmac_new(QCRYPTO_HASH_ALGO_SHA256, key, RPMC_KEY_LEN, &err);
    if (!hmac ||
        qcrypto_hmac_bytes(hmac, (const char *)data, len, &out, &out_len,
                           &err) < 0) {
        error_report_err(err);
        return false;
    }

    return true;
}

/* Compare without leaking the position of the first mismatch */
static bool rpmc_sig_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }

    return diff == 0;
}

static size_t rpmc_nv_len(Flash *s)
{
    return RPMC_NV_HDR_LEN + s->pi->rpmc_counters * RPMC_NV_COUNTER_LEN;
}

static void rpmc_nv_encode(Flash *s, uint8_t *buf)
{
    uint8_t *p = buf + RPMC_NV_HDR_LEN;
    int i;

    stl_be_p(buf, RPMC_NV_MAGIC);
    stl_be_p(buf + 4, RPMC_NV_VERSION);
    stl_be_p(buf + 8, s->pi->rpmc_counters);
    for (i = 0; i < s->pi->rpmc_counters; i++) {
        stl_be_p(p, (s->rpmc[i].root_key_valid ? RPMC_NV_FLAG_ROOT_KEY : 0) |
                    (s->rpmc[i].counter_valid ? RPMC_NV_FLAG_COUNTER : 0));
        stl_be_p(p + 4, s->rpmc[i].value);
        memcpy(p + 8, s->rpmc[i].root_key, RPMC_KEY_LEN);
        p += RPMC_NV_COUNTER_LEN;
    }
    stl_be_p(buf + 12, crc32c(0xffffffff, buf + RPMC_NV_HDR_LEN,
                              rpmc_nv_len(s) - RPMC_NV_HDR_LEN));
}

static bool rpmc_nv_save(Flash *s)
{
    uint8_t buf[RPMC_NV_HDR_LEN + RPMC_MAX_COUNTERS * RPMC_NV_COUNTER_LEN];
    int ret;

    if (!s->rpmc_blk) {
        return true;
    }

    rpmc_nv_encode(s, buf);
    ret = blk_pwrite(s->rpmc_blk, 0, rpmc_nv_len(s), buf, BDRV_REQ_FUA);
    if (ret < 0) {
        error_report("M25P80: failed to update RPMC state: %s",
                     strerror(-ret));
        return false;
    }

    return true;
}

static bool rpmc_nv_load(Flash *s, Error **errp)
{
    uint8_t buf[RPMC_NV_HDR_LEN + RPMC_MAX_COUNTERS * RPMC_NV_COUNTER_LEN];
    const uint8_t *p = buf + RPMC_NV_HDR_LEN;
    uint32_t flags;
    int64_t len;
    int i, ret;

    len = blk_getlength(s->rpmc_blk);
    if (len < 0) {
        error_setg_errno(errp, -len, "can't get size of rpmc-drive");
        return false;
    }
    if (len < RPMC_NV_SIZE) {
        error_setg(errp, "rpmc-drive must be at least %d bytes", RPMC_NV_SIZE);
        return false;
    }

    ret = blk_pread(s->rpmc_blk, 0, rpmc_nv_len(s), buf, 0);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "failed to read rpmc-drive");
        return false;
    }

    if (ldl_be_p(buf) != RPMC_NV_MAGIC) {
        /* Blank image: factory state, no root keys and all counters 0 */
        if (!buffer_is_zero(buf, RPMC_NV_HDR_LEN) &&
            !(ldl_be_p(buf) == UINT32_MAX && ldl_be_p(buf + 4) == UINT32_MAX)) {
            error_setg(errp, "rpmc-drive does not contain RPMC state");
            return false;
        }
        if (!rpmc_nv_save(s)) {
            error_setg(errp, "failed to initialize rpmc-drive");
            return false;
        }
        return true;
    }

    if (ldl_be_p(buf + 4) != RPMC_NV_VERSION) {
        error_setg(errp, "rpmc-drive has unsupported version %u",
                   ldl_be_p(buf + 4));
        return false;
    }
    if (ldl_be_p(buf + 8) != s->pi->rpmc_counters) {
        error_setg(errp, "rpmc-drive holds %u counters, %s has %u",
                   ldl_be_p(buf + 8), s->pi->part_name, s->pi->rpmc_counters);
        return false;
    }
    if (ldl_be_p(buf + 12) != crc32c(0xffffffff, buf + RPMC_NV_HDR_LEN,
                                     rpmc_nv_len(s) - RPMC_NV_HDR_LEN)) {
        error_setg(errp, "rpmc-drive is corrupted (CRC mismatch)");
        return false;
    }

    for (i = 0; i < s->pi->rpmc_counters; i++) {
        flags = ldl_be_p(p);
        s->rpmc[i].root_key_valid = flags & RPMC_NV_FLAG_ROOT_KEY;
        s->rpmc[i].counter_valid = flags & (RPMC_NV_FLAG_ROOT_KEY |
                                            RPMC_NV_FLAG_COUNTER);
        s->rpmc[i].value = ldl_be_p(p + 4);
        memcpy(s->rpmc[i].root_key, p + 8, RPMC_KEY_LEN);
        p += RPMC_NV_COUNTER_LEN;
    }

    return true;
}

static uint8_t rpmc_write_root_key(Flash *s, RPMCCounter *c, const uint8_t *msg)
{
    const uint8_t *key = msg + RPMC_HDR_LEN;
    const uint8_t *trunc_sig = key + RPMC_KEY_LEN;
    uint8_t sig[RPMC_SIG_LEN];
    RPMCCounter old = *c;
    int i;

    if (c->root_key_valid) {
        return RPMC_ES_ROOT_KEY;
    }

    /* The truncated signature is the last 224 bits of the HMAC */
    if (!rpmc_hmac(key, msg, RPMC_HDR_LEN, sig)) {
        return RPMC_ES_FATAL;
    }
    if (!rpmc_sig_equal(sig + RPMC_SIG_LEN - RPMC_TRUNC_SIG_LEN, trunc_sig,
                        RPMC_TRUNC_SIG_LEN)) {
        return RPMC_ES_ROOT_KEY;
    }

    /*
     * An all-ones root key is a temporary key: it initializes the counter
     * but leaves the root key register writable. A counter that is already
     * initialized keeps its value. Any HMAC key derived from the previous
     * root key is dropped.
     */
    memcpy(c->root_key, key, RPMC_KEY_LEN);
    c->root_key_valid = false;
    for (i = 0; i < RPMC_KEY_LEN; i++) {
        c->root_key_valid |= key[i] != 0xff;
    }
    if (!c->counter_valid) {
        c->counter_valid = true;
        c->value = 0;
    }
    c->hmac_key_valid = false;
    memset(c->hmac_key, 0, RPMC_KEY_LEN);
    if (!rpmc_nv_save(s)) {
        *c = old;
        return RPMC_ES_FATAL;
    }

    return RPMC_ES_SUCCESS;
}

static uint8_t rpmc_update_hmac_key(RPMCCounter *c, const uint8_t *msg)
{
    const uint8_t *key_data = msg + RPMC_HDR_LEN;
    const uint8_t *msg_sig = key_data + RPMC_KEY_DATA_LEN;
    uint8_t hmac_key[RPMC_KEY_LEN];
    uint8_t sig[RPMC_SIG_LEN];

    if (!c->counter_valid) {
        return RPMC_ES_ROOT_KEY;
    }

    if (!rpmc_hmac(c->root_key, key_data, RPMC_KEY_DATA_LEN, hmac_key) ||
        !rpmc_hmac(hmac_key, msg, RPMC_HDR_LEN + RPMC_KEY_DATA_LEN, sig)) {
        return RPMC_ES_FATAL;
    }
    if (!rpmc_sig_equal(sig, msg_sig, RPMC_SIG_LEN)) {
        return RPMC_ES_PAYLOAD;
    }

    memcpy(c->hmac_key, hmac_key, RPMC_KEY_LEN);
    c->hmac_key_valid = true;

    return RPMC_ES_SUCCESS;
}

static uint8_t rpmc_increment_counter(Flash *s, RPMCCounter *c,
                                      const uint8_t *msg)
{
    const uint8_t *counter_data = msg + RPMC_HDR_LEN;
    const uint8_t *msg_sig = counter_data + RPMC_COUNTER_LEN;
    uint8_t sig[RPMC_SIG_LEN];

    if (!c->hmac_key_valid) {
        return RPMC_ES_HMAC_KEY_UNINIT;
    }

    /* Authenticate before revealing whether the counter data matches */
    if (!rpmc_hmac(c->hmac_key, msg, RPMC_HDR_LEN + RPMC_COUNTER_LEN, sig)) {
        return RPMC_ES_FATAL;
    }
    if (!rpmc_sig_equal(sig, msg_sig, RPMC_SIG_LEN)) {
        return RPMC_ES_PAYLOAD;
    }
    if (ldl_be_p(counter_data) != c->value) {
        return RPMC_ES_COUNTER_MISMATCH;
    }
    /* JESD260 does not define wrap around, an exhausted counter is fatal */
    if (c->value == UINT32_MAX) {
        return RPMC_ES_FATAL;
    }

    c->value++;
    if (!rpmc_nv_save(s)) {
        c->value--;
        return RPMC_ES_FATAL;
    }

    return RPMC_ES_SUCCESS;
}

static uint8_t rpmc_request_counter(Flash *s, RPMCCounter *c,
                                    const uint8_t *msg)
{
    const uint8_t *tag = msg + RPMC_HDR_LEN;
    const uint8_t *msg_sig = tag + RPMC_TAG_LEN;
    uint8_t *resp_counter = s->rpmc_resp + RPMC_TAG_LEN;
    uint8_t *resp_sig = resp_counter + RPMC_COUNTER_LEN;
    uint8_t sig[RPMC_SIG_LEN];

    if (!c->hmac_key_valid) {
        return RPMC_ES_HMAC_KEY_UNINIT;
    }

    if (!rpmc_hmac(c->hmac_key, msg, RPMC_HDR_LEN + RPMC_TAG_LEN, sig)) {
        return RPMC_ES_FATAL;
    }
    if (!rpmc_sig_equal(sig, msg_sig, RPMC_SIG_LEN)) {
        return RPMC_ES_PAYLOAD;
    }

    memcpy(s->rpmc_resp, tag, RPMC_TAG_LEN);
    stl_be_p(resp_counter, c->value);
    if (!rpmc_hmac(c->hmac_key, s->rpmc_resp, RPMC_TAG_LEN + RPMC_COUNTER_LEN,
                   resp_sig)) {
        memset(s->rpmc_resp, 0, RPMC_RESP_LEN);
        return RPMC_ES_FATAL;
    }

    return RPMC_ES_SUCCESS;
}

/* Called when CS# is deasserted at the end of an OP1 packet */
static void rpmc_op1_complete(Flash *s)
{
    const uint8_t *msg = s->rpmc_in;
    uint32_t expected_len;
    uint8_t cmd_type = msg[1];
    uint8_t counter = msg[2];
    uint8_t status;

    /* A new OP1 always invalidates the previously staged response */
    memset(s->rpmc_resp, 0, RPMC_RESP_LEN);

    switch (cmd_type) {
    case RPMC_CMD_WRITE_ROOT_KEY:
        expected_len = RPMC_HDR_LEN + RPMC_KEY_LEN + RPMC_TRUNC_SIG_LEN;
        break;
    case RPMC_CMD_UPDATE_HMAC_KEY:
        expected_len = RPMC_HDR_LEN + RPMC_KEY_DATA_LEN + RPMC_SIG_LEN;
        break;
    case RPMC_CMD_INCREMENT_COUNTER:
        expected_len = RPMC_HDR_LEN + RPMC_COUNTER_LEN + RPMC_SIG_LEN;
        break;
    case RPMC_CMD_REQUEST_COUNTER:
        expected_len = RPMC_HDR_LEN + RPMC_TAG_LEN + RPMC_SIG_LEN;
        break;
    default:
        expected_len = 0;
        break;
    }

    if (s->rpmc_in_len < RPMC_HDR_LEN || !expected_len ||
        s->rpmc_in_len != expected_len ||
        counter >= s->pi->rpmc_counters) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "M25P80: Invalid RPMC OP1 packet: cmd type 0x%x, "
                      "counter %u, length %u\n",
                      cmd_type, counter, s->rpmc_in_len);
        status = RPMC_ES_PAYLOAD;
        goto out;
    }

    switch (cmd_type) {
    case RPMC_CMD_WRITE_ROOT_KEY:
        status = rpmc_write_root_key(s, &s->rpmc[counter], msg);
        break;
    case RPMC_CMD_UPDATE_HMAC_KEY:
        status = rpmc_update_hmac_key(&s->rpmc[counter], msg);
        break;
    case RPMC_CMD_INCREMENT_COUNTER:
        status = rpmc_increment_counter(s, &s->rpmc[counter], msg);
        break;
    case RPMC_CMD_REQUEST_COUNTER:
        status = rpmc_request_counter(s, &s->rpmc[counter], msg);
        break;
    default:
        g_assert_not_reached();
    }

out:
    s->rpmc_status = status;
    trace_m25p80_rpmc_op1(s, cmd_type, counter, s->rpmc_in_len, status);
}

static uint8_t rpmc_op2_read(Flash *s)
{
    uint32_t pos = s->rpmc_out_pos;
    uint8_t r;

    if (pos == 0) {
        r = 0; /* dummy byte */
    } else if (pos == 1) {
        r = s->rpmc_status;
    } else if (pos < 2 + RPMC_RESP_LEN) {
        r = s->rpmc_resp[pos - 2];
    } else {
        r = 0xff;
    }

    if (pos < 2 + RPMC_RESP_LEN) {
        s->rpmc_out_pos++;
    }
    trace_m25p80_rpmc_op2(s, pos, r);

    return r;
}

static void decode_rpmc_cmd(Flash *s, uint8_t value)
{
    if (value == RPMC_OP1) {
        s->rpmc_in[0] = value;
        s->rpmc_in_len = 1;
        s->state = STATE_RPMC_COLLECTING;
    } else {
        s->rpmc_out_pos = 0;
        s->state = STATE_RPMC_READING;
    }
}

static void rpmc_reset(Flash *s)
{
    int i;

    for (i = 0; i < RPMC_MAX_COUNTERS; i++) {
        s->rpmc[i].hmac_key_valid = false;
        memset(s->rpmc[i].hmac_key, 0, RPMC_KEY_LEN);
    }
    s->rpmc_status = 0;
    s->rpmc_in_len = 0;
    s->rpmc_out_pos = 0;
    memset(s->rpmc_resp, 0, RPMC_RESP_LEN);
}

static void decode_new_cmd(Flash *s, uint32_t value)
{
    int i;

    s->cmd_in_progress = value;
    trace_m25p80_command_decoded(s, value);

    if (value != RESET_MEMORY) {
        s->reset_enable = false;
    }

    if (get_man(s) == MAN_SST && s->aai_enable && !is_valid_aai_cmd(value)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "M25P80: Invalid cmd within AAI programming sequence");
    }

    if (s->pi->rpmc_counters && (value == RPMC_OP1 || value == RPMC_OP2)) {
        decode_rpmc_cmd(s, value);
        return;
    }

    switch (value) {

    case ERASE_4K:
    case ERASE4_4K:
    case ERASE_32K:
    case ERASE4_32K:
    case ERASE_SECTOR:
    case ERASE4_SECTOR:
    case PP:
    case PP4:
    case DIE_ERASE:
    case RDID_90:
    case RDID_AB:
        s->needed_bytes = get_addr_length(s);
        s->pos = 0;
        s->len = 0;
        s->state = STATE_COLLECTING_DATA;
        break;
    case READ:
    case READ4:
        if (get_man(s) != MAN_NUMONYX || numonyx_mode(s) == MODE_STD) {
            s->needed_bytes = get_addr_length(s);
            s->pos = 0;
            s->len = 0;
            s->state = STATE_COLLECTING_DATA;
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: Cannot execute cmd %x in "
                          "DIO or QIO mode\n", s->cmd_in_progress);
        }
        break;
    case DPP:
        if (get_man(s) != MAN_NUMONYX || numonyx_mode(s) != MODE_QIO) {
            s->needed_bytes = get_addr_length(s);
            s->pos = 0;
            s->len = 0;
            s->state = STATE_COLLECTING_DATA;
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: Cannot execute cmd %x in "
                          "QIO mode\n", s->cmd_in_progress);
        }
        break;
    case QPP:
    case QPP_4:
    case PP4_4:
        if (get_man(s) != MAN_NUMONYX || numonyx_mode(s) != MODE_DIO) {
            s->needed_bytes = get_addr_length(s);
            s->pos = 0;
            s->len = 0;
            s->state = STATE_COLLECTING_DATA;
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: Cannot execute cmd %x in "
                          "DIO mode\n", s->cmd_in_progress);
        }
        break;

    case FAST_READ:
    case FAST_READ4:
        decode_fast_read_cmd(s);
        break;
    case DOR:
    case DOR4:
        if (get_man(s) != MAN_NUMONYX || numonyx_mode(s) != MODE_QIO) {
            decode_fast_read_cmd(s);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: Cannot execute cmd %x in "
                          "QIO mode\n", s->cmd_in_progress);
        }
        break;
    case QOR:
    case QOR4:
        if (get_man(s) != MAN_NUMONYX || numonyx_mode(s) != MODE_DIO) {
            decode_fast_read_cmd(s);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: Cannot execute cmd %x in "
                          "DIO mode\n", s->cmd_in_progress);
        }
        break;

    case DIOR:
    case DIOR4:
        if (get_man(s) != MAN_NUMONYX || numonyx_mode(s) != MODE_QIO) {
            decode_dio_read_cmd(s);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: Cannot execute cmd %x in "
                          "QIO mode\n", s->cmd_in_progress);
        }
        break;

    case QIOR:
    case QIOR4:
        if (get_man(s) != MAN_NUMONYX || numonyx_mode(s) != MODE_DIO) {
            decode_qio_read_cmd(s);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: Cannot execute cmd %x in "
                          "DIO mode\n", s->cmd_in_progress);
        }
        break;

    case WRSR:
        /*
         * If WP# is low and status_register_write_disabled is high,
         * status register writes are disabled.
         * This is also called "hardware protected mode" (HPM). All other
         * combinations of the two states are called "software protected mode"
         * (SPM), and status register writes are permitted.
         */
        if ((s->wp_level == 0 && s->status_register_write_disabled)
            || !s->write_enable) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "M25P80: Status register write is disabled!\n");
            break;
        }

        switch (get_man(s)) {
        case MAN_SPANSION:
            s->needed_bytes = 2;
            s->state = STATE_COLLECTING_DATA;
            break;
        case MAN_MACRONIX:
            s->needed_bytes = 2;
            s->state = STATE_COLLECTING_VAR_LEN_DATA;
            break;
        case MAN_WINBOND:
            s->needed_bytes = 2;
            s->state = STATE_COLLECTING_VAR_LEN_DATA;
            break;
        default:
            s->needed_bytes = 1;
            s->state = STATE_COLLECTING_DATA;
        }
        s->pos = 0;
        break;
    case WRSR2:
        /*
         * If WP# is low and status_register_write_disabled is high,
         * status register writes are disabled.
         * This is also called "hardware protected mode" (HPM). All other
         * combinations of the two states are called "software protected mode"
         * (SPM), and status register writes are permitted.
         */
        if ((s->wp_level == 0 && s->status_register_write_disabled)
            || !s->write_enable) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "M25P80: Status register 2 write is disabled!\n");
            break;
        }

        switch (get_man(s)) {
        case MAN_WINBOND:
            s->needed_bytes = 1;
            s->state = STATE_COLLECTING_DATA;
            s->pos = 0;
            break;
        default:
            break;
        }
        break;
    case WRDI:
        s->write_enable = false;
        if (get_man(s) == MAN_SST) {
            s->aai_enable = false;
        }
        break;
    case WREN:
        s->write_enable = true;
        break;

    case RDSR:
        s->data[0] = (!!s->write_enable) << 1;
        s->data[0] |= (!!s->status_register_write_disabled) << 7;
        s->data[0] |= (!!s->block_protect0) << 2;
        s->data[0] |= (!!s->block_protect1) << 3;
        s->data[0] |= (!!s->block_protect2) << 4;
        if (s->pi->flags & HAS_SR_TB) {
            s->data[0] |= (!!s->top_bottom_bit) << 5;
        }
        if (s->pi->flags & HAS_SR_BP3_BIT6) {
            s->data[0] |= (!!s->block_protect3) << 6;
        }

        if (get_man(s) == MAN_MACRONIX || get_man(s) == MAN_ISSI) {
            s->data[0] |= (!!s->quad_enable) << 6;
        }
        if (get_man(s) == MAN_SST) {
            s->data[0] |= (!!s->aai_enable) << 6;
        }

        s->pos = 0;
        s->len = 1;
        s->data_read_loop = true;
        s->state = STATE_READING_DATA;
        break;

    case READ_FSR:
        s->data[0] = FSR_FLASH_READY;
        if (s->four_bytes_address_mode) {
            s->data[0] |= FSR_4BYTE_ADDR_MODE_ENABLED;
        }
        s->pos = 0;
        s->len = 1;
        s->data_read_loop = true;
        s->state = STATE_READING_DATA;
        break;

    case JEDEC_READ:
        if (get_man(s) != MAN_NUMONYX || numonyx_mode(s) == MODE_STD) {
            trace_m25p80_populated_jedec(s);
            for (i = 0; i < s->pi->id_len; i++) {
                s->data[i] = s->pi->id[i];
            }
            for (; i < SPI_NOR_MAX_ID_LEN; i++) {
                s->data[i] = 0;
            }

            s->len = SPI_NOR_MAX_ID_LEN;
            s->pos = 0;
            s->state = STATE_READING_DATA;
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: Cannot execute JEDEC read "
                          "in DIO or QIO mode\n");
        }
        break;

    case RDCR:
        s->data[0] = s->volatile_cfg & 0xFF;
        s->data[0] |= (!!s->four_bytes_address_mode) << 5;
        s->pos = 0;
        s->len = 1;
        s->state = STATE_READING_DATA;
        break;

    case BULK_ERASE_60:
    case BULK_ERASE:
        if (s->write_enable) {
            trace_m25p80_chip_erase(s);
            flash_erase(s, 0, BULK_ERASE);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: chip erase with write "
                          "protect!\n");
        }
        break;
    case NOP:
        break;
    case EN_4BYTE_ADDR:
        s->four_bytes_address_mode = true;
        break;
    case EX_4BYTE_ADDR:
        s->four_bytes_address_mode = false;
        break;
    case BRRD:
    case EXTEND_ADDR_READ:
        s->data[0] = s->ear;
        s->pos = 0;
        s->len = 1;
        s->state = STATE_READING_DATA;
        break;
    case BRWR:
    case EXTEND_ADDR_WRITE:
        if (s->write_enable) {
            s->needed_bytes = 1;
            s->pos = 0;
            s->len = 0;
            s->state = STATE_COLLECTING_DATA;
        }
        break;
    case RNVCR:
        s->data[0] = s->nonvolatile_cfg & 0xFF;
        s->data[1] = (s->nonvolatile_cfg >> 8) & 0xFF;
        s->pos = 0;
        s->len = 2;
        s->state = STATE_READING_DATA;
        break;
    case WNVCR:
        if (s->write_enable && get_man(s) == MAN_NUMONYX) {
            s->needed_bytes = 2;
            s->pos = 0;
            s->len = 0;
            s->state = STATE_COLLECTING_DATA;
        }
        break;
    case RVCR:
        s->data[0] = s->volatile_cfg & 0xFF;
        s->pos = 0;
        s->len = 1;
        s->state = STATE_READING_DATA;
        break;
    case WVCR:
        if (s->write_enable) {
            s->needed_bytes = 1;
            s->pos = 0;
            s->len = 0;
            s->state = STATE_COLLECTING_DATA;
        }
        break;
    case REVCR:
        s->data[0] = s->enh_volatile_cfg & 0xFF;
        s->pos = 0;
        s->len = 1;
        s->state = STATE_READING_DATA;
        break;
    case WEVCR:
        if (s->write_enable) {
            s->needed_bytes = 1;
            s->pos = 0;
            s->len = 0;
            s->state = STATE_COLLECTING_DATA;
        }
        break;
    case RESET_ENABLE:
        s->reset_enable = true;
        break;
    case RESET_MEMORY:
        if (s->reset_enable) {
            reset_memory(s);
        }
        break;
    case RDCR_EQIO:
        switch (get_man(s)) {
        case MAN_SPANSION:
            s->data[0] = (!!s->quad_enable) << 1;
            s->pos = 0;
            s->len = 1;
            s->state = STATE_READING_DATA;
            break;
        case MAN_MACRONIX:
            s->quad_enable = true;
            break;
        case MAN_WINBOND:
            s->data[0] = (!!s->quad_enable) << 1;
            s->pos = 0;
            s->len = 1;
            s->state = STATE_READING_DATA;
            break;
        default:
            break;
        }
        break;
    case RSTQIO:
        s->quad_enable = false;
        break;
    case AAI_WP:
        if (get_man(s) == MAN_SST) {
            if (s->write_enable) {
                if (s->aai_enable) {
                    s->state = STATE_PAGE_PROGRAM;
                } else {
                    s->aai_enable = true;
                    s->needed_bytes = get_addr_length(s);
                    s->state = STATE_COLLECTING_DATA;
                }
            } else {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "M25P80: AAI_WP with write protect\n");
            }
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "M25P80: Unknown cmd %x\n", value);
        }
        break;
    case RDSFDP:
        if (s->pi->sfdp_read) {
            s->needed_bytes = get_addr_length(s) + 1; /* SFDP addr + dummy */
            s->pos = 0;
            s->len = 0;
            s->state = STATE_COLLECTING_DATA;
            break;
        }
        /* Fallthrough */

    default:
        s->pos = 0;
        s->len = 1;
        s->state = STATE_READING_DATA;
        s->data_read_loop = true;
        s->data[0] = 0;
        qemu_log_mask(LOG_GUEST_ERROR, "M25P80: Unknown cmd %x\n", value);
        break;
    }
}

static int m25p80_cs(SSIPeripheral *ss, bool select)
{
    Flash *s = M25P80(ss);

    if (select) {
        if (s->state == STATE_COLLECTING_VAR_LEN_DATA) {
            complete_collecting_data(s);
        } else if (s->state == STATE_RPMC_COLLECTING) {
            rpmc_op1_complete(s);
        }
        s->len = 0;
        s->pos = 0;
        s->state = STATE_IDLE;
        flash_sync_dirty(s, -1);
        s->data_read_loop = false;
    }

    trace_m25p80_select(s, select ? "de" : "");

    return 0;
}

static uint32_t m25p80_transfer8(SSIPeripheral *ss, uint32_t tx)
{
    Flash *s = M25P80(ss);
    uint32_t r = 0;

    trace_m25p80_transfer(s, s->state, s->len, s->needed_bytes, s->pos,
                          s->cur_addr, (uint8_t)tx);

    switch (s->state) {

    case STATE_PAGE_PROGRAM:
        trace_m25p80_page_program(s, s->cur_addr, (uint8_t)tx);
        flash_write8(s, s->cur_addr, (uint8_t)tx);
        s->cur_addr = (s->cur_addr + 1) & (s->size - 1);

        if (get_man(s) == MAN_SST && s->aai_enable && s->cur_addr == 0) {
            /*
             * There is no wrap mode during AAI programming once the highest
             * unprotected memory address is reached. The Write-Enable-Latch
             * bit is automatically reset, and AAI programming mode aborts.
             */
            s->write_enable = false;
            s->aai_enable = false;
        }

        break;

    case STATE_READ:
        r = s->storage[s->cur_addr];
        trace_m25p80_read_byte(s, s->cur_addr, (uint8_t)r);
        s->cur_addr = (s->cur_addr + 1) & (s->size - 1);
        break;

    case STATE_COLLECTING_DATA:
    case STATE_COLLECTING_VAR_LEN_DATA:

        if (s->len >= M25P80_INTERNAL_DATA_BUFFER_SZ) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "M25P80: Write overrun internal data buffer. "
                          "SPI controller (QEMU emulator or guest driver) "
                          "is misbehaving\n");
            s->len = s->pos = 0;
            s->state = STATE_IDLE;
            break;
        }

        s->data[s->len] = (uint8_t)tx;
        s->len++;

        if (s->len == s->needed_bytes) {
            complete_collecting_data(s);
        }
        break;

    case STATE_READING_DATA:

        if (s->pos >= M25P80_INTERNAL_DATA_BUFFER_SZ) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "M25P80: Read overrun internal data buffer. "
                          "SPI controller (QEMU emulator or guest driver) "
                          "is misbehaving\n");
            s->len = s->pos = 0;
            s->state = STATE_IDLE;
            break;
        }

        r = s->data[s->pos];
        trace_m25p80_read_data(s, s->pos, (uint8_t)r);
        s->pos++;
        if (s->pos == s->len) {
            s->pos = 0;
            if (!s->data_read_loop) {
                s->state = STATE_IDLE;
            }
        }
        break;
    case STATE_READING_SFDP:
        assert(s->pi->sfdp_read);
        r = s->pi->sfdp_read(s->cur_addr);
        trace_m25p80_read_sfdp(s, s->cur_addr, (uint8_t)r);
        s->cur_addr = (s->cur_addr + 1) & (M25P80_SFDP_MAX_SIZE - 1);
        break;

    case STATE_RPMC_COLLECTING:
        /* Oversized packets are rejected when CS# is deasserted */
        if (s->rpmc_in_len < RPMC_OP1_MAX_LEN) {
            s->rpmc_in[s->rpmc_in_len++] = (uint8_t)tx;
        } else {
            s->rpmc_in_len = RPMC_OP1_MAX_LEN + 1;
        }
        break;

    case STATE_RPMC_READING:
        r = rpmc_op2_read(s);
        break;

    default:
    case STATE_IDLE:
        decode_new_cmd(s, (uint8_t)tx);
        break;
    }

    return r;
}

static void m25p80_write_protect_pin_irq_handler(void *opaque, int n, int level)
{
    Flash *s = M25P80(opaque);
    /* WP# is just a single pin. */
    assert(n == 0);
    s->wp_level = !!level;
}

static void m25p80_realize(SSIPeripheral *ss, Error **errp)
{
    Flash *s = M25P80(ss);
    M25P80Class *mc = M25P80_GET_CLASS(s);
    int ret;

    s->pi = mc->pi;

    s->size = s->pi->sector_size * s->pi->n_sectors;
    s->dirty_page = -1;

    if (s->blk) {
        uint64_t perm = BLK_PERM_CONSISTENT_READ |
                        (blk_supports_write_perm(s->blk) ? BLK_PERM_WRITE : 0);
        ret = blk_set_perm(s->blk, perm, BLK_PERM_ALL, errp);
        if (ret < 0) {
            return;
        }

        trace_m25p80_binding(s);
        s->storage = blk_blockalign(s->blk, s->size);

        if (!blk_check_size_and_read_all(s->blk, DEVICE(s),
                                         s->storage, s->size, errp)) {
            return;
        }
    } else {
        trace_m25p80_binding_no_bdrv(s);
        s->storage = blk_blockalign(NULL, s->size);
        memset(s->storage, 0xFF, s->size);
    }

    if (s->rpmc_blk) {
        if (!s->pi->rpmc_counters) {
            error_setg(errp, "%s does not support RPMC, rpmc-drive is invalid",
                       s->pi->part_name);
            return;
        }
        if (!blk_supports_write_perm(s->rpmc_blk)) {
            error_setg(errp, "rpmc-drive must be writable");
            return;
        }
        ret = blk_set_perm(s->rpmc_blk,
                           BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE,
                           BLK_PERM_ALL, errp);
        if (ret < 0) {
            return;
        }
    }
    if (s->pi->rpmc_counters) {
        assert(s->pi->rpmc_counters <= RPMC_MAX_COUNTERS);
        if (!qcrypto_hmac_supports(QCRYPTO_HASH_ALGO_SHA256)) {
            error_setg(errp, "RPMC requires HMAC-SHA256 support");
            return;
        }
        if (s->rpmc_blk && !rpmc_nv_load(s, errp)) {
            return;
        }
    }

    qdev_init_gpio_in_named(DEVICE(s),
                            m25p80_write_protect_pin_irq_handler, "WP#", 1);
}

static void m25p80_reset(DeviceState *d)
{
    Flash *s = M25P80(d);

    s->wp_level = true;
    s->status_register_write_disabled = false;
    s->block_protect0 = false;
    s->block_protect1 = false;
    s->block_protect2 = false;
    s->block_protect3 = false;
    s->top_bottom_bit = false;

    reset_memory(s);
    rpmc_reset(s);
}

static int m25p80_pre_save(void *opaque)
{
    flash_sync_dirty((Flash *)opaque, -1);

    return 0;
}

static const Property m25p80_properties[] = {
    /* This is default value for Micron flash */
    DEFINE_PROP_BOOL("write-enable", Flash, write_enable, false),
    DEFINE_PROP_UINT32("nonvolatile-cfg", Flash, nonvolatile_cfg, 0x8FFF),
    DEFINE_PROP_UINT8("spansion-cr1nv", Flash, spansion_cr1nv, 0x0),
    DEFINE_PROP_UINT8("spansion-cr2nv", Flash, spansion_cr2nv, 0x8),
    DEFINE_PROP_UINT8("spansion-cr3nv", Flash, spansion_cr3nv, 0x2),
    DEFINE_PROP_UINT8("spansion-cr4nv", Flash, spansion_cr4nv, 0x10),
    DEFINE_PROP_DRIVE("drive", Flash, blk),
    DEFINE_PROP_DRIVE("rpmc-drive", Flash, rpmc_blk),
};

static int m25p80_pre_load(void *opaque)
{
    Flash *s = (Flash *)opaque;

    s->data_read_loop = false;
    return 0;
}

static bool m25p80_data_read_loop_needed(void *opaque)
{
    Flash *s = (Flash *)opaque;

    return s->data_read_loop;
}

static const VMStateDescription vmstate_m25p80_data_read_loop = {
    .name = "m25p80/data_read_loop",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m25p80_data_read_loop_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(data_read_loop, Flash),
        VMSTATE_END_OF_LIST()
    }
};

static bool m25p80_aai_enable_needed(void *opaque)
{
    Flash *s = (Flash *)opaque;

    return s->aai_enable;
}

static const VMStateDescription vmstate_m25p80_aai_enable = {
    .name = "m25p80/aai_enable",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m25p80_aai_enable_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(aai_enable, Flash),
        VMSTATE_END_OF_LIST()
    }
};

static bool m25p80_wp_level_srwd_needed(void *opaque)
{
    Flash *s = (Flash *)opaque;

    return !s->wp_level || s->status_register_write_disabled;
}

static const VMStateDescription vmstate_m25p80_write_protect = {
    .name = "m25p80/write_protect",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m25p80_wp_level_srwd_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(wp_level, Flash),
        VMSTATE_BOOL(status_register_write_disabled, Flash),
        VMSTATE_END_OF_LIST()
    }
};

static bool m25p80_block_protect_needed(void *opaque)
{
    Flash *s = (Flash *)opaque;

    return s->block_protect0 ||
           s->block_protect1 ||
           s->block_protect2 ||
           s->block_protect3 ||
           s->top_bottom_bit;
}

static const VMStateDescription vmstate_m25p80_block_protect = {
    .name = "m25p80/block_protect",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m25p80_block_protect_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(block_protect0, Flash),
        VMSTATE_BOOL(block_protect1, Flash),
        VMSTATE_BOOL(block_protect2, Flash),
        VMSTATE_BOOL(block_protect3, Flash),
        VMSTATE_BOOL(top_bottom_bit, Flash),
        VMSTATE_END_OF_LIST()
    }
};

static bool m25p80_rpmc_needed(void *opaque)
{
    Flash *s = (Flash *)opaque;

    return s->pi->rpmc_counters;
}

static const VMStateDescription vmstate_m25p80_rpmc_counter = {
    .name = "m25p80/rpmc/counter",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(root_key_valid, RPMCCounter),
        VMSTATE_UINT8_ARRAY(root_key, RPMCCounter, RPMC_KEY_LEN),
        VMSTATE_BOOL(counter_valid, RPMCCounter),
        VMSTATE_UINT32(value, RPMCCounter),
        VMSTATE_BOOL(hmac_key_valid, RPMCCounter),
        VMSTATE_UINT8_ARRAY(hmac_key, RPMCCounter, RPMC_KEY_LEN),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_m25p80_rpmc = {
    .name = "m25p80/rpmc",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m25p80_rpmc_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(rpmc, Flash, RPMC_MAX_COUNTERS, 1,
                             vmstate_m25p80_rpmc_counter, RPMCCounter),
        VMSTATE_UINT8(rpmc_status, Flash),
        VMSTATE_UINT8_ARRAY(rpmc_in, Flash, RPMC_OP1_MAX_LEN),
        VMSTATE_UINT32(rpmc_in_len, Flash),
        VMSTATE_UINT8_ARRAY(rpmc_resp, Flash, RPMC_RESP_LEN),
        VMSTATE_UINT32(rpmc_out_pos, Flash),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_m25p80 = {
    .name = "m25p80",
    .version_id = 0,
    .minimum_version_id = 0,
    .pre_save = m25p80_pre_save,
    .pre_load = m25p80_pre_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT8(state, Flash),
        VMSTATE_UINT8_ARRAY(data, Flash, M25P80_INTERNAL_DATA_BUFFER_SZ),
        VMSTATE_UINT32(len, Flash),
        VMSTATE_UINT32(pos, Flash),
        VMSTATE_UINT8(needed_bytes, Flash),
        VMSTATE_UINT8(cmd_in_progress, Flash),
        VMSTATE_UINT32(cur_addr, Flash),
        VMSTATE_BOOL(write_enable, Flash),
        VMSTATE_BOOL(reset_enable, Flash),
        VMSTATE_UINT8(ear, Flash),
        VMSTATE_BOOL(four_bytes_address_mode, Flash),
        VMSTATE_UINT32(nonvolatile_cfg, Flash),
        VMSTATE_UINT32(volatile_cfg, Flash),
        VMSTATE_UINT32(enh_volatile_cfg, Flash),
        VMSTATE_BOOL(quad_enable, Flash),
        VMSTATE_UINT8(spansion_cr1nv, Flash),
        VMSTATE_UINT8(spansion_cr2nv, Flash),
        VMSTATE_UINT8(spansion_cr3nv, Flash),
        VMSTATE_UINT8(spansion_cr4nv, Flash),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_m25p80_data_read_loop,
        &vmstate_m25p80_aai_enable,
        &vmstate_m25p80_write_protect,
        &vmstate_m25p80_block_protect,
        &vmstate_m25p80_rpmc,
        NULL
    }
};

static void m25p80_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SSIPeripheralClass *k = SSI_PERIPHERAL_CLASS(klass);
    M25P80Class *mc = M25P80_CLASS(klass);

    k->realize = m25p80_realize;
    k->transfer = m25p80_transfer8;
    k->set_cs = m25p80_cs;
    k->cs_polarity = SSI_CS_LOW;
    dc->vmsd = &vmstate_m25p80;
    device_class_set_props(dc, m25p80_properties);
    device_class_set_legacy_reset(dc, m25p80_reset);
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    mc->pi = data;
    dc->desc = "Serial Flash";
}

static const TypeInfo m25p80_info = {
    .name           = TYPE_M25P80,
    .parent         = TYPE_SSI_PERIPHERAL,
    .instance_size  = sizeof(Flash),
    .class_size     = sizeof(M25P80Class),
    .abstract       = true,
};

static void m25p80_register_types(void)
{
    int i;

    type_register_static(&m25p80_info);
    for (i = 0; i < ARRAY_SIZE(known_devices); ++i) {
        const TypeInfo ti = {
            .name       = known_devices[i].part_name,
            .parent     = TYPE_M25P80,
            .class_init = m25p80_class_init,
            .class_data = &known_devices[i],
        };
        type_register_static(&ti);
    }
}

type_init(m25p80_register_types)

BlockBackend *m25p80_get_blk(DeviceState *dev)
{
    return M25P80(dev)->blk;
}
