/*
 * QTest for the JESD260 Replay Protected Monotonic Counter (RPMC) support
 * of the m25p80 SPI NOR flash model, driven through the PL022 SPI controller
 * and PL061 chip select of the arm virt machine ("-machine virt,spi=...").
 *
 * The host side of the protocol is implemented independently of the device
 * model, following the message layout used by flashrom.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "qemu/bswap.h"
#include "qemu/crc32c.h"
#include "libqtest.h"
#include "crypto/init.h"
#include "crypto/hmac.h"
#include "qapi/error.h"

#define SPI_BASE            0x090d0000
#define PL022_CR0           (SPI_BASE + 0x00)
#define PL022_CR1           (SPI_BASE + 0x04)
#define PL022_DR            (SPI_BASE + 0x08)
#define PL022_SR            (SPI_BASE + 0x0c)
#define PL022_PERIPH_ID0    (SPI_BASE + 0xfe0)
#define PL022_CR0_DSS_8BIT  0x07
#define PL022_CR1_SSE       0x02
#define PL022_SR_RNE        0x04

#define GPIO_BASE           0x090e0000
#define PL061_DATA_CS       (GPIO_BASE + (BIT(0) << 2))
#define PL061_DIR           (GPIO_BASE + 0x400)

#define OP_RDSFDP           0x5a
#define OP_JEDEC_READ       0x9f
#define OP_WREN             0x06
#define OP_PP               0x02
#define OP_READ             0x03
#define OP_RPMC_OP1         0x9b
#define OP_RPMC_OP2         0x96

#define RPMC_NUM_COUNTERS   4
#define RPMC_HDR_LEN        4
#define RPMC_KEY_LEN        32
#define RPMC_SIG_LEN        32
#define RPMC_TRUNC_SIG_LEN  28
#define RPMC_TAG_LEN        12
#define RPMC_RESP_LEN       (1 + RPMC_TAG_LEN + 4 + RPMC_SIG_LEN)
#define RPMC_MAX_MSG_LEN    64

#define CMD_WRITE_ROOT_KEY  0x00
#define CMD_UPDATE_HMAC_KEY 0x01
#define CMD_INCREMENT       0x02
#define CMD_REQUEST         0x03

#define ES_NONE             0x00
#define ES_ROOT_KEY         0x02
#define ES_PAYLOAD          0x04
#define ES_HMAC_KEY_UNINIT  0x08
#define ES_COUNTER_MISMATCH 0x10
#define ES_FATAL            0x20
#define ES_SUCCESS          0x80

#define NV_SIZE             4096
#define NV_HDR_LEN          16
#define NV_COUNTER_LEN      40

typedef struct RPMCMsg {
    uint8_t buf[RPMC_MAX_MSG_LEN + 8];
    size_t len;
} RPMCMsg;

static const uint32_t key_data = 0x12345678;

static void root_key_for(int counter, uint8_t *key)
{
    int i;

    for (i = 0; i < RPMC_KEY_LEN; i++) {
        key[i] = 0x40 + counter * 0x10 + i;
    }
}

/* Host side crypto */

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t len, uint8_t *out)
{
    g_autoptr(QCryptoHmac) hmac = NULL;
    size_t out_len = RPMC_SIG_LEN;

    hmac = qcrypto_hmac_new(QCRYPTO_HASH_ALGO_SHA256, key, key_len,
                            &error_abort);
    g_assert(qcrypto_hmac_bytes(hmac, (const char *)data, len, &out,
                                &out_len, &error_abort) == 0);
}

static void derive_hmac_key(const uint8_t *root_key, uint32_t kd,
                            uint8_t *hmac_key)
{
    uint8_t kd_be[4];

    stl_be_p(kd_be, kd);
    hmac_sha256(root_key, RPMC_KEY_LEN, kd_be, sizeof(kd_be), hmac_key);
}

/* Bus access: PL022 for the data, PL061 pin 0 as CS# */

static void bus_init(QTestState *qts)
{
    qtest_writel(qts, PL061_DATA_CS, 1);
    qtest_writel(qts, PL061_DIR, 1);
    qtest_writel(qts, PL022_CR0, PL022_CR0_DSS_8BIT);
    qtest_writel(qts, PL022_CR1, PL022_CR1_SSE);
}

static void cs_assert(QTestState *qts, bool assert)
{
    qtest_writel(qts, PL061_DATA_CS, assert ? 0 : 1);
}

static uint8_t spi_xfer(QTestState *qts, uint8_t tx)
{
    qtest_writel(qts, PL022_DR, tx);
    g_assert(qtest_readl(qts, PL022_SR) & PL022_SR_RNE);
    return qtest_readl(qts, PL022_DR);
}

static void spi_cmd(QTestState *qts, const uint8_t *tx, size_t tx_len,
                    uint8_t *rx, size_t rx_len)
{
    size_t i;

    cs_assert(qts, true);
    for (i = 0; i < tx_len; i++) {
        spi_xfer(qts, tx[i]);
    }
    for (i = 0; i < rx_len; i++) {
        rx[i] = spi_xfer(qts, 0);
    }
    cs_assert(qts, false);
}

/* RPMC message builders, mirroring flashrom's rpmc.c */

static void msg_header(RPMCMsg *m, uint8_t cmd_type, uint8_t counter)
{
    memset(m, 0, sizeof(*m));
    m->buf[0] = OP_RPMC_OP1;
    m->buf[1] = cmd_type;
    m->buf[2] = counter;
    m->buf[3] = 0;
}

static void build_write_root_key(RPMCMsg *m, uint8_t counter,
                                 const uint8_t *root_key)
{
    uint8_t sig[RPMC_SIG_LEN];

    msg_header(m, CMD_WRITE_ROOT_KEY, counter);
    memcpy(m->buf + 4, root_key, RPMC_KEY_LEN);
    hmac_sha256(root_key, RPMC_KEY_LEN, m->buf, RPMC_HDR_LEN, sig);
    memcpy(m->buf + 36, sig + RPMC_SIG_LEN - RPMC_TRUNC_SIG_LEN,
           RPMC_TRUNC_SIG_LEN);
    m->len = 64;
}

static void build_update_hmac_key(RPMCMsg *m, uint8_t counter,
                                  const uint8_t *root_key, uint32_t kd)
{
    uint8_t hmac_key[RPMC_KEY_LEN];

    msg_header(m, CMD_UPDATE_HMAC_KEY, counter);
    stl_be_p(m->buf + 4, kd);
    derive_hmac_key(root_key, kd, hmac_key);
    hmac_sha256(hmac_key, RPMC_KEY_LEN, m->buf, 8, m->buf + 8);
    m->len = 40;
}

static void build_increment(RPMCMsg *m, uint8_t counter,
                            const uint8_t *hmac_key, uint32_t prev)
{
    msg_header(m, CMD_INCREMENT, counter);
    stl_be_p(m->buf + 4, prev);
    hmac_sha256(hmac_key, RPMC_KEY_LEN, m->buf, 8, m->buf + 8);
    m->len = 40;
}

static void build_request(RPMCMsg *m, uint8_t counter,
                          const uint8_t *hmac_key, const uint8_t *tag)
{
    msg_header(m, CMD_REQUEST, counter);
    memcpy(m->buf + 4, tag, RPMC_TAG_LEN);
    hmac_sha256(hmac_key, RPMC_KEY_LEN, m->buf, 16, m->buf + 16);
    m->len = 48;
}

static uint8_t rpmc_status(QTestState *qts)
{
    const uint8_t cmd[] = { OP_RPMC_OP2, 0 };
    uint8_t status;

    spi_cmd(qts, cmd, sizeof(cmd), &status, 1);
    return status;
}

static void rpmc_read_data(QTestState *qts, uint8_t *resp)
{
    const uint8_t cmd[] = { OP_RPMC_OP2, 0 };

    spi_cmd(qts, cmd, sizeof(cmd), resp, RPMC_RESP_LEN);
}

static uint8_t send_op1(QTestState *qts, const RPMCMsg *m)
{
    spi_cmd(qts, m->buf, m->len, NULL, 0);
    return rpmc_status(qts);
}

/* High level helpers, asserting success */

static void provision(QTestState *qts, uint8_t counter)
{
    uint8_t root_key[RPMC_KEY_LEN];
    RPMCMsg m;

    root_key_for(counter, root_key);
    build_write_root_key(&m, counter, root_key);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_SUCCESS);
}

static void update_hmac_key(QTestState *qts, uint8_t counter, uint8_t *hmac_key)
{
    uint8_t root_key[RPMC_KEY_LEN];
    RPMCMsg m;

    root_key_for(counter, root_key);
    build_update_hmac_key(&m, counter, root_key, key_data);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_SUCCESS);
    derive_hmac_key(root_key, key_data, hmac_key);
}

/* Returns the counter value after authenticating the device response */
static uint32_t request_counter(QTestState *qts, uint8_t counter,
                                const uint8_t *hmac_key)
{
    const uint8_t tag[RPMC_TAG_LEN] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab ^ counter,
    };
    uint8_t resp[RPMC_RESP_LEN];
    uint8_t sig[RPMC_SIG_LEN];
    RPMCMsg m;

    build_request(&m, counter, hmac_key, tag);
    spi_cmd(qts, m.buf, m.len, NULL, 0);
    rpmc_read_data(qts, resp);

    g_assert_cmphex(resp[0], ==, ES_SUCCESS);
    g_assert(memcmp(resp + 1, tag, RPMC_TAG_LEN) == 0);
    hmac_sha256(hmac_key, RPMC_KEY_LEN, resp + 1, RPMC_TAG_LEN + 4, sig);
    g_assert(memcmp(resp + 17, sig, RPMC_SIG_LEN) == 0);

    return ldl_be_p(resp + 13);
}

static void increment(QTestState *qts, uint8_t counter,
                      const uint8_t *hmac_key, uint32_t prev)
{
    RPMCMsg m;

    build_increment(&m, counter, hmac_key, prev);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_SUCCESS);
}

/* Machine setup */

static QTestState *rpmc_start(const char *nv_path)
{
    QTestState *qts;

    if (nv_path) {
        qts = qtest_initf("-machine virt,spi=nonsecure "
                          "-drive if=mtd,index=1,format=raw,file=%s",
                          nv_path);
    } else {
        qts = qtest_init("-machine virt,spi=nonsecure");
    }
    bus_init(qts);

    return qts;
}

static char *nv_create(void)
{
    char *path;
    int fd;

    fd = g_file_open_tmp("qtest-rpmc-XXXXXX.bin", &path, NULL);
    g_assert(fd >= 0);
    g_assert(ftruncate(fd, NV_SIZE) == 0);
    close(fd);

    return path;
}

static void nv_remove(char *path)
{
    unlink(path);
    g_free(path);
}

/* Build an NV image the way the device model lays it out */
static void nv_write_image(const char *path, const uint32_t *values,
                           bool provisioned, bool bad_crc)
{
    uint8_t buf[NV_SIZE] = { 0 };
    uint8_t *p = buf + NV_HDR_LEN;
    size_t len = NV_HDR_LEN + RPMC_NUM_COUNTERS * NV_COUNTER_LEN;
    uint32_t crc;
    int i;

    stl_be_p(buf, 0x52504d43);
    stl_be_p(buf + 4, 1);
    stl_be_p(buf + 8, RPMC_NUM_COUNTERS);
    for (i = 0; i < RPMC_NUM_COUNTERS; i++) {
        stl_be_p(p, provisioned ? 1 : 0);
        stl_be_p(p + 4, values[i]);
        root_key_for(i, p + 8);
        p += NV_COUNTER_LEN;
    }
    crc = crc32c(0xffffffff, buf + NV_HDR_LEN, len - NV_HDR_LEN);
    stl_be_p(buf + 12, bad_crc ? ~crc : crc);
    g_assert(g_file_set_contents(path, (const char *)buf, sizeof(buf), NULL));
}

/*
 * Discovery: JEDEC ID and the SFDP RPMC parameter table must advertise the
 * opcodes and counter count the device implements.
 */
static void test_discovery(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t cmd[5] = { OP_JEDEC_READ };
    uint8_t buf[24];
    uint32_t ptr, dw1;

    spi_cmd(qts, cmd, 1, buf, 3);
    g_assert_cmphex(buf[0], ==, 0xef);
    g_assert_cmphex(buf[1], ==, 0x40);
    g_assert_cmphex(buf[2], ==, 0x19);

    /* SFDP header and second parameter header */
    cmd[0] = OP_RDSFDP;
    cmd[1] = cmd[2] = cmd[3] = cmd[4] = 0;
    spi_cmd(qts, cmd, 5, buf, 24);
    g_assert(memcmp(buf, "SFDP", 4) == 0);
    g_assert_cmpint(buf[6], ==, 1); /* NPH: two parameter headers */
    g_assert_cmphex(buf[8 + 8 + 0], ==, 0x03);  /* ID LSB */
    g_assert_cmphex(buf[8 + 8 + 7], ==, 0xff);  /* ID MSB */
    g_assert_cmpint(buf[8 + 8 + 2], ==, 1);     /* major */
    g_assert_cmpint(buf[8 + 8 + 1], ==, 0);     /* minor */
    g_assert_cmpint(buf[8 + 8 + 3], ==, 2);     /* length in DWORDs */
    ptr = buf[20] | (buf[21] << 8) | (buf[22] << 16);

    cmd[1] = ptr >> 16;
    cmd[2] = ptr >> 8;
    cmd[3] = ptr;
    spi_cmd(qts, cmd, 5, buf, 8);
    dw1 = ldl_le_p(buf);
    g_assert_cmpint(dw1 & BIT(0), ==, 0);           /* RPMC supported */
    g_assert_cmpint((dw1 >> 2) & 1, ==, 0);         /* poll OP2 status */
    g_assert_cmpint(((dw1 >> 4) & 0xf) + 1, ==, RPMC_NUM_COUNTERS);
    g_assert_cmphex((dw1 >> 8) & 0xff, ==, OP_RPMC_OP1);
    g_assert_cmphex((dw1 >> 16) & 0xff, ==, OP_RPMC_OP2);

    qtest_quit(qts);
}

/* The default machine and the secure variant must not expose the PL022 */
static void test_machine_property(void)
{
    QTestState *qts;

    qts = qtest_init("-machine virt");
    g_assert_cmphex(qtest_readl(qts, PL022_PERIPH_ID0), ==, 0);
    qtest_quit(qts);

    qts = qtest_init("-machine virt,secure=on,spi=secure");
    g_assert_cmphex(qtest_readl(qts, PL022_PERIPH_ID0), ==, 0);
    qtest_quit(qts);

    qts = qtest_init("-machine virt,spi=nonsecure");
    g_assert_cmphex(qtest_readl(qts, PL022_PERIPH_ID0), ==, 0x22);
    qtest_quit(qts);
}

static void test_power_on_status(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t resp[RPMC_RESP_LEN];
    uint8_t zero[RPMC_RESP_LEN] = { 0 };

    g_assert_cmphex(rpmc_status(qts), ==, ES_NONE);
    rpmc_read_data(qts, resp);
    g_assert(memcmp(resp, zero, sizeof(resp)) == 0);

    qtest_quit(qts);
}

static void test_write_root_key(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t root_key[RPMC_KEY_LEN];
    RPMCMsg m;

    provision(qts, 0);

    /* A provisioned root key can never be overwritten, not even with itself */
    root_key_for(0, root_key);
    build_write_root_key(&m, 0, root_key);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_ROOT_KEY);
    root_key_for(3, root_key);
    build_write_root_key(&m, 0, root_key);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_ROOT_KEY);

    /* Every counter has its own root key */
    provision(qts, 1);
    provision(qts, 2);
    provision(qts, 3);

    qtest_quit(qts);
}

static void test_write_root_key_bad_signature(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t root_key[RPMC_KEY_LEN];
    uint8_t other_key[RPMC_KEY_LEN];
    uint8_t sig[RPMC_SIG_LEN];
    RPMCMsg m;

    root_key_for(0, root_key);

    /* Truncated signature errors are reported in the root key bit */

    /* Corrupted truncated signature */
    build_write_root_key(&m, 0, root_key);
    m.buf[63] ^= 0x01;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_ROOT_KEY);

    /* First 28 bytes of the HMAC instead of the last 28 */
    build_write_root_key(&m, 0, root_key);
    hmac_sha256(root_key, RPMC_KEY_LEN, m.buf, RPMC_HDR_LEN, sig);
    memcpy(m.buf + 36, sig, RPMC_TRUNC_SIG_LEN);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_ROOT_KEY);

    /* Signature computed with a key other than the one being written */
    root_key_for(1, other_key);
    build_write_root_key(&m, 0, other_key);
    memcpy(m.buf + 4, root_key, RPMC_KEY_LEN);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_ROOT_KEY);

    /* Failed attempts must not have provisioned anything */
    provision(qts, 0);

    qtest_quit(qts);
}

/*
 * An all-ones root key is temporary: it initializes the counter but the root
 * key register stays writable, and the counter keeps its value when the real
 * root key is written later.
 */
static void test_temporary_root_key(void)
{
    char *nv = nv_create();
    uint8_t temp_key[RPMC_KEY_LEN];
    uint8_t hmac_key[RPMC_KEY_LEN];
    QTestState *qts;
    RPMCMsg m;

    memset(temp_key, 0xff, sizeof(temp_key));

    qts = rpmc_start(nv);
    build_write_root_key(&m, 0, temp_key);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_SUCCESS);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_SUCCESS);

    build_update_hmac_key(&m, 0, temp_key, key_data);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_SUCCESS);
    derive_hmac_key(temp_key, key_data, hmac_key);
    increment(qts, 0, hmac_key, 0);
    increment(qts, 0, hmac_key, 1);
    qtest_quit(qts);

    /* The temporary state survives a restart */
    qts = rpmc_start(nv);
    build_update_hmac_key(&m, 0, temp_key, key_data);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_SUCCESS);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 2);

    /* The real root key keeps the counter and drops the old HMAC key */
    provision(qts, 0);
    build_increment(&m, 0, hmac_key, 2);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_HMAC_KEY_UNINIT);
    update_hmac_key(qts, 0, hmac_key);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 2);

    /* Now locked, a further temporary key write is an overwrite */
    build_write_root_key(&m, 0, temp_key);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_ROOT_KEY);
    qtest_quit(qts);

    nv_remove(nv);
}

static void test_invalid_framing(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t root_key[RPMC_KEY_LEN];
    uint8_t hmac_key[RPMC_KEY_LEN];
    RPMCMsg m;
    int i;

    root_key_for(0, root_key);

    /* Counter address out of range */
    build_write_root_key(&m, RPMC_NUM_COUNTERS, root_key);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);
    build_write_root_key(&m, 0xff, root_key);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);

    /* Unknown command types */
    for (i = 0x04; i <= 0xff; i += 0x3b) {
        build_write_root_key(&m, 0, root_key);
        m.buf[1] = i;
        g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);
    }

    /* Truncated and oversized packets of a valid command */
    build_write_root_key(&m, 0, root_key);
    m.len--;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);
    build_write_root_key(&m, 0, root_key);
    m.len++;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);
    build_write_root_key(&m, 0, root_key);
    m.len += 8;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);

    /* Opcode only, and header only */
    m.len = 1;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);
    msg_header(&m, CMD_REQUEST, 0);
    m.len = RPMC_HDR_LEN;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);

    /* A Write Root Key sized Increment packet is rejected */
    provision(qts, 0);
    update_hmac_key(qts, 0, hmac_key);
    build_increment(&m, 0, hmac_key, 0);
    m.len = 64;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);

    /* None of the above changed any state */
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 0);
    provision(qts, 1);

    qtest_quit(qts);
}

static void test_update_hmac_key(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t root_key[RPMC_KEY_LEN];
    uint8_t wrong_key[RPMC_KEY_LEN];
    uint8_t hmac_key[RPMC_KEY_LEN];
    RPMCMsg m;

    root_key_for(0, root_key);

    /* No root key yet */
    build_update_hmac_key(&m, 0, root_key, key_data);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_ROOT_KEY);

    provision(qts, 0);

    /* Corrupted signature, corrupted key data, wrong root key */
    build_update_hmac_key(&m, 0, root_key, key_data);
    m.buf[8] ^= 0x80;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);
    build_update_hmac_key(&m, 0, root_key, key_data);
    m.buf[7] ^= 0x01;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);
    root_key_for(1, wrong_key);
    build_update_hmac_key(&m, 0, wrong_key, key_data);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);

    /* Failed updates left the HMAC key register uninitialized */
    build_increment(&m, 0, root_key, 0);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_HMAC_KEY_UNINIT);

    update_hmac_key(qts, 0, hmac_key);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 0);

    qtest_quit(qts);
}

static void test_increment(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t hmac_key[RPMC_KEY_LEN];
    RPMCMsg m, old;
    uint32_t i;

    provision(qts, 0);

    /* HMAC key register not initialized */
    build_increment(&m, 0, hmac_key, 0);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_HMAC_KEY_UNINIT);

    update_hmac_key(qts, 0, hmac_key);

    for (i = 0; i < 10; i++) {
        increment(qts, 0, hmac_key, i);
        g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, i + 1);
    }

    /* Bad signature: rejected, counter unchanged */
    build_increment(&m, 0, hmac_key, 10);
    m.buf[39] ^= 0x01;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 10);

    /* Wrong counter data, correctly signed */
    build_increment(&m, 0, hmac_key, 11);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_COUNTER_MISMATCH);
    build_increment(&m, 0, hmac_key, 9);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_COUNTER_MISMATCH);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 10);

    /* Replaying a previously accepted packet must fail */
    build_increment(&old, 0, hmac_key, 10);
    g_assert_cmphex(send_op1(qts, &old), ==, ES_SUCCESS);
    g_assert_cmphex(send_op1(qts, &old), ==, ES_COUNTER_MISMATCH);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 11);

    /* Signature is checked before the counter data, no oracle */
    build_increment(&m, 0, hmac_key, 5);
    m.buf[8] ^= 0x01;
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);

    qtest_quit(qts);
}

static void test_request(void)
{
    QTestState *qts = rpmc_start(NULL);
    const uint8_t tag[RPMC_TAG_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const uint8_t zero[RPMC_RESP_LEN] = { 0 };
    uint8_t hmac_key[RPMC_KEY_LEN];
    uint8_t resp[RPMC_RESP_LEN], again[RPMC_RESP_LEN];
    uint8_t cmd[] = { OP_RPMC_OP2, 0 };
    uint8_t padding[4];
    RPMCMsg m;

    provision(qts, 0);

    build_request(&m, 0, hmac_key, tag);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_HMAC_KEY_UNINIT);

    update_hmac_key(qts, 0, hmac_key);
    increment(qts, 0, hmac_key, 0);
    increment(qts, 0, hmac_key, 1);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 2);

    /* OP2 can be read repeatedly and returns 0xff past the response */
    rpmc_read_data(qts, resp);
    rpmc_read_data(qts, again);
    g_assert(memcmp(resp, again, sizeof(resp)) == 0);
    cs_assert(qts, true);
    spi_xfer(qts, cmd[0]);
    spi_xfer(qts, cmd[1]);
    for (size_t i = 0; i < RPMC_RESP_LEN; i++) {
        g_assert_cmphex(spi_xfer(qts, 0), ==, resp[i]);
    }
    for (size_t i = 0; i < sizeof(padding); i++) {
        g_assert_cmphex(spi_xfer(qts, 0), ==, 0xff);
    }
    cs_assert(qts, false);

    /* Bad request signature: error status and no payload */
    build_request(&m, 0, hmac_key, tag);
    m.buf[16] ^= 0x01;
    spi_cmd(qts, m.buf, m.len, NULL, 0);
    rpmc_read_data(qts, resp);
    g_assert_cmphex(resp[0], ==, ES_PAYLOAD);
    g_assert(memcmp(resp + 1, zero, RPMC_RESP_LEN - 1) == 0);

    /* Any later OP1 invalidates a staged response */
    request_counter(qts, 0, hmac_key);
    provision(qts, 1);
    rpmc_read_data(qts, resp);
    g_assert_cmphex(resp[0], ==, ES_SUCCESS);
    g_assert(memcmp(resp + 1, zero, RPMC_RESP_LEN - 1) == 0);

    qtest_quit(qts);
}

static void test_counter_isolation(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t hmac_key[RPMC_NUM_COUNTERS][RPMC_KEY_LEN];
    RPMCMsg m;
    int i;

    for (i = 0; i < RPMC_NUM_COUNTERS; i++) {
        provision(qts, i);
        update_hmac_key(qts, i, hmac_key[i]);
    }

    increment(qts, 2, hmac_key[2], 0);
    increment(qts, 2, hmac_key[2], 1);
    increment(qts, 3, hmac_key[3], 0);

    g_assert_cmpuint(request_counter(qts, 0, hmac_key[0]), ==, 0);
    g_assert_cmpuint(request_counter(qts, 1, hmac_key[1]), ==, 0);
    g_assert_cmpuint(request_counter(qts, 2, hmac_key[2]), ==, 2);
    g_assert_cmpuint(request_counter(qts, 3, hmac_key[3]), ==, 1);

    /* A key of one counter does not authenticate another */
    build_increment(&m, 1, hmac_key[0], 0);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);
    g_assert_cmpuint(request_counter(qts, 1, hmac_key[1]), ==, 0);

    qtest_quit(qts);
}

static void test_hmac_key_rotation(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t root_key[RPMC_KEY_LEN];
    uint8_t old_key[RPMC_KEY_LEN], new_key[RPMC_KEY_LEN];
    RPMCMsg m;

    root_key_for(0, root_key);
    provision(qts, 0);
    update_hmac_key(qts, 0, old_key);
    increment(qts, 0, old_key, 0);

    build_update_hmac_key(&m, 0, root_key, 0xcafef00d);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_SUCCESS);
    derive_hmac_key(root_key, 0xcafef00d, new_key);

    build_increment(&m, 0, old_key, 1);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_PAYLOAD);
    increment(qts, 0, new_key, 1);
    g_assert_cmpuint(request_counter(qts, 0, new_key), ==, 2);

    qtest_quit(qts);
}

/*
 * A system reset is a power cycle for the flash: the HMAC key register is
 * lost, root keys and counters are kept.
 */
static void test_reset(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t hmac_key[RPMC_KEY_LEN];
    uint8_t root_key[RPMC_KEY_LEN];
    RPMCMsg m;

    provision(qts, 0);
    update_hmac_key(qts, 0, hmac_key);
    increment(qts, 0, hmac_key, 0);
    increment(qts, 0, hmac_key, 1);

    qtest_system_reset(qts);
    bus_init(qts);

    g_assert_cmphex(rpmc_status(qts), ==, ES_NONE);
    build_increment(&m, 0, hmac_key, 2);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_HMAC_KEY_UNINIT);

    root_key_for(0, root_key);
    build_write_root_key(&m, 0, root_key);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_ROOT_KEY);

    update_hmac_key(qts, 0, hmac_key);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 2);

    qtest_quit(qts);
}

/* Root keys and counters survive a restart of QEMU through rpmc-drive */
static void test_persistence(void)
{
    char *nv = nv_create();
    uint8_t hmac_key[RPMC_KEY_LEN];
    g_autofree gchar *contents = NULL;
    gsize len;
    QTestState *qts;
    RPMCMsg m;
    int i;

    qts = rpmc_start(nv);
    provision(qts, 0);
    provision(qts, 2);
    update_hmac_key(qts, 0, hmac_key);
    for (i = 0; i < 7; i++) {
        increment(qts, 0, hmac_key, i);
    }
    qtest_quit(qts);

    /* Check the on-disk layout */
    g_assert(g_file_get_contents(nv, &contents, &len, NULL));
    g_assert_cmpuint(len, ==, NV_SIZE);
    g_assert_cmphex(ldl_be_p(contents), ==, 0x52504d43);
    g_assert_cmpuint(ldl_be_p(contents + 4), ==, 1);
    g_assert_cmpuint(ldl_be_p(contents + 8), ==, RPMC_NUM_COUNTERS);
    g_assert_cmphex(ldl_be_p(contents + 12), ==,
                    crc32c(0xffffffff, (uint8_t *)contents + NV_HDR_LEN,
                           RPMC_NUM_COUNTERS * NV_COUNTER_LEN));
    g_assert_cmpuint(ldl_be_p(contents + NV_HDR_LEN + 4), ==, 7);

    qts = rpmc_start(nv);
    update_hmac_key(qts, 0, hmac_key);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 7);
    increment(qts, 0, hmac_key, 7);
    provision(qts, 1);
    root_key_for(2, hmac_key);
    build_write_root_key(&m, 2, hmac_key);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_ROOT_KEY);
    qtest_quit(qts);

    qts = rpmc_start(nv);
    update_hmac_key(qts, 0, hmac_key);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 8);
    root_key_for(1, hmac_key);
    build_write_root_key(&m, 1, hmac_key);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_ROOT_KEY);
    qtest_quit(qts);

    nv_remove(nv);
}

/* An exhausted counter refuses to wrap around */
static void test_counter_overflow(void)
{
    const uint32_t values[RPMC_NUM_COUNTERS] = {
        UINT32_MAX - 1, UINT32_MAX, 0, 0,
    };
    char *nv = nv_create();
    uint8_t hmac_key[RPMC_KEY_LEN];
    QTestState *qts;
    RPMCMsg m;

    nv_write_image(nv, values, true, false);
    qts = rpmc_start(nv);

    update_hmac_key(qts, 0, hmac_key);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, UINT32_MAX - 1);
    increment(qts, 0, hmac_key, UINT32_MAX - 1);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, UINT32_MAX);
    build_increment(&m, 0, hmac_key, UINT32_MAX);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_FATAL);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, UINT32_MAX);

    update_hmac_key(qts, 1, hmac_key);
    build_increment(&m, 1, hmac_key, UINT32_MAX);
    g_assert_cmphex(send_op1(qts, &m), ==, ES_FATAL);

    qtest_quit(qts);
    nv_remove(nv);
}

/* Bad backing stores must stop QEMU from starting rather than reset state */
static void expect_startup_failure(const char *nv, const char *msg)
{
    const char *qemu = g_getenv("QTEST_QEMU_BINARY");
    g_autofree char *drive = g_strdup_printf("if=mtd,index=1,format=raw,"
                                             "file=%s", nv);
    g_autofree char *err = NULL;
    int status;
    char *argv[] = {
        (char *)qemu, (char *)"-machine", (char *)"virt,spi=nonsecure",
        (char *)"-drive", drive, (char *)"-display", (char *)"none",
        (char *)"-accel", (char *)"qtest", (char *)"-S", NULL,
    };

    g_assert(qemu);
    g_assert(g_spawn_sync(NULL, argv, NULL, G_SPAWN_STDOUT_TO_DEV_NULL,
                          NULL, NULL, NULL, &err, &status, NULL));
    g_assert(!WIFEXITED(status) || WEXITSTATUS(status) != 0);
    g_assert_nonnull(strstr(err, msg));
}

static void test_bad_backing_store(void)
{
    const uint32_t values[RPMC_NUM_COUNTERS] = { 1, 2, 3, 4 };
    char *nv = nv_create();
    uint8_t junk[NV_SIZE];

    nv_write_image(nv, values, true, true);
    expect_startup_failure(nv, "CRC mismatch");

    memset(junk, 0x5a, sizeof(junk));
    g_assert(g_file_set_contents(nv, (const char *)junk, sizeof(junk), NULL));
    expect_startup_failure(nv, "does not contain RPMC state");

    g_assert(g_file_set_contents(nv, (const char *)junk, 512, NULL));
    expect_startup_failure(nv, "must be at least");

    nv_remove(nv);
}

/* Regular flash operation keeps working next to RPMC */
static void test_flash_data_path(void)
{
    QTestState *qts = rpmc_start(NULL);
    uint8_t hmac_key[RPMC_KEY_LEN];
    uint8_t cmd[8] = { OP_WREN };
    uint8_t buf[4];

    provision(qts, 0);
    update_hmac_key(qts, 0, hmac_key);

    spi_cmd(qts, cmd, 1, NULL, 0);
    cmd[0] = OP_PP;
    cmd[1] = 0x00;
    cmd[2] = 0x10;
    cmd[3] = 0x00;
    cmd[4] = 0xde;
    cmd[5] = 0xad;
    cmd[6] = 0xbe;
    cmd[7] = 0xef;
    spi_cmd(qts, cmd, 8, NULL, 0);

    increment(qts, 0, hmac_key, 0);

    cmd[0] = OP_READ;
    spi_cmd(qts, cmd, 4, buf, 4);
    g_assert_cmphex((uint32_t)ldl_be_p(buf), ==, 0xdeadbeef);
    g_assert_cmpuint(request_counter(qts, 0, hmac_key), ==, 1);

    qtest_quit(qts);
}

/* RFC 4231 test case 2, guards the host side HMAC helper itself */
static void test_host_hmac(void)
{
    const uint8_t expected[RPMC_SIG_LEN] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    const char *data = "what do ya want for nothing?";
    uint8_t out[RPMC_SIG_LEN];

    hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)data,
                strlen(data), out);
    g_assert(memcmp(out, expected, sizeof(out)) == 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_assert(qcrypto_init(NULL) == 0);

    qtest_add_func("/m25p80/rpmc/host_hmac", test_host_hmac);
    qtest_add_func("/m25p80/rpmc/machine_property", test_machine_property);
    qtest_add_func("/m25p80/rpmc/discovery", test_discovery);
    qtest_add_func("/m25p80/rpmc/power_on_status", test_power_on_status);
    qtest_add_func("/m25p80/rpmc/write_root_key", test_write_root_key);
    qtest_add_func("/m25p80/rpmc/write_root_key_bad_signature",
                   test_write_root_key_bad_signature);
    qtest_add_func("/m25p80/rpmc/temporary_root_key", test_temporary_root_key);
    qtest_add_func("/m25p80/rpmc/invalid_framing", test_invalid_framing);
    qtest_add_func("/m25p80/rpmc/update_hmac_key", test_update_hmac_key);
    qtest_add_func("/m25p80/rpmc/increment", test_increment);
    qtest_add_func("/m25p80/rpmc/request", test_request);
    qtest_add_func("/m25p80/rpmc/counter_isolation", test_counter_isolation);
    qtest_add_func("/m25p80/rpmc/hmac_key_rotation", test_hmac_key_rotation);
    qtest_add_func("/m25p80/rpmc/reset", test_reset);
    qtest_add_func("/m25p80/rpmc/persistence", test_persistence);
    qtest_add_func("/m25p80/rpmc/counter_overflow", test_counter_overflow);
    qtest_add_func("/m25p80/rpmc/bad_backing_store", test_bad_backing_store);
    qtest_add_func("/m25p80/rpmc/flash_data_path", test_flash_data_path);

    return g_test_run();
}
