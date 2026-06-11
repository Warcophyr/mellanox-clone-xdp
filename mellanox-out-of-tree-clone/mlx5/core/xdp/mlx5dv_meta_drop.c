/*
 * mlx5dv_meta_drop.c
 *
 * Esempio: creazione di una flow rule tramite mlx5 Direct Verbs (mlx5dv DR)
 * che matcha sul metadata della pipeline (reg_c0 / packet metadata = 10)
 * ed esegue un'azione di DROP sul percorso di TRASMISSIONE (NIC_TX).
 *
 * Questa versione NON usa le macro DEVX_SET / DEVX_ST_SZ_BYTES ne' le
 * struct mlx5_ifc_*: quelle definizioni vivono in header PRM interni di
 * rdma-core che non vengono installati pubblicamente. Costruiamo invece
 * il match buffer (fte_match_param) a mano, scrivendo il campo
 * metadata_reg_c_0 al suo offset noto.
 *
 * Compilazione:
 *   gcc -Wall mlx5dv_meta_drop.c -o mlx5dv_meta_drop -libverbs -lmlx5
 *
 * Esecuzione (richiede privilegi e device mlx5):
 *   sudo ./mlx5dv_meta_drop [device_rdma]
 *   es. sudo ./mlx5dv_meta_drop rocep129s0f1
 *
 * Mappatura netdev -> device RDMA:
 *   ls -l /sys/class/net/enp7s0np0/device/infiniband/
 *
 * PCI=0000:81:00.0
 * sudo apt install linux-modules-extra-$(uname -r)
 * sudo devlink dev param set pci/$PCI name flow_steering_mode value dmfs cmode runtime
 * sudo devlink dev eswitch set pci/0000:81:00.0 mode legacy
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <arpa/inet.h>

#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

/* Valore di metadata da matchare e maschera piena a 32 bit */
#define META_MATCH_VALUE 0x0000002a
#define META_MASK        0xfffffffu
/*
 * fte_match_param (PRM) ha dimensione fissa: 0x40 DWORD = 256 byte.
 * E' composto da blocchi consecutivi da 0x40 byte (16 DWORD) ciascuno:
 *
 *   offset 0x000  outer_headers
 *   offset 0x040  misc_parameters
 *   offset 0x080  inner_headers
 *   offset 0x0C0  misc_parameters_2
 *   offset 0x100  misc_parameters_3
 *   offset 0x140  misc_parameters_4
 *   offset 0x180  misc_parameters_5
 *
 * In misc_parameters_2 il primo DWORD e' metadata_reg_c_0.
 * Quindi metadata_reg_c_0 si trova a offset 0xC0 dall'inizio del buffer.
 *
 * Usiamo 256 byte per coprire l'intero fte_match_param.
 */
#define FTE_MATCH_PARAM_SZ        256
#define OFF_MISC2_METADATA_REG_C0 0xC0  /* byte offset del DWORD reg_c0 */

/* Bit di criterion_enable: outer(0), misc(1), inner(2), misc2(3), ... */
#define MATCH_CRITERIA_MISC2 (1u << 3)

/* Scrive un valore big-endian a 32 bit nel match buffer all'offset dato */
static void set_reg32_be(uint8_t *buf, size_t off, uint32_t val)
{
    uint32_t be = htonl(val);
    memcpy(buf + off, &be, sizeof(be));
}

static struct ibv_context *open_device(const char *name)
{
    struct ibv_device **dev_list;
    struct ibv_device *dev = NULL;
    struct ibv_context *ctx = NULL;
    int num, i;

    dev_list = ibv_get_device_list(&num);
    if (!dev_list || num == 0) {
        fprintf(stderr, "Nessun device RDMA trovato\n");
        return NULL;
    }

    if (name) {
        for (i = 0; i < num; i++) {
            if (strcmp(ibv_get_device_name(dev_list[i]), name) == 0) {
                dev = dev_list[i];
                break;
            }
        }
        if (!dev) {
            fprintf(stderr, "Device '%s' non trovato. Disponibili:\n", name);
            for (i = 0; i < num; i++)
                fprintf(stderr, "  %s\n", ibv_get_device_name(dev_list[i]));
            ibv_free_device_list(dev_list);
            return NULL;
        }
    } else {
        dev = dev_list[0];
        fprintf(stderr, "Uso device di default: %s\n",
                ibv_get_device_name(dev));
    }

    if (!mlx5dv_is_supported(dev)) {
        fprintf(stderr, "Il device %s non supporta mlx5dv\n",
                ibv_get_device_name(dev));
        ibv_free_device_list(dev_list);
        return NULL;
    }

    struct mlx5dv_context_attr dv_attr = {0};
    ctx = mlx5dv_open_device(dev, &dv_attr);
    if (!ctx)
        fprintf(stderr, "mlx5dv_open_device fallita: %s\n", strerror(errno));

    ibv_free_device_list(dev_list);
    return ctx;
}

/* Alloca una mlx5dv_flow_match_parameters contenente il buffer dato */
static struct mlx5dv_flow_match_parameters *
make_match_params(const uint8_t *buf, size_t buf_sz)
{
    size_t total = offsetof(struct mlx5dv_flow_match_parameters, match_buf)
                   + buf_sz;
    struct mlx5dv_flow_match_parameters *mp = calloc(1, total);
    if (!mp)
        return NULL;
    mp->match_sz = buf_sz;
    memcpy(mp->match_buf, buf, buf_sz);
    return mp;
}

int main(int argc, char **argv)
{
    const char *dev_name = (argc > 1) ? argv[1] : NULL;
    struct ibv_context *ctx = NULL;
    struct ibv_pd *pd = NULL;
    int ret = EXIT_FAILURE;

    struct mlx5dv_dr_domain  *domain  = NULL;
    struct mlx5dv_dr_table   *table   = NULL;
    struct mlx5dv_dr_matcher *matcher = NULL;
    struct mlx5dv_dr_rule    *rule    = NULL;
    struct mlx5dv_dr_action  *action_drop = NULL;
    struct mlx5dv_flow_match_parameters *match_mask = NULL;
    struct mlx5dv_flow_match_parameters *match_value = NULL;

    ctx = open_device(dev_name);
    if (!ctx)
        return EXIT_FAILURE;

    pd = ibv_alloc_pd(ctx);
    if (!pd) {
        fprintf(stderr, "ibv_alloc_pd fallita\n");
        goto cleanup;
    }

    /*
     * 1) Dominio di steering.
     *    NIC_TX -> trasmissione (egress), e' quello che vogliamo per droppare
     *    il pacchetto in uscita. (NIC_RX per ingress, FDB per eswitch.)
     */
    domain = mlx5dv_dr_domain_create(ctx, MLX5DV_DR_DOMAIN_TYPE_NIC_TX);
    if (!domain) {
        fprintf(stderr, "dr_domain_create fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    /* 2) Flow table al livello 0 */
    table = mlx5dv_dr_table_create(domain, 0 /* level */);
    if (!table) {
        fprintf(stderr, "dr_table_create fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    /* 3) Costruisci maschera e valore a mano nel fte_match_param */
    uint8_t mask[FTE_MATCH_PARAM_SZ]  = {0};
    uint8_t value[FTE_MATCH_PARAM_SZ] = {0};

    set_reg32_be(mask,  OFF_MISC2_METADATA_REG_C0, META_MASK);
    set_reg32_be(value, OFF_MISC2_METADATA_REG_C0, META_MATCH_VALUE);

    match_mask = make_match_params(mask, sizeof(mask));
    if (!match_mask) {
        fprintf(stderr, "alloc match_mask fallita\n");
        goto cleanup;
    }

    /* 4) Matcher: criterion_enable abilita misc_parameters_2 */
    matcher = mlx5dv_dr_matcher_create(table,
                                       0 /* priority */,
                                       MATCH_CRITERIA_MISC2,
                                       match_mask);
    if (!matcher) {
        fprintf(stderr, "dr_matcher_create fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    /* 5) Azione DROP */
    action_drop = mlx5dv_dr_action_create_drop();
    if (!action_drop) {
        fprintf(stderr, "dr_action_create_drop fallita: %s\n",
                strerror(errno));
        goto cleanup;
    }

    /* 6) Rule: match value -> [drop] */
    match_value = make_match_params(value, sizeof(value));
    if (!match_value) {
        fprintf(stderr, "alloc match_value fallita\n");
        goto cleanup;
    }

    struct mlx5dv_dr_action *actions[] = { action_drop };

    rule = mlx5dv_dr_rule_create(matcher,
                                 match_value,
                                 1 /* num actions */,
                                 actions);
    if (!rule) {
        fprintf(stderr, "dr_rule_create fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Regola installata: NIC_TX, metadata (reg_c0) == %u -> DROP\n",
           META_MATCH_VALUE);
    printf("Premi INVIO per rimuovere la regola e uscire...\n");
    getchar();

    ret = EXIT_SUCCESS;

cleanup:
    if (rule)        mlx5dv_dr_rule_destroy(rule);
    if (action_drop) mlx5dv_dr_action_destroy(action_drop);
    if (matcher)     mlx5dv_dr_matcher_destroy(matcher);
    if (table)       mlx5dv_dr_table_destroy(table);
    if (domain)      mlx5dv_dr_domain_destroy(domain);
    if (pd)          ibv_dealloc_pd(pd);
    if (ctx)         ibv_close_device(ctx);
    free(match_mask);
    free(match_value);

    return ret;
}