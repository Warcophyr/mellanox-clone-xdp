/*
 * mlx5dv_mac_drop.c  --  versione a DUE LIVELLI
 *
 * Struttura dell'albero di steering (dominio NIC_RX):
 *
 *   ROOT table (level 0)
 *     matcher (mask vuota, matcha tutto)
 *       rule  --action--> dest_table ---> TABLE level 1
 *
 *   TABLE level 1
 *     matcher (mask = dst MAC)
 *       rule (value = dst MAC) --action--> DROP
 *
 * Motivazione (man mlx5dv_dr): "All packets start traversing the steering
 * domain tree at table level zero (0)". Una regola di drop messa
 * direttamente sulla root non intercetta il traffico di produzione; va
 * creata una table di livello > 0 e raggiunta dalla root via dest_table.
 *
 * NB: il dominio NIC_RX ha "Default behavior: Drop packet". Per evitare di
 *     droppare TUTTO cio' che non matcha, la table level 1 ha anche una
 *     regola di "default miss" che rimanda al comportamento di default.
 *     (Per questo semplice test di drop selettivo lo lasciamo esplicito.)
 *
 * Compilazione:
 *   gcc -Wall mlx5dv_mac_drop.c -o mlx5dv_mac_drop -libverbs -lmlx5
 * Uso:
 *   sudo ./mlx5dv_mac_drop <device_rdma> <dst_mac>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>

#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

#define FTE_MATCH_PARAM_SZ 256
#define OFF_DMAC_47_16     0x08
#define OFF_DMAC_15_0      0x0C
#define MATCH_CRITERIA_OUTER (1u << 0)

static int parse_mac(const char *s, uint8_t mac[6])
{
    int v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) {
        if (v[i] < 0 || v[i] > 0xff) return -1;
        mac[i] = (uint8_t)v[i];
    }
    return 0;
}

static void set_dmac(uint8_t *buf, const uint8_t mac[6])
{
    buf[OFF_DMAC_47_16 + 0] = mac[0];
    buf[OFF_DMAC_47_16 + 1] = mac[1];
    buf[OFF_DMAC_47_16 + 2] = mac[2];
    buf[OFF_DMAC_47_16 + 3] = mac[3];
    buf[OFF_DMAC_15_0 + 0]  = mac[4];
    buf[OFF_DMAC_15_0 + 1]  = mac[5];
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
    for (i = 0; i < num; i++)
        if (strcmp(ibv_get_device_name(dev_list[i]), name) == 0) {
            dev = dev_list[i]; break;
        }
    if (!dev) {
        fprintf(stderr, "Device '%s' non trovato. Disponibili:\n", name);
        for (i = 0; i < num; i++)
            fprintf(stderr, "  %s\n", ibv_get_device_name(dev_list[i]));
        ibv_free_device_list(dev_list);
        return NULL;
    }
    if (!mlx5dv_is_supported(dev)) {
        fprintf(stderr, "Il device %s non supporta mlx5dv\n", name);
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

static struct mlx5dv_flow_match_parameters *
make_match_params(const uint8_t *buf, size_t buf_sz)
{
    size_t aligned_sz = (buf_sz + 7) & ~((size_t)7);
    size_t n_u64 = aligned_sz / sizeof(uint64_t);
    size_t total = sizeof(struct mlx5dv_flow_match_parameters)
                   + n_u64 * sizeof(uint64_t);
    struct mlx5dv_flow_match_parameters *mp = calloc(1, total);
    if (!mp) return NULL;
    mp->match_sz = aligned_sz;
    memcpy(mp->match_buf, buf, buf_sz);
    return mp;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Uso: %s <device_rdma> <dst_mac>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *dev_name = argv[1];
    uint8_t mac[6];
    if (parse_mac(argv[2], mac) != 0) {
        fprintf(stderr, "MAC non valido: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    struct ibv_context *ctx = NULL;
    struct ibv_pd *pd = NULL;
    int ret = EXIT_FAILURE;

    struct mlx5dv_dr_domain  *domain   = NULL;
    struct mlx5dv_dr_table   *t_root   = NULL;  /* level 0 */
    struct mlx5dv_dr_table   *t_lvl1   = NULL;  /* level 1 */
    struct mlx5dv_dr_matcher *m_root   = NULL;
    struct mlx5dv_dr_matcher *m_lvl1   = NULL;
    struct mlx5dv_dr_rule    *r_root   = NULL;
    struct mlx5dv_dr_rule    *r_lvl1   = NULL;
    struct mlx5dv_dr_action  *a_drop   = NULL;
    struct mlx5dv_dr_action  *a_goto   = NULL;
    struct mlx5dv_flow_match_parameters *mask_mac = NULL, *val_mac = NULL;
    struct mlx5dv_flow_match_parameters *mask_any = NULL, *val_any = NULL;

    ctx = open_device(dev_name);
    if (!ctx) return EXIT_FAILURE;

    pd = ibv_alloc_pd(ctx);
    if (!pd) { fprintf(stderr, "ibv_alloc_pd fallita\n"); goto cleanup; }

    domain = mlx5dv_dr_domain_create(ctx, MLX5DV_DR_DOMAIN_TYPE_NIC_RX);
    if (!domain) {
        fprintf(stderr, "dr_domain_create fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    /* --- TABLE level 1: regola di DROP sul dst MAC --- */
    t_lvl1 = mlx5dv_dr_table_create(domain, 1);
    if (!t_lvl1) {
        fprintf(stderr, "table_create(level=1) fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    uint8_t mask_buf[FTE_MATCH_PARAM_SZ] = {0};
    uint8_t val_buf[FTE_MATCH_PARAM_SZ]  = {0};
    uint8_t mac_ff[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    set_dmac(mask_buf, mac_ff);
    set_dmac(val_buf,  mac);

    mask_mac = make_match_params(mask_buf, sizeof(mask_buf));
    val_mac  = make_match_params(val_buf,  sizeof(val_buf));
    if (!mask_mac || !val_mac) { fprintf(stderr,"alloc fallita\n"); goto cleanup; }

    m_lvl1 = mlx5dv_dr_matcher_create(t_lvl1, 0, MATCH_CRITERIA_OUTER, mask_mac);
    if (!m_lvl1) {
        fprintf(stderr, "matcher(level1) fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    a_drop = mlx5dv_dr_action_create_drop();
    if (!a_drop) {
        fprintf(stderr, "action_create_drop fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    struct mlx5dv_dr_action *act_drop[] = { a_drop };
    r_lvl1 = mlx5dv_dr_rule_create(m_lvl1, val_mac, 1, act_drop);
    if (!r_lvl1) {
        fprintf(stderr, "rule(level1, drop) fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    /* --- ROOT table (level 0): catch-all --> dest_table(level1) --- */
    t_root = mlx5dv_dr_table_create(domain, 0);
    if (!t_root) {
        fprintf(stderr, "table_create(level=0) fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    /* azione: inoltra alla table di livello 1 */
    a_goto = mlx5dv_dr_action_create_dest_table(t_lvl1);
    if (!a_goto) {
        fprintf(stderr, "action_create_dest_table fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    /* matcher con mask VUOTA (criterion_enable=0): matcha tutto */
    uint8_t empty[FTE_MATCH_PARAM_SZ] = {0};
    mask_any = make_match_params(empty, sizeof(empty));
    val_any  = make_match_params(empty, sizeof(empty));
    if (!mask_any || !val_any) { fprintf(stderr,"alloc any fallita\n"); goto cleanup; }

    m_root = mlx5dv_dr_matcher_create(t_root, 0, 0 /* no criteria = match all */,
                                      mask_any);
    if (!m_root) {
        fprintf(stderr, "matcher(root) fallita: %s\n", strerror(errno));
        goto cleanup;
    }

    struct mlx5dv_dr_action *act_goto[] = { a_goto };
    r_root = mlx5dv_dr_rule_create(m_root, val_any, 1, act_goto);
    if (!r_root) {
        fprintf(stderr, "rule(root, dest_table) fallita: %s\n", strerror(errno));
        fprintf(stderr, "  -> se errno=EINVAL, l'azione dest_table sulla root\n");
        fprintf(stderr, "     potrebbe richiedere il flag ROOT_LEVEL: vedi note.\n");
        goto cleanup;
    }

    /* commit verso l'hardware */
    if (mlx5dv_dr_domain_sync(domain,
            MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW |
            MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW))
        fprintf(stderr, "ATTENZIONE: domain_sync fallita: %s\n", strerror(errno));

    printf("Albero installato:\n");
    printf("  ROOT(L0) catch-all -> dest_table -> L1\n");
    printf("  L1: dst_mac %02x:%02x:%02x:%02x:%02x:%02x -> DROP\n",
           mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    printf("Invia traffico verso quel MAC e verifica con ethtool -S.\n");
    printf("Premi INVIO per uscire...\n");
    getchar();
    ret = EXIT_SUCCESS;

cleanup:
    if (r_root)  mlx5dv_dr_rule_destroy(r_root);
    if (r_lvl1)  mlx5dv_dr_rule_destroy(r_lvl1);
    if (a_goto)  mlx5dv_dr_action_destroy(a_goto);
    if (a_drop)  mlx5dv_dr_action_destroy(a_drop);
    if (m_root)  mlx5dv_dr_matcher_destroy(m_root);
    if (m_lvl1)  mlx5dv_dr_matcher_destroy(m_lvl1);
    if (t_root)  mlx5dv_dr_table_destroy(t_root);
    if (t_lvl1)  mlx5dv_dr_table_destroy(t_lvl1);
    if (domain)  mlx5dv_dr_domain_destroy(domain);
    if (pd)      ibv_dealloc_pd(pd);
    if (ctx)     ibv_close_device(ctx);
    free(mask_mac); free(val_mac); free(mask_any); free(val_any);
    return ret;
}