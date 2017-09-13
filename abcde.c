#include <net/netfilter/nf_tables.h>
#include <net/tcp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "abcde.h"

#define ABCDE_TEXT_SIZE 128
struct nft_abcde {
	char text[ABCDE_TEXT_SIZE];
	int len;
};

static inline bool modify_packet(struct nft_abcde *priv, struct sk_buff *skb) {
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
	char *user_data = (char *)((char *)tcph + (tcph->doff * 4));
	char *tail = skb_tail_pointer(skb);
	int tcplen = (skb->len - (iph->ihl << 2));

	if (!skb_make_writable(skb, skb->len))
		return false;

    printk(KERN_ERR "%s\n", user_data);
	printk(KERN_ERR "%s\n", priv->text);

	for (; user_data < tail - priv->len; user_data++) {
		bool match = 1;
		int i;
		for (i = 0; i < priv->len; i++)
			if (user_data[i] != priv->text[i]) {
				match = 0;
				break;
			}
		if (match)
			for (i = 0; i < priv->len; i++)
				user_data[i] = 'x';
	}

	tcph->check = 0;
	tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial((char *)tcph, tcplen, 0));
	if (skb_checksum_complete(skb)) {
		printk(KERN_ERR "abcde: wrong checksum");
		return false;
	}
	return true;
}

static const struct nla_policy nft_abcde_policy[NFTA_ABCDE_MAX + 1] = {
	[NFTA_ABCDE_TEXT]		= { .type = NLA_STRING, .len = ABCDE_TEXT_SIZE },
};

static void nft_abcde_eval(const struct nft_expr *expr, struct nft_regs *regs, const struct nft_pktinfo *pkt) {
	struct nft_abcde *priv = nft_expr_priv(expr);
	struct sk_buff *skb = pkt->skb;
	if(!modify_packet(priv, skb))
		regs->verdict.code = NFT_BREAK;
}

static int nft_abcde_init(const struct nft_ctx *ctx, const struct nft_expr *expr, const struct nlattr * const tb[]) {
	struct nft_abcde *priv = nft_expr_priv(expr);
	if (tb[NFTA_ABCDE_TEXT] == NULL)
		return -EINVAL;
	nla_strlcpy(priv->text, tb[NFTA_ABCDE_TEXT], ABCDE_TEXT_SIZE);
	priv->len = strlen(priv->text);
	return 0;
}

static int nft_abcde_dump(struct sk_buff *skb, const struct nft_expr *expr) {
	const struct nft_abcde *priv = nft_expr_priv(expr);
	if (nla_put_string(skb, NFTA_ABCDE_TEXT, priv->text))
		return -1;
	return 0;
}

static struct nft_expr_type nft_abcde_type;
static const struct nft_expr_ops nft_abcde_op = {
	.eval = nft_abcde_eval,
	.size = sizeof(struct nft_abcde),
	.init = nft_abcde_init,
	.dump = nft_abcde_dump,
	.type = &nft_abcde_type,
};
static struct nft_expr_type nft_abcde_type __read_mostly =  {
	.ops = &nft_abcde_op,
	.name = "abcde",
	.owner = THIS_MODULE,
	.policy = nft_abcde_policy,
	.maxattr = NFTA_ABCDE_MAX,
};

static int __init nft_abcde_module_init(void) {
	return nft_register_expr(&nft_abcde_type);
}
static void __exit nft_abcde_module_exit(void) {
	nft_unregister_expr(&nft_abcde_type);
}

module_init(nft_abcde_module_init);
module_exit(nft_abcde_module_exit);

MODULE_AUTHOR("Xiang Gao");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A sample nftables expression.");
