#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/mpls.h>
#include "internal.h"

static LIST_HEAD(ipmpls_dev_list);

#define MAX_NEW_LABELS 2

struct ipmpls_dev_priv {
	struct net_device *out_dev;
	struct list_head list;
	struct net_device *dev;
};

static netdev_tx_t ipmpls_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipmpls_dev_priv *priv = netdev_priv(dev);
	struct net_device *out_dev = priv->out_dev;
	struct mpls_shim_hdr *hdr;
	bool bottom_of_stack = true;
	int len = skb->len;
	const void *encap;
	int num_labels;
	unsigned ttl;
	const u32 *labels;
	int ret;
	int i;

	num_labels = dst_get_encap(skb, &encap) / 4;
	if (!num_labels)
		goto drop;

	labels = encap;

	/* Obtain the ttl */
	if (skb->protocol == htons(ETH_P_IP)) {
		ttl = ip_hdr(skb)->ttl;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ttl = ipv6_hdr(skb)->hop_limit;
	} else if (skb->protocol == htons(ETH_P_MPLS_UC)) {
		ttl = mpls_entry_decode(mpls_hdr(skb)).ttl;
		bottom_of_stack = false;
	} else {
		goto drop;
	}

	/* Now that the encap has been retrieved, there's no longer
	 * any need to keep the dst around so clear it out.
	 */
	skb_dst_drop(skb);
	skb_orphan(skb);

	skb->inner_protocol = skb->protocol;
	skb->inner_network_header = skb->network_header;

	skb_push(skb, num_labels * sizeof(*hdr));
	skb_reset_network_header(skb);
	hdr = mpls_hdr(skb);

	for (i = num_labels - 1; i >= 0; i--) {
		hdr[i] = mpls_entry_encode(labels[i], ttl, 0, bottom_of_stack);
		bottom_of_stack = false;
	}

	skb->dev = out_dev;
	skb->protocol = htons(ETH_P_MPLS_UC);

	ret = dev_hard_header(skb, out_dev, ETH_P_MPLS_UC,
			      out_dev->dev_addr, NULL, len);
	if (ret >= 0)
		ret = dev_queue_xmit(skb);
	if (ret)
		goto drop;

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += len;

	return 0;

drop:
	dev->stats.tx_dropped++;
	kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int ipmpls_dev_init(struct net_device *dev)
{
	struct ipmpls_dev_priv *priv = netdev_priv(dev);

	list_add_tail(&priv->list, &ipmpls_dev_list);

	return 0;
}

static void ipmpls_dev_uninit(struct net_device *dev)
{
	struct ipmpls_dev_priv *priv = netdev_priv(dev);

	list_del_init(&priv->list);
}

static void ipmpls_dev_free(struct net_device *dev)
{
	free_netdev(dev);
}

static const struct net_device_ops ipmpls_netdev_ops = {
	.ndo_init		= ipmpls_dev_init,
	.ndo_start_xmit		= ipmpls_dev_xmit,
	.ndo_uninit		= ipmpls_dev_uninit,
};

#define IPMPLS_FEATURES (NETIF_F_SG |			\
			 NETIF_F_FRAGLIST |		\
			 NETIF_F_HIGHDMA |		\
			 NETIF_F_VLAN_CHALLENGED)

static void ipmpls_dev_setup(struct net_device *dev)
{
	dev->netdev_ops		= &ipmpls_netdev_ops;

	dev->type		= ARPHRD_MPLS;
	dev->flags		= IFF_NOARP;
	netif_keep_dst(dev);
	dev->addr_len		= 0;
	dev->features		|= NETIF_F_LLTX;
	dev->features		|= IPMPLS_FEATURES;
	dev->hw_features	|= IPMPLS_FEATURES;
	dev->vlan_features	= 0;

	dev->destructor = ipmpls_dev_free;
}

static int ipmpls_dev_validate(struct nlattr *tb[], struct nlattr *data[])
{
	return 0;
}

static int ipmpls_dev_newlink(struct net *src_net, struct net_device *dev,
			      struct nlattr *tb[], struct nlattr *data[])
{
	struct ipmpls_dev_priv *priv = netdev_priv(dev);

	priv->out_dev = src_net->loopback_dev;
	priv->dev = dev;

	dev->hard_header_len =
		priv->out_dev->hard_header_len +
		sizeof(struct mpls_shim_hdr) * MAX_NEW_LABELS;

	return register_netdevice(dev);
}

static void ipmpls_dev_dellink(struct net_device *dev, struct list_head *head)
{
	unregister_netdevice_queue(dev, head);
}

static int ipmpls_dev_parse_encap(const struct net_device *dev,
				  const struct nlattr *nla,
				  void *encap)
{
	u32 labels;

	if (nla_len(nla) / 4 > MAX_NEW_LABELS)
		return -EINVAL;

	if (encap && nla_get_labels(nla, MAX_NEW_LABELS, &labels, encap))
		return -EINVAL;

	/* Stored encap size is the same as the rtnl encap len */
	return nla_len(nla);
}

static int ipmpls_dev_fill_encap(const struct net_device *dev,
				 struct sk_buff *skb, int encap_len,
				 const void *encap)
{
	return nla_put_labels(skb, RTA_ENCAP, encap_len / 4, encap);
}

static int ipmpls_dev_match_encap(const struct net_device *dev,
				  const struct nlattr *nla, int encap_len,
				  const void *encap)
{
	unsigned nla_labels;
	struct mpls_shim_hdr *nla_label;
	const u32 *stored_labels = encap;
	int i;

	/* Stored encap size is the same as the rtnl encap len */
	if (nla_len(nla) != encap_len)
		return 1;

	nla_labels = nla_len(nla) / 4;
	nla_label = nla_data(nla);

	for (i = 0; i < nla_labels; i++) {
		struct mpls_entry_decoded dec;

		dec = mpls_entry_decode(nla_label + i);

		if (stored_labels[i] != dec.label)
			return 1;
	}

	return 0;
}

static struct rtnl_link_ops ipmpls_ops = {
	.kind		= "ipmpls",
	.priv_size	= sizeof(struct ipmpls_dev_priv),
	.setup		= ipmpls_dev_setup,
	.validate	= ipmpls_dev_validate,
	.newlink	= ipmpls_dev_newlink,
	.dellink	= ipmpls_dev_dellink,
	.parse_encap	= ipmpls_dev_parse_encap,
	.fill_encap	= ipmpls_dev_fill_encap,
	.match_encap	= ipmpls_dev_match_encap,
};

static int ipmpls_dev_notify(struct notifier_block *this, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event == NETDEV_UNREGISTER) {
		struct ipmpls_dev_priv *priv, *priv2;
		LIST_HEAD(list_kill);

		/* Ignore netns device moves */
		if (dev->reg_state != NETREG_UNREGISTERING)
			goto done;

		list_for_each_entry_safe(priv, priv2, &ipmpls_dev_list, list) {
			if (priv->out_dev != dev)
				continue;

			ipmpls_dev_dellink(priv->dev, &list_kill);
		}
		unregister_netdevice_many(&list_kill);
	}
done:
	return NOTIFY_OK;
}

static struct notifier_block ipmpls_dev_notifier = {
	.notifier_call = ipmpls_dev_notify,
};

static int __init ipmpls_init(void)
{
	int err;

	err = register_netdevice_notifier(&ipmpls_dev_notifier);
	if (err)
		goto out;

	err = rtnl_link_register(&ipmpls_ops);
	if (err)
		goto out_unregister_notifier;
out:
	return err;
out_unregister_notifier:
	unregister_netdevice_notifier(&ipmpls_dev_notifier);
	goto out;
}
module_init(ipmpls_init);

static void __exit ipmpls_exit(void)
{
	rtnl_link_unregister(&ipmpls_ops);
	unregister_netdevice_notifier(&ipmpls_dev_notifier);
}
module_exit(ipmpls_exit);

MODULE_LICENSE("GPL v2");
MODULE_ALIAS_RTNL_LINK("ipmpls");
