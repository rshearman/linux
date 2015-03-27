/*
 * Based on net/ipv6/proc.c.
 */
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stddef.h>
#include <linux/export.h>
#include <linux/mpls.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/snmp.h>
#include <net/ip.h>
#include "internal.h"

static const struct snmp_mib mpls_snmp_list[] = {
	/* RFC 2863 ifEntry (interpreted by RFC 3813) commonly used fields */
	SNMP_MIB_ITEM("ifInOctets", MPLS_IFSTATS_MIB_INOCTETS),
	SNMP_MIB_ITEM("ifInUcastPkts", MPLS_IFSTATS_MIB_INUCASTPKTS),
	SNMP_MIB_ITEM("ifOutOctets", MPLS_IFSTATS_MIB_OUTOCTETS),
	SNMP_MIB_ITEM("ifOutUcastPkts", MPLS_IFSTATS_MIB_OUTUCASTPKTS),

	/* RFC2863 ifEntry/ifXEntry other fields */
	SNMP_MIB_ITEM("ifInDiscards", MPLS_IFSTATS_MIB_INDISCARDS),
	SNMP_MIB_ITEM("ifInErrors", MPLS_IFSTATS_MIB_INERRORS),
	SNMP_MIB_ITEM("ifInUnknownProtos", MPLS_IFSTATS_MIB_INUNKNOWNPROTOS),
	SNMP_MIB_ITEM("ifOutDiscards", MPLS_IFSTATS_MIB_OUTDISCARDS),
	SNMP_MIB_ITEM("ifOutErrors", MPLS_IFSTATS_MIB_OUTERRORS),
	SNMP_MIB_ITEM("ifHCInMulticastPkts", MPLS_IFSTATS_MIB_INMCASTPKTS),
	SNMP_MIB_ITEM("ifHCOutMulticastPkts", MPLS_IFSTATS_MIB_OUTMCASTPKTS),

	/* RFC3813 mplsInterfacePerfEntry fields */
	SNMP_MIB_ITEM("mplsInterfacePerfInLabelLookupFailures",
		      MPLS_LSR_MIB_INLABELLOOKUPFAILURES),
	SNMP_MIB_ITEM("mplsInterfacePerfOutFragmentedPkts",
		      MPLS_LSR_MIB_OUTFRAGMENTEDPKTS),
	SNMP_MIB_SENTINEL
};

static void
mpls_snmp_seq_show_item64(struct seq_file *seq, void __percpu *mib,
			  const struct snmp_mib *itemlist, size_t syncpoff)
{
	int i;

	for (i = 0; itemlist[i].name; i++)
		seq_printf(seq, "%-32s\t%llu\n", itemlist[i].name,
			   snmp_fold_field64(mib, itemlist[i].entry, syncpoff));
}

static int mpls_snmp_dev_seq_show(struct seq_file *seq, void *v)
{
	struct mpls_dev *mdev = (struct mpls_dev *)seq->private;

	seq_printf(seq, "%-32s\t%u\n", "ifIndex", mdev->dev->ifindex);
	mpls_snmp_seq_show_item64(seq, mdev->stats,
			    mpls_snmp_list, offsetof(struct mpls_stats, syncp));
	/* Broadcast not supported by MPLS now, but in case it is ever
	 * supported in the future
	 */
	seq_printf(seq, "%-32s\t%llu\n", "ifHCInBroadcastPkts", 0ULL);
	seq_printf(seq, "%-32s\t%llu\n", "ifHCOutBroadcastPkts", 0ULL);

	return 0;
}

static int mpls_snmp_dev_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, mpls_snmp_dev_seq_show, PDE_DATA(inode));
}

static const struct file_operations mpls_snmp_dev_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = mpls_snmp_dev_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

int mpls_snmp_register_dev(struct mpls_dev *mdev)
{
	struct proc_dir_entry *p;
	struct net *net;

	if (!mdev || !mdev->dev)
		return -EINVAL;

	net = dev_net(mdev->dev);
	if (!net->mpls.proc_net_devsnmp)
		return -ENOENT;

	p = proc_create_data(mdev->dev->name, S_IRUGO,
			     net->mpls.proc_net_devsnmp,
			     &mpls_snmp_dev_seq_fops, mdev);
	if (!p)
		return -ENOMEM;

	mdev->proc_dir_entry_snmp = p;
	return 0;
}

int mpls_snmp_unregister_dev(struct mpls_dev *mdev)
{
	struct net *net = dev_net(mdev->dev);
	if (!net->mpls.proc_net_devsnmp)
		return -ENOENT;
	if (!mdev->proc_dir_entry_snmp)
		return -EINVAL;
	proc_remove(mdev->proc_dir_entry_snmp);
	mdev->proc_dir_entry_snmp = NULL;
	return 0;
}

int mpls_proc_init_net(struct net *net)
{
	net->mpls.proc_net_devsnmp = proc_mkdir("dev_snmp_mpls", net->proc_net);
	if (!net->mpls.proc_net_devsnmp)
		return -ENOMEM;
	return 0;
}

void mpls_proc_exit_net(struct net *net)
{
	remove_proc_entry("dev_snmp_mpls", net->proc_net);
}
