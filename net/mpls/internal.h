#ifndef MPLS_INTERNAL_H
#define MPLS_INTERNAL_H

enum
{
	/* RFC2863 ifEntry/ifXEntry commonly used fields */
	MPLS_IFSTATS_MIB_INOCTETS,		/* ifInOctets */
	MPLS_IFSTATS_MIB_INUCASTPKTS,		/* ifInUcastPkts */
	MPLS_IFSTATS_MIB_OUTOCTETS,		/* ifOutOctets */
	MPLS_IFSTATS_MIB_OUTUCASTPKTS,		/* ifOutUcastPkts */

	/* RFC2863 ifEntry/ifXEntry other fields */
	MPLS_IFSTATS_MIB_INDISCARDS,		/* ifInDiscards */
	MPLS_IFSTATS_MIB_INERRORS,		/* ifInErrors */
	MPLS_IFSTATS_MIB_INUNKNOWNPROTOS,	/* ifInUnknownProtos */
	MPLS_IFSTATS_MIB_OUTDISCARDS,		/* ifOutDiscards */
	MPLS_IFSTATS_MIB_OUTERRORS,		/* ifOutErrors */
	MPLS_IFSTATS_MIB_INMCASTPKTS,		/* ifHCInMulticastPkts */
	MPLS_IFSTATS_MIB_OUTMCASTPKTS,		/* ifHCOutMulticastPkts */
	/* ifHCOutBroadcastPkts and ifHCInBroadcastPkts not stored */

	/* RFC3813 mplsInterfacePerfEntry fields */
	MPLS_LSR_MIB_INLABELLOOKUPFAILURES,	/* mplsInterfacePerfInLabelLookupFailures */
	MPLS_LSR_MIB_OUTFRAGMENTEDPKTS,		/* mplsInterfacePerfOutFragmentedPkts */
	MPLS_MIB_MAX
};

struct mpls_shim_hdr {
	__be32 label_stack_entry;
};

struct mpls_entry_decoded {
	u32 label;
	u8 ttl;
	u8 tc;
	u8 bos;
};

struct mpls_stats {
	u64 			mib[MPLS_MIB_MAX];
	struct u64_stats_sync 	syncp;
};

struct mpls_dev {
	struct net_device      		*dev;
	int				input_enabled;

	struct mpls_stats __percpu	*stats;
	struct ctl_table_header 	*sysctl;
	struct proc_dir_entry 	 	*proc_dir_entry_snmp;
};

struct sk_buff;

static inline struct mpls_shim_hdr *mpls_hdr(const struct sk_buff *skb)
{
	return (struct mpls_shim_hdr *)skb_network_header(skb);
}

static inline struct mpls_shim_hdr mpls_entry_encode(u32 label, unsigned ttl, unsigned tc, bool bos)
{
	struct mpls_shim_hdr result;
	result.label_stack_entry =
		cpu_to_be32((label << MPLS_LS_LABEL_SHIFT) |
			    (tc << MPLS_LS_TC_SHIFT) |
			    (bos ? (1 << MPLS_LS_S_SHIFT) : 0) |
			    (ttl << MPLS_LS_TTL_SHIFT));
	return result;
}

static inline struct mpls_entry_decoded mpls_entry_decode(struct mpls_shim_hdr *hdr)
{
	struct mpls_entry_decoded result;
	unsigned entry = be32_to_cpu(hdr->label_stack_entry);

	result.label = (entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
	result.ttl = (entry & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;
	result.tc =  (entry & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
	result.bos = (entry & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT;

	return result;
}

int nla_put_labels(struct sk_buff *skb, int attrtype,  u8 labels, const u32 label[]);
int nla_get_labels(const struct nlattr *nla, u32 max_labels, u32 *labels, u32 label[]);

int mpls_snmp_register_dev(struct mpls_dev *idev);
int mpls_snmp_unregister_dev(struct mpls_dev *idev);
int mpls_proc_init_net(struct net *net);
void mpls_proc_exit_net(struct net *net);

#endif /* MPLS_INTERNAL_H */
