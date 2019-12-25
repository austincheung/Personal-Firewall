#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

static struct nf_hook_ops telnetFilterHook;
unsigned int telnetFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
 struct iphdr *iph;
 struct tcphdr *tcph;
 iph = ip_hdr(skb);
 tcph = (void *)iph+iph->ihl*4;

if(iph->saddr == in_aton("10.0.2.5") && iph->daddr == in_aton("130.63.236.137"))
{
return NF_DROP;

}
else
{
 return NF_ACCEPT;
}

}

int setUpFilter(void)
{
printk(KERN_INFO "Registering Filter. \n");
telnetFilterHook.hook = telnetFilter;
telnetFilterHook.hooknum = NF_INET_POST_ROUTING;
telnetFilterHook.pf = PF_INET;
telnetFilterHook.priority = NF_IP_PRI_FIRST;
nf_register_net_hook(&init_net,&telnetFilterHook);
return 0;
}
void removeFilter(void)
{
printk(KERN_INFO "Filter is being Removed. \n");
nf_unregister_net_hook(&init_net,&telnetFilterHook);
}
module_init(setUpFilter);
module_exit(removeFilter);
                          