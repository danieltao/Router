/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
int send_pac(struct sr_instance* sr,
		uint32_t dip,
		uint8_t* buf,
		uint32_t len) {
	struct sr_rt *rt;
	rt = sr_longest_prefix_match(sr, dip);

	if (rt == NULL)
		return DEST_NET_UNREACHABLE;

	sr_send_packet(sr, buf, len, rt->interface);
	fprintf(stderr, "Packet sent.\n");
	return 0;
}

int send_arp_request(struct sr_instance* sr, uint32_t dip)
{
	fprintf(stderr, "Sending ARP request to ");
	print_addr_ip_int(ntohl(dip));
	fprintf(stderr, "... ");

	struct sr_rt *rt;
	rt = sr_longest_prefix_match(sr, dip);
	if (rt == NULL) return DEST_NET_UNREACHABLE;

	struct sr_if* interface;
	interface = sr_get_interface(sr, rt->interface);

	sr_arp_hdr_t *arp_pac;
	arp_pac = (sr_arp_hdr_t*) malloc(sizeof(sr_arp_hdr_t));
	arp_pac->ar_hrd = htons(arp_hrd_ethernet);
	arp_pac->ar_pro = htons(arp_pro_ip);
	arp_pac->ar_hln = ETHER_ADDR_LEN;
	arp_pac->ar_pln = sizeof(uint32_t);
	arp_pac->ar_op = htons(arp_op_request);
	memcpy(arp_pac->ar_sha, interface->addr, ETHER_ADDR_LEN);
	memset(arp_pac->ar_tha, 255, ETHER_ADDR_LEN);
	arp_pac->ar_sip = interface->ip;
	arp_pac->ar_tip = dip;

	sr_ethernet_hdr_t *eth_pac;
	eth_pac = (sr_ethernet_hdr_t*) malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(eth_pac->ether_shost, interface->addr, ETHER_ADDR_LEN);
	memset(eth_pac->ether_dhost, 255, ETHER_ADDR_LEN);
	eth_pac->ether_type = htons(ethertype_arp);

	uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t* buf = malloc(len);
	memcpy(buf, eth_pac, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), arp_pac, sizeof(sr_arp_hdr_t));

	int res = send_pac(sr, dip, buf, len);

	free(arp_pac);
	free(eth_pac);
	free(buf);

	return res;
}

int send_arp_reply(struct sr_instance* sr,
		uint32_t sip,
		uint32_t dip,
		uint8_t smac[ETHER_ADDR_LEN],
		uint8_t dmac[ETHER_ADDR_LEN])
{
	fprintf(stderr, "Sending ARP reply to ");
	print_addr_ip_int(ntohl(dip));
	fprintf(stderr, "... ");

	sr_arp_hdr_t *arp_pac;
	arp_pac = (sr_arp_hdr_t*) malloc(sizeof(sr_arp_hdr_t));
	arp_pac->ar_hrd = htons(arp_hrd_ethernet);
	arp_pac->ar_pro = htons(arp_pro_ip);
	arp_pac->ar_hln = ETHER_ADDR_LEN;
	arp_pac->ar_pln = sizeof(uint32_t);
	arp_pac->ar_op = htons(arp_op_reply);
	memcpy(arp_pac->ar_sha, smac, ETHER_ADDR_LEN);
	memcpy(arp_pac->ar_tha, dmac, ETHER_ADDR_LEN);
	arp_pac->ar_sip = sip;
	arp_pac->ar_tip = dip;

	sr_ethernet_hdr_t *eth_pac;
	eth_pac = (sr_ethernet_hdr_t*) malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(eth_pac->ether_dhost, dmac, ETHER_ADDR_LEN);
	memcpy(eth_pac->ether_shost, smac, ETHER_ADDR_LEN);
	eth_pac->ether_type = htons(ethertype_arp);

	uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t* buf = malloc(len);
	memcpy(buf, eth_pac, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), arp_pac, sizeof(sr_arp_hdr_t));

	int res = send_pac(sr, dip, buf, len);

	free(arp_pac);
	free(eth_pac);
	free(buf);

	return res;
}

int send_icmp_reply(struct sr_instance* sr,
		uint32_t sip,
		uint32_t dip,
		uint8_t smac[ETHER_ADDR_LEN],
		uint8_t dmac[ETHER_ADDR_LEN],
		uint16_t ip_id,
		uint32_t icmp_unused,
		uint8_t *icmp_data,
		uint16_t icmp_data_len)
{
	fprintf(stderr, "Sending ICMP reply to ");
	print_addr_ip_int(ntohl(dip));
	fprintf(stderr, "... ");

	sr_icmp_hdr_t *icmp_pac;
	uint32_t icmp_len = sizeof(sr_icmp_hdr_t) + icmp_data_len;
	icmp_pac = malloc(icmp_len);
	icmp_pac->icmp_type = 0;
	icmp_pac->icmp_code = 0;
	icmp_pac->unused = icmp_unused;
	memcpy((uint8_t*)icmp_pac + sizeof(sr_icmp_hdr_t), icmp_data, icmp_data_len);
	icmp_pac->icmp_sum = 0;
	icmp_pac->icmp_sum = cksum(icmp_pac, icmp_len);

	sr_ip_hdr_t *ip_pac;
	ip_pac = (sr_ip_hdr_t*) malloc(sizeof(sr_ip_hdr_t));
	ip_pac->ip_v = 4;
	ip_pac->ip_hl = 5;
	ip_pac->ip_tos = 0;
	ip_pac->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_len);
	ip_pac->ip_id = htons(ip_id);
	ip_pac->ip_off = htons(IP_DF);
	ip_pac->ip_ttl = 64;
	ip_pac->ip_p = ip_protocol_icmp;
	ip_pac->ip_src = sip;
	ip_pac->ip_dst = dip;
	ip_pac->ip_sum = 0;
	ip_pac->ip_sum = cksum(ip_pac, sizeof(sr_ip_hdr_t));

	sr_ethernet_hdr_t *eth_pac;
	eth_pac = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(eth_pac->ether_dhost, dmac, ETHER_ADDR_LEN);
	memcpy(eth_pac->ether_shost, smac, ETHER_ADDR_LEN);
	eth_pac->ether_type = htons(ethertype_ip);

	uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len;
	uint8_t* buf = malloc(len);
	memcpy(buf, eth_pac, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), ip_pac, sizeof(sr_ip_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_pac, icmp_len);

	int res = send_pac(sr, dip, buf, len);

	free(icmp_pac);
	free(ip_pac);
	free(eth_pac);
	free(buf);

	return res;
}

int send_icmp_exception(struct sr_instance* sr,
		uint32_t dip,
		uint8_t dmac[ETHER_ADDR_LEN],
		uint16_t ip_id,
		uint8_t *icmp_data,
		uint16_t icmp_data_len,
		int icmp_exeption_type)
{
	fprintf(stderr, "Sending ICMP packet to ");
	print_addr_ip_int(ntohl(dip));

	struct sr_rt *rt;
	rt = sr_longest_prefix_match(sr, dip);
	struct sr_if *interface;
	interface = sr_get_interface(sr, rt->interface);

	sr_icmp_hdr_t *icmp_pac;
	uint32_t icmp_len = sizeof(sr_icmp_hdr_t) + icmp_data_len;
	icmp_pac = malloc(icmp_len);

	if (icmp_exeption_type == DEST_NET_UNREACHABLE) {
		icmp_pac->icmp_type = 3;
		icmp_pac->icmp_code = 0;
		fprintf(stderr, " (Destination net unreachable)... ");
	} else if (icmp_exeption_type == DEST_HOST_UNREACHABLE) {
		icmp_pac->icmp_type = 3;
		icmp_pac->icmp_code = 1;
		fprintf(stderr, " (Destination host unreachable)... ");
	} else if (icmp_exeption_type == PORT_UNREACHABLE) {
		icmp_pac->icmp_type = 3;
		icmp_pac->icmp_code = 3;
		fprintf(stderr, " (Port unreachable)... ");
	} else if (icmp_exeption_type == TTL_EXCEEDED) {
		icmp_pac->icmp_type = 11;
		icmp_pac->icmp_code = 0;
		fprintf(stderr, " (TTL exceeded)... ");
	}

	icmp_pac->unused = 0;
	memcpy((uint8_t*)icmp_pac + sizeof(sr_icmp_hdr_t), icmp_data, icmp_data_len);
	icmp_pac->icmp_sum = 0;
	icmp_pac->icmp_sum = cksum(icmp_pac, icmp_len);

	sr_ip_hdr_t *ip_pac;
	ip_pac = (sr_ip_hdr_t*) malloc(sizeof(sr_ip_hdr_t));
	ip_pac->ip_v = 4;
	ip_pac->ip_hl = 5;
	ip_pac->ip_tos = 0;
	ip_pac->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_len);
	ip_pac->ip_id = htons(ip_id);
	ip_pac->ip_off = htons(IP_DF);
	ip_pac->ip_ttl = 64;
	ip_pac->ip_p = ip_protocol_icmp;
	ip_pac->ip_src = interface->ip;
	ip_pac->ip_dst = dip;
	ip_pac->ip_sum = 0;
	ip_pac->ip_sum = cksum(ip_pac, sizeof(sr_ip_hdr_t));

	sr_ethernet_hdr_t *eth_pac;
	eth_pac = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(eth_pac->ether_dhost, dmac, ETHER_ADDR_LEN);
	memcpy(eth_pac->ether_shost, interface->addr, ETHER_ADDR_LEN);
	eth_pac->ether_type = htons(ethertype_ip);

	uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len;
	uint8_t* buf = malloc(len);
	memcpy(buf, eth_pac, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), ip_pac, sizeof(sr_ip_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_pac, icmp_len);

	int res = send_pac(sr, dip, buf, len);

	free(icmp_pac);
	free(ip_pac);
	free(eth_pac);
	free(buf);

	return res;
}

int forward_pac(struct sr_instance *sr,
		uint8_t* pac,
		uint32_t len) {
	uint8_t *buf = malloc(len);
	memcpy(buf, pac, len);

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) buf;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));

	fprintf(stderr, "Forwarding IP packet to ");
	print_addr_ip_int(ntohl(ip_hdr->ip_dst));
	fprintf(stderr, "... ");

	if (ip_hdr->ip_ttl == 1)
		return TTL_EXCEEDED;

	struct sr_rt *rt;
	rt = sr_longest_prefix_match(sr, ip_hdr->ip_dst);

	if (rt == NULL)
		return DEST_NET_UNREACHABLE;

	struct sr_if* interface;
	interface = sr_get_interface(sr, rt->interface);
	struct sr_arpentry* entry;
	entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);

	if (entry) {
		memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
	} else {
		fprintf(stderr, "MAC not found in ARP cache, queuing...\n");
		struct sr_arpreq *req;
		req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, buf, len, rt->interface);
		sr_handle_arpreq(sr, req);
		return 0;
	}

	ip_hdr->ip_ttl--;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

	int res = send_pac(sr, ip_hdr->ip_dst, buf, len);

	free(buf);

	return res;
}

int validate(uint8_t* buf, uint32_t len) {
	uint32_t minlength = sizeof(sr_ethernet_hdr_t);
	if (len < minlength) {
		fprintf(stderr, "Failed to validate ETHERNET header: insufficient length.\n");
		return 0;
	}

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buf;
	if (eth_hdr->ether_type == htons(ethertype_ip)) { /* IP */
		minlength += sizeof(sr_ip_hdr_t);
		if (len < minlength) {
			fprintf(stderr, "Failed to validate IP header: insufficient length.\n");
			return 0;
		}
		sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
		if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xFFFF) {
			fprintf(stderr, "Failed to validate IP header: incorrect checksum.\n");
			return 0;
		}
		if (ip_hdr->ip_p == ip_protocol_icmp) { /* ICMP */
			minlength += sizeof(sr_icmp_hdr_t);
			if (len < minlength) {
				fprintf(stderr, "Failed to validate ICMP header: insufficient length\n");
				return 0;
			}
			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			if (cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)) != 0xFFFF) {
				fprintf(stderr, "Failed to validate ICMP header: incorrect checksum.\n");
				return 0;
			}
		}
	} else if (eth_hdr->ether_type == htons(ethertype_arp)) { /* ARP */
		minlength += sizeof(sr_arp_hdr_t);
		if (len < minlength) {
			fprintf(stderr, "Failed to print ARP header, insufficient length\n");
			return 0;
		}
	} else {
		fprintf(stderr, "Unrecognized Ethernet Type: %u\n", htons(eth_hdr->ether_type));
		return 0;
	}
	return 1;
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * buf /* lent */,
        unsigned int len,
        char* interface /* lent */)
{
	assert(sr);
	assert(buf);
	assert(interface);
	printf("\n*** -> Received packet of length %d\n", len);

	if (validate(buf, len) == 0) return;

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buf;

	if (eth_hdr->ether_type == htons(ethertype_ip)) { /* IP */
		sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));

		fprintf(stderr, "Received IP packet (Source: ");
		print_addr_ip_int(ntohl(ip_hdr->ip_src));
		fprintf(stderr, " Target: ");
		print_addr_ip_int(ntohl(ip_hdr->ip_dst));
		fprintf(stderr, " ID: %u)\n", htons(ip_hdr->ip_id));

		struct sr_if *if_walker;
		for (if_walker = sr->if_list; if_walker != NULL; if_walker = if_walker->next){
			if (if_walker->ip == ip_hdr->ip_dst) {
				if (ip_hdr->ip_p == ip_protocol_icmp) {
					sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					if (icmp_hdr->icmp_type != 8) return;
					send_icmp_reply(sr,
							ip_hdr->ip_dst,
							ip_hdr->ip_src,
							eth_hdr->ether_dhost,
							eth_hdr->ether_shost,
							htons(ip_hdr->ip_id) + 1,
							icmp_hdr->unused,
							buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t),
							htons(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t));
				} else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
					send_icmp_exception(sr, ip_hdr->ip_src, eth_hdr->ether_shost, htons(ip_hdr->ip_id) + 1, buf + sizeof(sr_ethernet_hdr_t), htons(ip_hdr->ip_len), PORT_UNREACHABLE);
				}
				return;
			}
		}
		int res = forward_pac(sr, buf, len);
		if (res != 0) {
			fprintf(stderr, "failed.\n");
			send_icmp_exception(sr, ip_hdr->ip_src, eth_hdr->ether_shost, htons(ip_hdr->ip_id) + 1, buf + sizeof(sr_ethernet_hdr_t), htons(ip_hdr->ip_len), res);
		}
	} else if (eth_hdr->ether_type == htons(ethertype_arp)) {
		sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
		struct sr_if *if_walker;
		for (if_walker = sr->if_list; if_walker != NULL; if_walker = if_walker->next)
			if (if_walker->ip == arp_hdr->ar_tip) {
				if (arp_hdr->ar_op == htons(arp_op_request)) {
					fprintf(stderr, "Received ARP request (Source: ");
					print_addr_ip_int(ntohl(arp_hdr->ar_sip));
					fprintf(stderr, " Target: ");
					print_addr_ip_int(ntohl(arp_hdr->ar_tip));
					fprintf(stderr, ")\n");

					send_arp_reply(sr,
							arp_hdr->ar_tip,
							arp_hdr->ar_sip,
							if_walker->addr,
							arp_hdr->ar_sha);
				} else {
					fprintf(stderr, "Received ARP reply (Source: ");
					print_addr_ip_int(ntohl(arp_hdr->ar_sip));
					fprintf(stderr, " Target: ");
					print_addr_ip_int(ntohl(arp_hdr->ar_tip));
					fprintf(stderr, ")\n");

					struct sr_arpreq *req;
					req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

					fprintf(stderr, "New entry inserted, ARP Cache Table:\n");
					sr_arpcache_dump(&sr->cache);

					if (req != NULL) {
						sr_arpcache_send_all_pacs(sr, req->packets);
						sr_arpreq_destroy(&(sr->cache), req);
					}
				}
				return;
			}
		send_pac(sr, arp_hdr->ar_tip, buf, len);
	}
}

