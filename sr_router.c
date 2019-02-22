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
int forward(sr_ip_hdr_t * ip_hdr, struct sr_instance *sr, unsigned int len, uint8_t *
		packet){
	if(ip_hdr->ip_ttl == 1){
		//time to live is up
		return -1;
	}
	// longest prefix match
	struct sr_rt * rt;
	struct sr_if * interfaces;
	struct sr_arpentry * entry;
	rt = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
	if(rt==NULL){
		return -1;
	}
	interfaces = sr_get_interface(sr, rt->interface);
	// look up in routing cache
	entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);

	if (entry) {
		memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
	} else {
		struct sr_arpreq *req;
		req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, buf, len, rt->interface);
		sr_handle_arpreq(sr, req);
		return 0;
	}

	// update ttl and cksum
	ip_hdr->ip_ttl--;
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

	sr_send_packet(sr, packet ,len, rt->interface);
	return 0;
}


void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  // first check length
  if(len<sizeof(sr_ethernet_hdr_t)){
	  return;
  }

  // if the ether packet is an ip packet
  if(ethertype(packet) == htons(ethertype_ip)){
	  // check size:
	  if(len-sizeof(sr_ethernet_hdr_t) < sizeof(sr_ip_hdr_t)){
		  return;
	  }
	  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	  // check checksum
	  if(cksum(ip_hdr, sizeof(sr_ip_hdr_t))!= 0xFFFF){
		  return;
	  }
	  // walk through the interfaces of sr, and figure out where to forward
	  for (struct sr_if * walker = sr->if_list; walker != NULL; walker = walker->next)
		if (walker->ip == ip_hdr->ip_dst) {
			// if the packet is sent to sr
			return;
		}
	  	// else, forward it according to routing table
	  		int res = forward(ip_hdr, sr, len, packet);
	  		if (res != 0) {
	  			fprintf(stderr, "failed.\n");
	  			send_icmp_exception(sr, ip_hdr->ip_src, eth_hdr->ether_shost, htons(ip_hdr->ip_id) + 1, buf + sizeof(sr_ethernet_hdr_t), htons(ip_hdr->ip_len), res);
	  		}
  }

}/* end sr_ForwardPacket */

