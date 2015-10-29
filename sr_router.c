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
#include <string.h>
#include <stdlib.h>

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

}/* end sr_ForwardPacket */


void sr_ip_handle(struct sr_instance *sr, 
                  uint8_t *packet,  
                  struct sr_if *interface,
                  unsigned int len){

  assert(sr);
  assert(packet);
  assert(interface);
  
  sr_ip_hdr_t *ihdr = (sr_ip_hdr_t *)(sizeof(sr_ethernet_hdr_t) + packet);
  struct sr_if *dest_interface = sr_get_interface_byIP(sr,ihdr->ip_dst);

  unsigned int check_len1 = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  unsigned int check_len2 = sizeof(sr_ethernet_hdr_t) + (ihdr->ip_hl*4);
  uint16_t sum = ihdr->ip_sum;
  uint16_t ck_sum = cksum(ihdr,ihdr->ip_hl*4);

  if(len < check_len1 || len < check_len2 || sum!=ck_sum){
    printf("ERROR!!!! -> not enough length or check sum not mach");
  }

  /* find address , directly forward*/
  if(!dest_interface){
    sr_ip_forward(sr,packet,len);
    /*if address is not found, i*/
  }else{
    if(ihdr->ip_p == ip_protocol_icmp){
      sr_icmp_handler(sr,packet,len);
    }else{

      /*
      icmp type  unreachable =   3
      icmp code = unreachable = 3
      */
      sr_send_icmp(sr,packet,len,3,3);
    }
  }
}


void sr_ip_forward(struct sr_instance *sr, 
                   uint8_t *packet, 
                   unsigned int len){

  assert(sr);
  assert(packet);

  sr_ip_hdr_t *ihdr =(sr_ip_hdr_t *) (sizeof(sr_ethernet_hdr_t) + packet);
  ihdr->ip_ttl--;
  ihdr->ip_sum = 0;
  ihdr->ip_sum = cksum(ihdr,ihdr->ip_dst);
  struct sr_rt *lpm = sr_lpm(sr, ihdr->ip_dst);
  if(ihdr->ip_ttl == 0){
    /* 
    icmp type : time excceded = 11
    icmp code : time exceeded_ttl = 0
    */
    sr_send_icmp(sr,packet,len,11,0);
  }else if (!lpm){
    /*
    icmp type : unreachable = 3
    icmp code : unreachable-net = 0
    */
    sr_send_icmp(sr,packet,len,3,0);
  }

  struct sr_if *out_interface =  sr_get_interface(sr,lpm->interface);
  sr_sending(sr,packet,len,out_interface,lpm->gw.s_addr);
}

void sr_send_icmp(struct sr_instance *sr,
                  uint8_t *packet,
                  unsigned int len,
                  uint8_t type,
                  uint8_t code){

  assert(sr);
  assert(packet);
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet; 
  sr_ip_hdr_t *ihdr = (sr_ip_hdr_t *)(sizeof(sr_ethernet_hdr_t) + packet);
  struct sr_rt *lpm = sr_lpm(sr,ihdr->ip_dst);
  struct sr_if *out_interface = sr_get_interface(sr,lpm->interface);
  sr_icmp_hdr_t *ichdr = (sr_icmp_hdr_t *)(sizeof(sr_ethernet_hdr_t)+ sizeof(ihdr->ip_hl *4) + packet);
  /*
    handle ICMP according to following type and code. 
    Type 
    unreachable     3
    time exceed     11
    echo            0

    code
    unreachable_host = 1
    unreachable_net = 0
    unreachable_port = 3
    time_exceed = 0
    echo reply = 0
  */

  /* type = unreachable*/
  if(type == 3){
    uint8_t *data = (uint8_t *)malloc(sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    assert(data);

    sr_ip_hdr_t *new_ihdr = (sr_ip_hdr_t *)(sizeof(sr_ethernet_hdr_t) + data);
    sr_ethernet_hdr_t *new_ehdr = (sr_ethernet_hdr_t *)data;
    sr_icmp_t3_hdr_t *new_ichdr = (sr_icmp_t3_hdr_t *)(sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + data);

    /*crate ip header*/
    new_ihdr->ip_p = ip_protocol_icmp;
    new_ihdr->ip_hl = sizeof(sr_ip_hdr_t)/4;
    new_ihdr->ip_tos = 0;
    new_ihdr->ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
    new_ihdr->ip_id = htons(0);
    new_ihdr->ip_off = htons(IP_DF);
    new_ihdr->ip_ttl = 64;
    new_ihdr->ip_v = 4;
    new_ihdr->ip_dst = ihdr->ip_src;
    new_ihdr->ip_sum = cksum(new_ihdr,sizeof(sr_ip_hdr_t));
    /* icmp code = unrachable_port = 3*/
    if(code == 3){
      new_ihdr->ip_src = ihdr->ip_dst;
    }else{
      new_ihdr->ip_src = out_interface->ip;
    }

    /*create icmp header*/
    new_ichdr->icmp_type = type;
    new_ichdr->icmp_code = code;
    new_ichdr->unused = 0;
    new_ichdr->next_mtu = 0;
    new_ichdr->icmp_sum = cksum(new_ichdr,sizeof(sr_icmp_t3_hdr_t));
    memcpy(new_ichdr->data,ihdr,ICMP_DATA_SIZE);

    /*create ethernet header*/
    new_ehdr->ether_type = htons(ethertype_ip);
    memset(new_ehdr->ether_shost,0,ETHER_ADDR_LEN);
    memset(new_ehdr->ether_dhost,0,ETHER_ADDR_LEN);

    uint32_t new_length = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    sr_sending(sr,data,new_length,out_interface,lpm->gw.s_addr);
    free(data);

    /*type = time exceed*/
  }else if (type == 11){
    uint8_t *data = (uint8_t *)malloc(sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    assert(data);

    sr_ip_hdr_t *new_ihdr = (sr_ip_hdr_t *)(sizeof(sr_ethernet_hdr_t) + data);
    sr_ethernet_hdr_t *new_ehdr = (sr_ethernet_hdr_t *)data;
    sr_icmp_t3_hdr_t *new_ichdr = (sr_icmp_t3_hdr_t *)(sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + data);

    /*crate ip header*/
    new_ihdr->ip_p = ip_protocol_icmp;
    new_ihdr->ip_hl = sizeof(sr_ip_hdr_t)/4;
    new_ihdr->ip_tos = 0;
    new_ihdr->ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
    new_ihdr->ip_id = htons(0);
    new_ihdr->ip_off = htons(IP_DF);
    new_ihdr->ip_ttl = 64;
    new_ihdr->ip_v = 4;
    new_ihdr->ip_dst = ihdr->ip_src;
    new_ihdr->ip_src = out_interface->ip;
    new_ihdr->ip_sum = cksum(new_ihdr,sizeof(sr_ip_hdr_t));

    /*create icmp header*/
    new_ichdr->icmp_type = type;
    new_ichdr->icmp_code = code;
    new_ichdr->unused = 0;
    new_ichdr->next_mtu = 0;
    new_ichdr->icmp_sum = cksum(new_ichdr,sizeof(sr_icmp_t3_hdr_t));
    memcpy(new_ichdr->data,ihdr,ICMP_DATA_SIZE);

    /*create ethernet header*/
    new_ehdr->ether_type = htons(ethertype_ip);
    memset(new_ehdr->ether_shost,0,ETHER_ADDR_LEN);
    memset(new_ehdr->ether_dhost,0,ETHER_ADDR_LEN);

    uint32_t new_length = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    sr_sending(sr,data,new_length,out_interface,lpm->gw.s_addr);
    free(data);

    /* echo reply*/
  }else if (type == 0){

    /*update ip hearder*/

    uint32_t ip_dst = ihdr->ip_src;
    ihdr->ip_src = ihdr->ip_dst;
    ihdr->ip_dst = ip_dst;

    /*update icmp header*/

    ichdr->icmp_type = 0;
    ichdr->icmp_code = 0;
    ichdr->icmp_sum = cksum(ichdr,ntohs(ihdr->ip_len)-(ihdr->ip_hl*4));
    /*update ethernet header*/
    memset(ehdr->ether_shost,0,ETHER_ADDR_LEN);
    memset(ehdr->ether_dhost,0,ETHER_ADDR_LEN);  

    sr_sending(sr,packet,len,out_interface,lpm->gw.s_addr);
  }


}
void sr_icmp_handler(struct sr_instance *sr,
                     uint8_t *packet,
                     unsigned int len){

  assert(sr);
  assert(packet);

  sr_ip_hdr_t *ihdr = (sr_ip_hdr_t *)(sizeof(sr_ethernet_hdr_t)+packet);
  sr_icmp_hdr_t *ichdr = (sr_icmp_hdr_t *)(sizeof(sr_ethernet_hdr_t) + (ihdr->ip_hl * 4) + packet);
  unsigned int check_len = sizeof(sr_icmp_hdr_t) + (ihdr->ip_hl*4) + sizeof(sr_ethernet_hdr_t);
  uint16_t sum = ichdr->icmp_sum;
  uint16_t check_sum = cksum(ichdr,ntohs(ihdr->ip_len) - (ihdr->ip_hl*4));
  ichdr->icmp_sum = sum;
  if( len < check_len || sum != check_sum){
    fprintf(stderr,"Faill to produce ICMP header , not enough length or check sum not mach ");
  }

  /* when type is echo request = 8 , and code is echo request = 0*/
  if (ichdr->icmp_type == 8 && ichdr->icmp_code == 0){

    /* send echo replay type = 0 , echo reply code = 0*/
    sr_send_icmp(sr,packet,len,0,0);
  }
                     }
void sr_sending(struct sr_instance *sr,
                uint8_t *packet,
                unsigned int len,
                struct sr_if *interface,
                uint32_t ip){

  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_arpentry *arp = sr_arpcache_lookup(&(sr->cache),ip);

  if(arp){
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;

    memcpy(ehdr->ether_dhost,arp->mac,ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost,interface->addr,ETHER_ADDR_LEN);

    sr_send_packet(sr,packet,len,interface->name);
  }else{
    struct sr_arpreq *request = sr_arpcache_queuereq(&(sr->cache),ip,packet,len,interface->name);
    sr_handle_arpreq(sr,request);

  }
}


void sr_handle_arp_packet(struct sr_instance *sr, 
                          uint8_t *packet,
                          unsigned int len,
                          char *receiving_interface)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(receiving_interface);

  /*Check packet length*/
  if (len != sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
  {
    fprintf(stderr, "ERROR: Incorrect packet length\n");
    return;
  }

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) packet;
  struct sr_if *receive_interface = sr_get_interface(sr, receiving_interface);
  struct sr_if *sender_interface  = sr_get_interface_byIP(sr, arp_hdr->ar_sip); 

  /*Check interface whether in router's IP address*/
  if (!receive_interface)
  {
    fprintf(stderr, "ERROR: Invalid interface\n");
    return;
  }

  /* Get arp_opcode: request or replay to me*/
  if (ntohs(arp_hdr->ar_op) == arp_op_request)  /* Request to me, send a reply*/
    sr_handle_arp_send_reply_to_requester(sr, packet, receive_interface, sender_interface);
  else if (ntohs(arp_hdr->ar_op) == arp_op_reply)    /* Reply to me, cache it */
    sr_handle_arp_cache_reply(sr, packet, receive_interface);

}/* end sr_handle_arp_packet */

void sr_handle_arp_cache_reply(struct sr_instance *sr,
                               uint8_t *packet,
                               struct sr_if *interface_info)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Cache it */
  struct sr_arpreq *requests = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip); 

  /* Go through my request queue for this IP and send outstanding packets if there are any*/
  if(requests)
  {
    struct sr_packet *pkts =  NULL;
    pkts = requests->packets;
    struct sr_if *dest_if;
    sr_ethernet_hdr_t *eth_hdr = NULL; 
    
    while(pkts)
    {
      eth_hdr = (sr_ethernet_hdr_t *)(pkts->buf);
      dest_if = sr_get_interface(sr, pkts->iface);
      /* source and desti mac addresss switched*/
      memcpy(eth_hdr->ether_shost, dest_if->addr, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      sr_send_packet(sr, pkts->buf, pkts->len, interface_info->name);
      pkts = pkts->next;
    }
    sr_arpreq_destroy(&(sr->cache), requests);
  }
}/* end sr_handle_arp_send_reply */


void sr_handle_arp_send_reply_to_requester(struct sr_instance *sr,
                                           uint8_t *packet,
                                           struct sr_if *receive_interface,
                                           struct sr_if *sender_interface)
{
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Consttruct a ARP reply*/
  uint8_t *reply = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)); 
  sr_ethernet_hdr_t *new_ether_hdr = (sr_ethernet_hdr_t *) reply;

  /* Construct the ethernet header */
  new_ether_hdr->ether_type = ethertype_arp;
  memcpy(new_ether_hdr->ether_dhost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(new_ether_hdr->ether_shost, receive_interface->addr,ETHER_ADDR_LEN);

  /* Construct the ARP header */
  sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)(reply + sizeof(sr_arp_hdr_t));
  new_arp_hdr->ar_hrd = arp_hdr->ar_hrd;      /* format of hardware address   */
  new_arp_hdr->ar_pro = arp_hdr->ar_pro;      /* format of protocol address   */
  new_arp_hdr->ar_hln = arp_hdr->ar_hln;     /* length of hardware address   */
  new_arp_hdr->ar_pln = arp_hdr->ar_pln;      /* length of protocol address   */
  new_arp_hdr->ar_op  = htons(arp_op_reply);  /* ARP opcode (command)         */
  new_arp_hdr->ar_sip = sender_interface->ip;   /* Sender IP address            */
  new_arp_hdr->ar_tip = arp_hdr->ar_sip;      /* Target IP address            */
  memcpy(new_arp_hdr->ar_sha, receive_interface->addr, ETHER_ADDR_LEN); /* sender hardware address      */
  memcpy(new_arp_hdr->ar_tha, sender_interface->addr, ETHER_ADDR_LEN);  /* target hardware address      */

  /*ARP replies are sent directly to the requester’s MAC address.*/
  sr_send_packet(sr, reply, sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t), sender_interface->name);
  free(reply);
}/* end sr_handle_arp_manage_reply*/


/* HELPERS */
struct sr_if *sr_get_interface_byIP(struct sr_instance *sr,
                                    uint32_t ip){
  struct sr_if *if_walker = 0;
  assert(sr);

  if_walker = sr->if_list;
  while(if_walker){
    if (ip == if_walker->ip){
      return if_walker;
    }
    if_walker = if_walker->next;
  }
  return 0;
}

struct sr_if *sr_get_interface_byAddr(struct sr_instance *sr,
                                    const unsigned char *addr){
  struct sr_if *if_walker = 0;
  assert(sr);
  assert(addr);


  if_walker = sr->if_list;
  while(if_walker){
    if (!memcpy(if_walker->addr,addr,ETHER_ADDR_LEN)){
      return if_walker;
    }
    if_walker = if_walker->next;
  }
  return 0;
}




struct sr_rt *sr_lpm(struct sr_instance *sr, uint32_t ip){

  assert(sr);
  struct sr_rt *lpm = 0;
  struct sr_rt *rt_walker = 0;
  uint32_t lpm_len = 0;
  rt_walker = sr->routing_table;

  while(rt_walker){
    if((rt_walker->mask.s_addr & ip ) == (rt_walker->mask.s_addr & rt_walker->dest.s_addr)){
      if(rt_walker->mask.s_addr >= lpm_len){
        lpm = rt_walker;
        lpm_len = rt_walker->mask.s_addr;
      }
    }
    rt_walker = rt_walker->next;
  }
  return lpm;
}

