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

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

static void sr_nat_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface);

static void sr_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface);
static void sr_forward_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len);

static void sr_handle_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len);
static void sr_send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code);

static void sr_lookup_and_send(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *oiface, uint32_t ip);

static void sr_handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface);
static void sr_send_arp_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *oiface, struct sr_if *tiface);
static void sr_send_arp_request(struct sr_instance *sr, struct sr_if *oiface, uint32_t tip);

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
    if (sr->nat_enabled) {
        sr_nat_init(&(sr->nat));
    }
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

    /* check length */
    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Failed to process ETHERNET header, insufficient length\n");
        return;
    }
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    /* print_hdr_eth(packet); */
    
    uint16_t ether_type = ntohs(eth_hdr->ether_type);
    struct sr_if *iface = sr_get_interface(sr, interface);
    
    if (ether_type == ethertype_ip) {
        sr_handle_ip(sr, packet, len, iface);
    } else if (ether_type == ethertype_arp) {
        sr_handle_arp(sr, packet, len, iface);
    }
} /* -- sr_handlepacket -- */

void sr_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface)
{
    assert(sr);
    assert(packet);
    assert(iface);
    
    /* check length */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "Failed to process IP header, insufficient length\n");
        return;
    }
    
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /* print_hdr_ip((uint8_t *)ip_hdr); */
    
    if (len < sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4)) {
        fprintf(stderr, "Failed to process IP header, insufficient length\n");
        return;
    }
    
    /* verify checksum */
    uint16_t received_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    
    uint16_t computed_cksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    ip_hdr->ip_sum = received_cksum;
    
    if (received_cksum != computed_cksum) {
        fprintf(stderr, "Failed to process IP header, incorrect checksum\n");
        return;
    }
    
    if (sr->nat_enabled) {
        sr_nat_handle_ip(sr, packet, len, iface);
        return;
    }
    
    /* is it for me? */
    struct sr_if *diface = sr_get_interface_from_ip(sr, ip_hdr->ip_dst);
    
    if (!diface) {
        sr_forward_ip(sr, packet, len);
    } else {
        if (ip_hdr->ip_p == ip_protocol_icmp) {
            sr_handle_icmp(sr, packet, len);
        } else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
            sr_send_icmp(sr, packet, len, icmp_type_unreachable, icmp_code_unreachable_port);
        }
    }
} /* -- sr_handle_ip -- */

void sr_nat_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface)
{
    assert(sr);
    assert(packet);
    assert(iface);
    
    /*
     * check if ICMP or TCP
     * check if outbound or inbound
     * if outbound
     *     lookup internal mapping
     *     if null, insert mapping
     * if inbound
     *     lookup external mapping
     *     if null and not TCP SYN, drop
     * update ip_src for outbound packets, ip_dst for inbound packets
     * update ip_sum
     * if TCP
     *     update port
     *     update tcp_sum
     * sr_forward_ip
     */
    
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    if (ip_hdr->ip_p == ip_protocol_icmp) {
        if (!strncmp(iface->name, NAT_INTERFACE_INT, sr_IFACE_NAMELEN)) {
            /* received from internal interface */
            
            /* is it for me? */
            struct sr_if *diface = sr_get_interface_from_ip(sr, ip_hdr->ip_dst);
            
            if (diface) {
                sr_handle_icmp(sr, packet, len);
            } else {
                /* outbound */
                
                sr_icmp_echo_hdr_t *icmp_hdr = (sr_icmp_echo_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
                
                struct sr_nat_mapping *mapping = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
                
                if (!mapping) {
                    mapping = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
                }
                
                struct sr_if *niface_ext = sr_get_interface(sr, NAT_INTERFACE_EXT);
                
                /* update IP header */
                ip_hdr->ip_src = niface_ext->ip;
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
                
                /* update ICMP header */
                icmp_hdr->icmp_id = mapping->aux_ext;
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
                
                free(mapping);
                
                sr_forward_ip(sr, packet, len);
            }
        } else if (!strncmp(iface->name, NAT_INTERFACE_EXT, sr_IFACE_NAMELEN)) {
            /* received from external interface */
            
            /* is it for me? */
            struct sr_if *diface = sr_get_interface_from_ip(sr, ip_hdr->ip_dst);
            
            if (!diface) {
                return;
            } else {
                /* inbound */
                
                sr_icmp_echo_hdr_t *icmp_hdr = (sr_icmp_echo_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
                
                struct sr_nat_mapping *mapping = sr_nat_lookup_external(&(sr->nat), icmp_hdr->icmp_id, nat_mapping_icmp);
                
                if (!mapping) {
                    return;
                }
                
                /* update IP header */
                ip_hdr->ip_dst = mapping->ip_int;
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
                
                /* update ICMP header */
                icmp_hdr->icmp_id = mapping->aux_int;
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
                
                free(mapping);
                
                sr_forward_ip(sr, packet, len);
            }
        }
    } else if (ip_hdr->ip_p == ip_protocol_tcp) {
        sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
        print_hdr_tcp((uint8_t *)tcp_hdr);
    }
}

void sr_forward_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len)
{
    assert(sr);
    assert(packet);
    
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* decrement ttl */
    ip_hdr->ip_ttl--;
    
    if (ip_hdr->ip_ttl == 0) {
        sr_send_icmp(sr, packet, len, icmp_type_time_exceeded, icmp_code_time_exceeded_ttl);
        return;
    }
    
    /* recompute the checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    
    /* longest prefix match */
    struct sr_rt *rt = sr_longest_prefix_match_lookup(sr, ip_hdr->ip_dst);
    
    if (!rt) {
        sr_send_icmp(sr, packet, len, icmp_type_unreachable, icmp_code_unreachable_net);
        return;
    }
    
    /* outgoing interface */
    struct sr_if *oiface = sr_get_interface(sr, rt->interface);
    
    sr_lookup_and_send(sr, packet, len, oiface, rt->gw.s_addr);
} /* -- sr_forward_ip -- */

void sr_handle_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len)
{
    assert(sr);
    assert(packet);
    
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* check length */
    if (len < sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4) + sizeof(sr_icmp_hdr_t)) {
        fprintf(stderr, "Failed to process ICMP header, insufficient length\n");
        return;
    }
    
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
    /* print_hdr_icmp((uint8_t *)icmp_hdr); */
    
    /* verify checksum */
    uint16_t received_cksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    
    uint16_t computed_cksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
    icmp_hdr->icmp_sum = received_cksum;
    
    if (received_cksum != computed_cksum) {
        fprintf(stderr, "Failed to process ICMP header, incorrect checksum\n");
        return;
    }
    
    if (icmp_hdr->icmp_type == icmp_type_echo_request && icmp_hdr->icmp_code == icmp_code_echo_request) {
        sr_send_icmp(sr, packet, len, icmp_type_echo_reply, icmp_code_echo_reply);
    }
} /* -- sr_handle_icmp -- */

void sr_send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code)
{
    assert(sr);
    assert(packet);
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
    
    /* longest prefix match */
    struct sr_rt *rt = sr_longest_prefix_match_lookup(sr, ip_hdr->ip_src);
    
    if (!rt) {
        /* do not send an ICMP message for an ICMP message */
        return;
    }
    
    /* outgoing interface */
    struct sr_if *oiface = sr_get_interface(sr, rt->interface);
    
    if (icmp_type == icmp_type_echo_reply) {
        /* update ethernet header */
        memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
        memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
        
        /* update ip header */
        uint32_t ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = ip_hdr->ip_dst;
        ip_hdr->ip_dst = ip_dst;
        
        /* update icmp header */
        icmp_hdr->icmp_type = icmp_type_echo_reply;
        icmp_hdr->icmp_code = icmp_code_echo_reply;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
        
        /* print_hdrs(packet, len); */
        sr_lookup_and_send(sr, packet, len, oiface, rt->gw.s_addr);
    } else if (icmp_type == icmp_type_unreachable) {
        unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t *buf = (uint8_t *)malloc(new_len);
        assert(buf);
        
        sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)buf;
        sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        /* ethernet header */
        memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
        memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
        new_eth_hdr->ether_type = htons(ethertype_ip);
        
        /* ip header */
        new_ip_hdr->ip_v = 4;
        new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
        new_ip_hdr->ip_tos = 0;
        new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        new_ip_hdr->ip_id = htons(0);
        new_ip_hdr->ip_off = htons(IP_DF);
        new_ip_hdr->ip_ttl = 64;
        new_ip_hdr->ip_p = ip_protocol_icmp;
        
        if (icmp_code == icmp_code_unreachable_port) {
            new_ip_hdr->ip_src = ip_hdr->ip_dst;
        } else {
            new_ip_hdr->ip_src = oiface->ip;
        }
        
        new_ip_hdr->ip_dst = ip_hdr->ip_src;
        
        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
        
        /* icmp header */
        new_icmp_hdr->icmp_type = icmp_type;
        new_icmp_hdr->icmp_code = icmp_code;
        new_icmp_hdr->unused = 0;
        new_icmp_hdr->next_mtu = 0;
        memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        
        new_icmp_hdr->icmp_sum = 0;
        new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        
        /* print_hdrs(buf, new_len); */
        sr_lookup_and_send(sr, buf, new_len, oiface, rt->gw.s_addr);
        free(buf);
    } else if (icmp_type == icmp_type_time_exceeded) {
        unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
        uint8_t *buf = (uint8_t *)malloc(new_len);
        assert(buf);
        
        sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)buf;
        sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t11_hdr_t *new_icmp_hdr = (sr_icmp_t11_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        /* ethernet header */
        memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
        memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
        new_eth_hdr->ether_type = htons(ethertype_ip);
        
        /* ip header */
        new_ip_hdr->ip_v = 4;
        new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
        new_ip_hdr->ip_tos = 0;
        new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
        new_ip_hdr->ip_id = htons(0);
        new_ip_hdr->ip_off = htons(IP_DF);
        new_ip_hdr->ip_ttl = 64;
        new_ip_hdr->ip_p = ip_protocol_icmp;
        new_ip_hdr->ip_src = oiface->ip;
        new_ip_hdr->ip_dst = ip_hdr->ip_src;
        
        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
        
        /* icmp header */
        new_icmp_hdr->icmp_type = icmp_type;
        new_icmp_hdr->icmp_code = icmp_code;
        new_icmp_hdr->unused = 0;
        memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        
        new_icmp_hdr->icmp_sum = 0;
        new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
        
        /* print_hdrs(buf, new_len); */
        sr_lookup_and_send(sr, buf, new_len, oiface, rt->gw.s_addr);
        free(buf);
    }
} /* -- sr_send_icmp -- */

void sr_lookup_and_send(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *oiface, uint32_t ip)
{
    assert(sr);
    assert(packet);
    assert(oiface);
    
    struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ip);
    
    if (entry) {
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
        
        memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
        
        sr_send_packet(sr, packet, len, oiface->name);
        
        free(entry);
    } else {
        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ip, packet, len, oiface->name);
        
        sr_handle_arpreq(sr, req);
    }
} /* -- sr_lookup_and_send -- */

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req)
{
    assert(sr);
    assert(req);
    
    if (difftime(time(NULL), req->sent) >= 1.0) {
        if (req->times_sent >= 5) {
            struct sr_packet *pkt = NULL;
            sr_ethernet_hdr_t *eth_hdr = NULL;
            struct sr_if *iface = NULL;
            
            pkt = req->packets;
            
            while (pkt) {
                eth_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
                iface = sr_get_interface_from_addr(sr, eth_hdr->ether_dhost);
                
                /* do not send an ICMP message for an ICMP message */
                if (iface) {
                    sr_send_icmp(sr, pkt->buf, pkt->len, icmp_type_unreachable, icmp_code_unreachable_host);
                }
                
                pkt = pkt->next;
            }
            
            sr_arpreq_destroy(&(sr->cache), req);
        } else {
            struct sr_if *oiface = sr_get_interface(sr, req->packets->iface);
            
            sr_send_arp_request(sr, oiface, req->ip);
            
            req->sent = time(NULL);
            req->times_sent++;
        }
    }
} /* -- sr_handle_arpreq -- */

void sr_handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface)
{
    assert(sr);
    assert(packet);
    assert(iface);
    
    /* check length */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        fprintf(stderr, "Failed to process ARP header, insufficient length\n");
        return;
    }
    
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /* print_hdr_arp((uint8_t *)arp_hdr); */
    
    /* check hardware type */
    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
        return;
    }
    
    /* check protocol */
    if (ntohs(arp_hdr->ar_pro) != ethertype_ip) {
        return;
    }
    
    /* is it for me? */
    struct sr_if *tiface = sr_get_interface_from_ip(sr, arp_hdr->ar_tip);
    
    if (!tiface) {
        return;
    }
    
    unsigned short arp_op = ntohs(arp_hdr->ar_op);
    
    if (arp_op == arp_op_request) {
        sr_send_arp_reply(sr, packet, iface, tiface);
    } else if (arp_op == arp_op_reply) {
        struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        
        if (req) {
            struct sr_packet *pkt = NULL;
            struct sr_if *oiface = NULL;
            sr_ethernet_hdr_t *eth_hdr = NULL;
            
            pkt = req->packets;
            
            while (pkt) {
                oiface = sr_get_interface(sr, pkt->iface);
                
                eth_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
                
                memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
                
                sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                
                pkt = pkt->next;
            }
            
            sr_arpreq_destroy(&(sr->cache), req);
        }
    }
} /* -- sr_handle_arp -- */

void sr_send_arp_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *oiface, struct sr_if *tiface)
{
    assert(sr);
    assert(packet);
    assert(oiface);
    assert(tiface);
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *buf = (uint8_t *)malloc(len);
    assert(buf);
    
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)buf;
    sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    
    /* ethernet header */
    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = eth_hdr->ether_type;
    
    /* arp header */
    new_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    new_arp_hdr->ar_pro = arp_hdr->ar_pro;
    new_arp_hdr->ar_hln = arp_hdr->ar_hln;
    new_arp_hdr->ar_pln = arp_hdr->ar_pln;
    new_arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(new_arp_hdr->ar_sha, tiface->addr, ETHER_ADDR_LEN);
    new_arp_hdr->ar_sip = tiface->ip;
    memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    new_arp_hdr->ar_tip = arp_hdr->ar_sip;
    
    /* print_hdrs(buf, len); */
    sr_send_packet(sr, buf, len, oiface->name);
    free(buf);
} /* -- sr_send_arp_reply -- */

void sr_send_arp_request(struct sr_instance *sr, struct sr_if *oiface, uint32_t tip)
{
    assert(sr);
    assert(oiface);
    
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *buf = (uint8_t *)malloc(len);
    assert(buf);
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buf;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    
    /* ethernet header */
    memset(eth_hdr->ether_dhost, 255, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);
    
    /* arp header */
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = sizeof(uint32_t);
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, oiface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = oiface->ip;
    memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = tip;
    
    /* print_hdrs(buf, len); */
    sr_send_packet(sr, buf, len, oiface->name);
    free(buf);
} /* -- sr_send_arp_request -- */

