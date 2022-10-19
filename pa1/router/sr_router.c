#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_arpcache.h"

/* custom import */
#include <stdlib.h>

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
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

/*
 Returns 1 if ip packet is valid, 0 otherwise
*/
int is_valid_icmp_ip(unsigned int icmp_ip_packet_length, uint8_t *icmp_ip_packet)
{
  unsigned int correct_icmp_ip_packet_length = icmp_ip_packet_length + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);

  if (icmp_ip_packet_length != correct_icmp_ip_packet_length)
  {
    printf("ICMP IP packet length is wrong dumbaassss \n");
    return 0;
  }
  sr_icmp_hdr_t *icmp_packet_header = (sr_icmp_hdr_t *)(icmp_ip_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* validate icmp ip checksum */
  uint16_t icmp_sum = icmp_packet_header->icmp_sum;
  icmp_packet_header->icmp_sum = 0;
  uint16_t correct_icmp_sum = cksum(icmp_packet_header, ntohs(sizeof(sr_icmp_hdr_t)));

  if (icmp_sum != correct_icmp_sum)
  {
    printf("Invalid ICMP checksum \n");
    return 0;
  }
  return 1;
}

/*
 Create ARP Request and send it to the right interface
*/
void build_arp_hdr(sr_arp_hdr_t *new_arp_reply_hdr, sr_arp_hdr_t *arp_request_hdr, struct sr_if *sr_interface)
{
  /* Copying over ap request data */
  new_arp_reply_hdr->ar_hrd = arp_request_hdr->ar_hrd;
  new_arp_reply_hdr->ar_pro = arp_request_hdr->ar_pro;
  new_arp_reply_hdr->ar_hln = arp_request_hdr->ar_hln;
  new_arp_reply_hdr->ar_pln = arp_request_hdr->ar_pln;

  /* One or the other */
  new_arp_reply_hdr->ar_op = htons(arp_op_reply); /* to be extra safe :) */

  /* change Src Dest IP and MAC */
  new_arp_reply_hdr->ar_sip = sr_interface->ip;
  new_arp_reply_hdr->ar_tip = arp_request_hdr->ar_sip;

  memmove(new_arp_reply_hdr->ar_tha, arp_request_hdr->ar_sha, ETHER_ADDR_LEN);
  memmove(new_arp_reply_hdr->ar_sha, sr_interface->addr, ETHER_ADDR_LEN);
}
void build_arp_reply_ethernet_hdr(sr_ethernet_hdr_t *new_ethernet_hdr, sr_ethernet_hdr_t *old_ethernet_hdr, struct sr_if *sr_interface)
{
  new_ethernet_hdr->ether_type = htons(ethertype_arp);

  /*check if using memcopy makes a difference */
  memmove(new_ethernet_hdr->ether_dhost, old_ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memmove(new_ethernet_hdr->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
}

int handle_arp_request(struct sr_instance *sr, unsigned int packet_length, sr_arp_hdr_t *arp_req_hdr, struct sr_if *sr_interface, uint8_t *packet)
{

  printf("Received ARP Request, build arp reply \n");
  uint8_t *new_packet_hdr = malloc(packet_length);
  sr_arp_hdr_t *new_arp_reply_hdr = (sr_arp_hdr_t *)(new_packet_hdr + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *new_ethr_hdr = (sr_ethernet_hdr_t *)(new_packet_hdr);

  sr_ethernet_hdr_t *old_ethr_hdr = (sr_ethernet_hdr_t *)(packet);

  build_arp_reply_ethernet_hdr(new_ethr_hdr, old_ethr_hdr, sr_interface);
  build_arp_hdr(new_arp_reply_hdr, arp_req_hdr, sr_interface);

  print_hdr_eth((uint8_t *)new_ethr_hdr);

  print_hdr_arp((uint8_t *)new_arp_reply_hdr);

  sr_send_packet(sr, new_packet_hdr, packet_length, sr_interface->name);
  free(new_packet_hdr);
  return 1;
}

int handle_arp_reply(struct sr_instance *sr, uint8_t *packet)
{

  printf("Received ARP Reply");
  /*
  Empty out packets in queue
  */
  sr_arp_hdr_t *arp_rep_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_arpreq *is_queued = sr_arpcache_insert(&sr->cache, arp_rep_hdr->ar_sha, arp_rep_hdr->ar_sip);
  struct sr_packet *curr_packet;
  struct sr_if *interface;
  sr_ethernet_hdr_t *ethr_hdr;
  if (is_queued)
  {
    curr_packet = is_queued->packets;
    while (curr_packet)
    {
      interface = sr_get_interface(sr, curr_packet->iface);
      if (interface)
      {
        ethr_hdr = (sr_ethernet_hdr_t *)(curr_packet->buf);
        memmove(ethr_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        memmove(ethr_hdr->ether_dhost, arp_rep_hdr->ar_sha, ETHER_ADDR_LEN);
      }
      curr_packet = curr_packet->next;
    }
    sr_arpreq_destroy(&sr->cache, is_queued);
  }
  return 1;
}

int handle_icmp_ip(struct sr_instance *sr, unsigned int icmp_ip_packet_length, uint8_t *icmp_packet)
{
  if (!is_valid_icmp_ip(icmp_ip_packet_length, icmp_packet))
  {
    return 0;
  }

  sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  print_hdr_icmp((uint8_t *)icmp_header);

  /* 8 : icmp request type 8 means an echo */
  if (icmp_header->icmp_type == 8)
  {
    printf("ICMP ECHO\n");
    send_icmp(sr, 0, 0, icmp_packet, icmp_ip_packet_length);
    return 1;
  }
  return 0;
}
/* Need to pass in packet and packet_length in case ip packet is an icmp ip packet */
int handle_ip_packet(struct sr_instance *sr, sr_ip_hdr_t *ip_header, uint8_t *packet, unsigned int packet_length, char *interface_name)
{

  /*validate checksum*/
  int ip_header_cksum = ip_header->ip_sum;
  ip_header->ip_sum = 0;

  if (ip_header_cksum != cksum(ip_header, sizeof(sr_ip_hdr_t)))
  {
    printf("ip packet has incorrect check sum \n");
    return 0;
  }

  /* Find destination interface of the packet */
  struct sr_if *sr_interface = sr_get_interface(sr, interface_name);
  struct sr_if *if_curr = sr->if_list;
  int is_destined_for_router = 0;
  while (if_curr)
  {
    if (if_curr->ip == ip_header->ip_dst)
    {
      is_destined_for_router = 1;
      break;
    }
    if_curr = if_curr->next;
  }

  if (is_destined_for_router)
  {
    printf("PACKET IS DESTINED FOR ROUTER \n");
    printf("=====Handling IP Packet====\n");
    if (ip_header->ip_p == ip_protocol_icmp)
    {
      printf("\n IP PACKET IS AN ICMP MESSAGE \n");
      handle_icmp_ip(sr, packet_length, packet);
    }

    else
    {
      printf("IP Packet is a TCP/UDP MESSAGE\n");
      /*
      type: 3
      code: 3
      Name: port unreachable
      */
      send_icmp(sr, 3, 3, packet, packet_length);
      return 1;
    }
  }

  else
  {
    printf("Pccket is destined womewhere else \n");
    /* Handle TTL */
    handle_ttl(ip_header, packet, packet_length, sr); 

    int route_ip_packet_res = route_ip_packet(sr, packet, packet_length, sr_interface);
    if (!route_ip_packet_res)
    {
      return 0;
    }
  }
  return 1;
}
void handle_ttl(sr_ip_hdr_t *ip_hdr, uint8_t *packet, unsigned int packet_length, struct sr_instance *sr) {
   ip_hdr->ip_ttl--;
    if (ip_hdr->ip_ttl == 0)
    {
      printf("IP Packet Time Limit Exceeded \n");
      send_icmp(sr, 11, 0, packet, packet_length);
      return;
    }

    /* Recompute modified check sum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

}

/* Custom method: returns 1 if routing succedeeds, 0 otherwise*/
int route_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int packet_length, struct sr_if *incoming_interface)
{
  sr_ip_hdr_t *ip_packet_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t dest_ip = ip_packet_hdr->ip_dst;

  struct sr_rt *potential_rt_entry;
  potential_rt_entry = get_longest_matched_prefix(dest_ip, sr);

  if (potential_rt_entry == NULL)
  {
    /*
    type: 3
    code: 0
    Sent if there is a non-existent route to the destination IP (no matching entry in the routing table when forwarding an IP packet).
    */
    printf("IP does not exist in routing table \n");
    send_icmp(sr, 3, 0, packet, packet_length);
    return 0;
  }

  struct sr_arpreq *arp_req;
  struct sr_arpcache *arp_cache = &sr->cache;
  struct sr_arpentry *cached_entry = sr_arpcache_lookup(arp_cache, dest_ip);

  /* Send an ARP request for the next-hop IP and add the packet to the queue of packets waiting on this ARP request. */
  if (cached_entry == NULL)
  {
    printf("ARP entry is not cached, so queue arp request \n");

    arp_req = sr_arpcache_queuereq(arp_cache, dest_ip, packet, packet_length, incoming_interface->name);
    handle_arpreq(arp_req, sr);
  }

  /* Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP. If it’s there, send it. */
  else
  {
    printf("ARP entry is cached \n");

    /* forward packet to next interface*/
    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)(packet);
    memmove(ethernet_hdr->ether_shost, incoming_interface->addr, ETHER_ADDR_LEN); /* memmove is safer than memcopy because memmove has defined behaviour when src and dst memory overlaps :/// */
    memmove(ethernet_hdr->ether_dhost, cached_entry->mac, ETHER_ADDR_LEN);

    /* send packet */
    sr_send_packet(sr, packet, packet_length, incoming_interface->name);

    /* freeing this based on sr_arpcache_lookup implementation */
    free(cached_entry);
  }
  return 1;
}

int is_ethernet_packet_too_short(unsigned int packet_length)
{
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (packet_length < minlength)
  {
    return 1;
  }
  return 0;
}

/*set attributes of type 3 icmp header*/
void construct_type_3_11_ip_hdr(sr_ip_hdr_t *new_ip_hdr, uint8_t icmp_code, sr_ip_hdr_t *old_ip_hdr, struct sr_instance *sr, struct sr_if *matched_entry_interface)
{
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  new_ip_hdr->ip_ttl = 168; /* some large number within 8 bits*/
  new_ip_hdr->ip_tos = 0;
  new_ip_hdr->ip_id = 0;
  new_ip_hdr->ip_off = htons(IP_DF);
  new_ip_hdr->ip_p = ip_protocol_icmp;

  /* If the port is unreachable, send an icmp packet back to the host*/
  if (icmp_code == 3)
  {
    new_ip_hdr->ip_dst = old_ip_hdr->ip_src;
  }
  /*
  code 0
   - Sent if there is a non-existent route to the destination IP
   (no matching entry in the routing table when forwarding an IP packet).

    code 1
    - Sent if five ARP requests were sent to the next-hop IP without a response.
   */
  else
  {
    new_ip_hdr->ip_dst = matched_entry_interface->ip;
  }
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
}

/* construct icmp hdr for type 3 icmp msgs*/
void construct_type_3_11_icmp_hdr(sr_icmp_t3_hdr_t *new_icmp_hdr, uint8_t icmp_code, uint8_t icmp_type, sr_ip_hdr_t *old_ip_hdr)
{
  new_icmp_hdr->icmp_code = icmp_code;
  new_icmp_hdr->icmp_type = icmp_type;
  memmove(new_icmp_hdr->data, old_ip_hdr, ICMP_DATA_SIZE);
  new_icmp_hdr->unused = 0;
  new_icmp_hdr->next_mtu = 0;

  /* calculate check sum*/
  new_icmp_hdr->icmp_sum = 0;
  new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
}

void construct_echo_icmp_hdr(sr_icmp_hdr_t *new_icmp_hdr, uint8_t icmp_code, uint8_t icmp_type, uint8_t packet_length)
{
  new_icmp_hdr->icmp_code = icmp_code;
  new_icmp_hdr->icmp_type = icmp_type;

  new_icmp_hdr->icmp_sum = 0;
  new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, packet_length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
}

void construct_icmp_ethr_hdr(sr_ethernet_hdr_t *new_ethernet_hdr, sr_ethernet_hdr_t *old_ethernet_hdr)
{
  new_ethernet_hdr->ether_type = htons(ethertype_ip);
  memmove(new_ethernet_hdr->ether_shost, old_ethernet_hdr->ether_dhost, ETHER_ADDR_LEN);
  memmove(old_ethernet_hdr->ether_dhost, old_ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  /*
  memmove(new_ethernet_hdr->ether_dhost, old_ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    memmove(new_ethernet_hdr->ether_shost, matched_entry_interface->addr, ETHER_ADDR_LEN);
    */
  /* TODO what to set this as??*/
}

void send_icmp(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint8_t *packet, unsigned int packet_length)
{

  printf("Send ICMP type: %d, code: %d\n", icmp_type, icmp_code);

  sr_ethernet_hdr_t *new_ethernet_hdr;
  sr_ip_hdr_t *new_ip_hdr;

  sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *old_ethernet_hdr = (sr_ethernet_hdr_t *)(packet);

  /* Outgoing interface */
  struct sr_rt *potential_matched_entry = get_longest_matched_prefix(old_ip_hdr->ip_src, sr);

  if (potential_matched_entry == NULL)
  {
    printf("No matching entry \n");
    return;
  }

  struct sr_if *matched_entry_interface = sr_get_interface(sr, potential_matched_entry->interface);

  if (icmp_type == 3 || icmp_type == 11)
  {
    printf("Building type 11 or type 3 packet\n");
    unsigned int new_packet_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    uint8_t *new_packet = malloc(new_packet_length);

    new_ethernet_hdr = (sr_ethernet_hdr_t *)(new_packet);

    new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *new_icmp_t3_hdr;

    new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    printf("Set packet's ethernet hdr\n");
    construct_icmp_ethr_hdr(new_ethernet_hdr, old_ethernet_hdr);

    printf("Set packet's IP hdr\n");
    construct_type_3_11_ip_hdr(new_ip_hdr, icmp_code, old_ip_hdr, sr, matched_entry_interface);

    printf("Set packet's ICMP3 hdr\n");
    construct_type_3_11_icmp_hdr(new_icmp_t3_hdr, icmp_code, icmp_type, old_ip_hdr);

    print_hdr_eth((uint8_t *)new_packet);
    print_hdr_ip((uint8_t *)new_packet + sizeof(sr_ethernet_hdr_t));
    print_hdr_icmp((uint8_t *)new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    handle_ttl(new_ip_hdr, new_packet, new_packet_length, sr);
    route_ip_packet(sr, new_packet, new_packet_length, matched_entry_interface);
    printf("IP packet was routed \n");
    free(new_packet);
  }

  /*echo reply return original stuff */
  else if (icmp_type == 0)
  {
    uint8_t *echo_packet = malloc(packet_length);
    printf("Construct ICMP for Echo packet\n");
    sr_icmp_hdr_t *new_icmp_hdr = (sr_icmp_hdr_t *)(echo_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_ethernet_hdr = (sr_ethernet_hdr_t *)(echo_packet);
    new_ip_hdr = (sr_ip_hdr_t *)(echo_packet + sizeof(sr_ethernet_hdr_t));

    construct_type_3_11_ip_hdr(new_ip_hdr, icmp_code, old_ip_hdr, sr, matched_entry_interface);
    /* swap src and dst */
    new_ip_hdr->ip_dst = old_ip_hdr->ip_src;
    new_ip_hdr->ip_src = old_ip_hdr->ip_dst;

    /* repeat check sum because we change the hdr*/
    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

    construct_echo_icmp_hdr(new_icmp_hdr, icmp_code, icmp_type, packet_length);
    construct_icmp_ethr_hdr(new_ethernet_hdr, old_ethernet_hdr);

    printf("Forward IP Packet");
    handle_ttl(new_ip_hdr, echo_packet, packet_length, sr);
    route_ip_packet(sr, echo_packet, packet_length, matched_entry_interface);
    free(echo_packet);
  }
}

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  if (is_ethernet_packet_too_short(len))
  {
    printf("Invalid Ethernet packet: too short");
    return;
  }

  /* ip packet */
  if (ethertype(packet) == ethertype_ip)
  {
    printf("This is an IP Packet \n");
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
    handle_ip_packet(sr, ip_header, packet, len, interface);
  }
  else if (ethertype(packet) == ethertype_arp)
  {
    printf("This is an ARP Packet \n");
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    int is_target_ip_one_of_routers_ip = 0;
    struct sr_if *if_curr = sr->if_list;
    while (if_curr)
    {
      if (arp_header->ar_tip == if_curr->ip)
      {
        is_target_ip_one_of_routers_ip = 1;
        break;
      }
      if_curr = if_curr->next;
    }

    if (is_target_ip_one_of_routers_ip)
    {
      printf("Target IP is in router\n");

      if (ntohs(arp_header->ar_op) == arp_op_reply)
      {
        printf("Processing arp reply\n");
        handle_arp_reply(sr, packet);
      }

      else if (ntohs(arp_header->ar_op) == arp_op_request)
      {
        printf("Proessing arp request\n");
        handle_arp_request(sr, len, arp_header, if_curr, packet);
      }
    }
    else
    {
      printf("Target IP is not in router\n");
    }
  }
  else
  {
    printf("Packet is of invalid type \n");
  }

} /* end sr_ForwardPacket */
