#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
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

void handle_arp_reply(struct sr_instance *sr, uint8_t *packet, unsigned int length, char *interface)
{
  printf("Handling ARP Reply\n");
  sr_arp_hdr_t *arp_rep_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_arpreq *ip_in_queue = sr_arpcache_insert(&(sr->cache), arp_rep_hdr->ar_sha, arp_rep_hdr->ar_sip);

  if (ip_in_queue == NULL)
  {
    return;
  }

  struct sr_packet *curr_packet = ip_in_queue->packets;
  while (curr_packet)
  {
    struct sr_if *pkt_interface = sr_get_interface(sr, curr_packet->iface);
    if (pkt_interface)
    {
      /* update eth hdr*/
      sr_ethernet_hdr_t *pkt_eth_hdr = (sr_ethernet_hdr_t *)(curr_packet->buf);
      memcpy(pkt_eth_hdr->ether_shost, pkt_interface->addr, ETHER_ADDR_LEN);
      memcpy(pkt_eth_hdr->ether_dhost, arp_rep_hdr->ar_sha, ETHER_ADDR_LEN);
      sr_send_packet(sr, curr_packet->buf, curr_packet->len, curr_packet->iface);
    }
    curr_packet = curr_packet->next;
  }
  sr_arpreq_destroy(&(sr->cache), ip_in_queue);
}

void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int length, char *interface)
{
  /* Add error check */
  sr_arp_hdr_t *arp_req_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *sr_if = sr_get_interface(sr, interface);

  if (sr_if)
  {
    if (ntohs(arp_req_hdr->ar_op) == arp_op_reply)
    {
      handle_arp_reply(sr, packet, length, interface);
    }
    else if (ntohs(arp_req_hdr->ar_op) == arp_op_request)
    {
      handle_arp_req(sr, packet, length, interface);
    }
  }
  else {
    printf("ARP reply error\n");
  }
}

void handle_arp_req(struct sr_instance *sr, uint8_t *packet, unsigned int length, char *interface)
{
  uint8_t *new_hdr = malloc(length);
  sr_ethernet_hdr_t *old_eth_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_arp_hdr_t *old_arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *new_ethr_hdr = (sr_ethernet_hdr_t *)(new_hdr);
  sr_arp_hdr_t *new_arp_rep_hdr = (sr_arp_hdr_t *)(new_hdr + sizeof(sr_ethernet_hdr_t));
  struct sr_if *sr_if = sr_get_interface(sr, interface);

  /*copy the whole packet and update values*/
  memcpy(new_hdr, packet, length);
  /*Build eth hdr*/
  memcpy(new_ethr_hdr->ether_dhost, old_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_ethr_hdr->ether_shost, sr_if->addr, ETHER_ADDR_LEN);
  /*Build arp reply hdr*/
  new_arp_rep_hdr->ar_op = htons(arp_op_reply);
  new_arp_rep_hdr->ar_sip = sr_if->ip;
  new_arp_rep_hdr->ar_tip = old_arp_hdr->ar_sip;
  memcpy(new_arp_rep_hdr->ar_tha, old_arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(new_arp_rep_hdr->ar_sha, sr_if->addr, ETHER_ADDR_LEN);

  /*Debug statements*/
  print_hdr_eth((uint8_t *)new_ethr_hdr);
  print_hdr_arp((uint8_t *)new_arp_rep_hdr);

  sr_send_packet(sr, new_hdr, length, interface);
  free(new_hdr);
}

sr_ip_hdr_t *get_ip_hdr(uint8_t *packet)
{
  return (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}

bool forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int packet_length, char *interface_name)
{
  sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
  struct sr_rt *rt_entry;
  rt_entry = get_longest_matched_prefix(ip_hdr->ip_dst, sr);

  if (rt_entry == NULL)
  {
    /*
    type: 3
    code: 0
    Sent if there is a non-existent route to the destination IP (no matching entry in the routing table when forwarding an IP packet).
    */
    printf("IP does not exist in routing table \n");
    send_icmp_unreachable(sr, packet, packet_length, interface_name, 0);
    return false;
  }

  /*
  If destination interface exists, check our arp cache
  if it's inside the arpcache, send it
  if it's not, send arp req
  */
  struct sr_if *outgoing_interface = sr_get_interface(sr, rt_entry->interface);
  struct sr_arpentry *arp_cached_entry;
  struct sr_arpreq *arp_req;

  arp_cached_entry = sr_arpcache_lookup(&(sr->cache), rt_entry->gw.s_addr);

  if (arp_cached_entry == NULL)
  {
    printf("ARP entry is not cached, so queue arp request \n");
    printf("Interface name %s \n", outgoing_interface->name);
    arp_req = sr_arpcache_queuereq(&(sr->cache), rt_entry->gw.s_addr, packet, packet_length, rt_entry->interface);
    handle_arpreq(arp_req, sr);
  }
  else
  {
    printf("ARP entry is cached \n");

    /* forward packet to next destination, update ethernet hdr*/
    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)(packet);
    memcpy(ethernet_hdr->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_dhost, arp_cached_entry->mac, ETHER_ADDR_LEN);

    /* send packet */
    sr_send_packet(sr, packet, packet_length, rt_entry->interface);

    /* freeing this based on sr_arpcache_lookup implementation */
    free(arp_cached_entry);
  }

  return true;
}
/* Need to pass in packet and packet_length in case ip packet is an icmp ip packet */
int handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int packet_length, char *interface)
{

  printf("=====Handling IP Packet====\n");
  /*validate checksum*/
  sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
  int curr_cksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  if (curr_cksum != cksum(ip_hdr, sizeof(sr_ip_hdr_t)))
  {
    printf("ip packet has incorrect check sum \n");
    return 0;
  }

  /*Traverse router's interface list*/
  struct sr_if *curr_if = sr->if_list;
  bool is_destined_for_router = false;

  while (curr_if)
  {
    if (curr_if->ip == ip_hdr->ip_dst)
    {
      is_destined_for_router = true;
      break;
    }
    curr_if = curr_if->next;
  }

  if (is_destined_for_router)
  {
    printf("PACKET IS DESTINED FOR ROUTER \n");

    if (ip_hdr->ip_p == ip_protocol_icmp)
    {
      printf("\n IP PACKET IS AN ICMP MESSAGE \n");
      /*
      TODO: Error checking on icmp packet
      */

      /* icmp type 8 is an echo request */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet);
      if (icmp_hdr->icmp_type == 8)
      {
        send_icmp_echo(sr, packet, packet_length, interface);
        return 1;
      }
      return 0;
    }
    else
    {
      printf("IP Packet is a TCP/UDP MESSAGE\n");
      /*
      type: 3
      code: 3
      Name: port unreachable
      */
      send_icmp_unreachable(sr, packet, packet_length, interface, 3);
      return 1;
    }
  }

  else
  {
    printf("Forward packet \n");
    /* Handle TTL */
    ip_hdr->ip_ttl--;
    print_hdrs(packet, packet_length);

    if (ip_hdr->ip_ttl == 0)
    {
      printf("Send ICMP type 11 message \n");

      send_icmp_time_limit_exceeded(sr, packet, packet_length, interface);
      return 0;
    }

    /* Recompute modified check sum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    bool is_forward_packet_succesful = forward_packet(sr, packet, packet_length, interface);
    if (is_forward_packet_succesful)
    {
      printf("Successfully forwarded packet\n");
      return 0;
    }
    else
    {
      printf("Did not successfuly forward packet\n");
    }
  }
  return 1;
}

void check_arp_cache_send_packet(struct sr_instance *sr, uint8_t *packet, unsigned int packet_length, struct sr_if *interface, uint32_t dest_ip)
{
  struct sr_arpreq *arp_req;
  struct sr_arpcache *arp_cache = &sr->cache;
  /*struct sr_arpentry *cached_entry = sr_arpcache_lookup(arp_cache, potential_rt_entry->gw.s_addr);*/
  struct sr_arpentry *cached_entry = sr_arpcache_lookup(arp_cache, dest_ip);

  /* Send an ARP request for the next-hop IP and add the packet to the queue of packets waiting on this ARP request. */
  if (cached_entry == NULL)
  {
    printf("ARP entry is not cached, so queue arp request \n");
    printf("Interface name %s \n", interface->name);
    arp_req = sr_arpcache_queuereq(arp_cache, dest_ip, packet, packet_length, interface->name);
    /*printf("\nLINE 287 HIT\n"); */
    handle_arpreq(arp_req, sr);
  }

  /* Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP. If it’s there, send it. */
  else
  {
    printf("ARP entry is cached \n");

    /* forward packet to next interface*/
    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)(packet);
    memmove(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN); /* memmove is safer than memcopy because memmove has defined behaviour when src and dst memory overlaps :/// */
    memmove(ethernet_hdr->ether_dhost, cached_entry->mac, ETHER_ADDR_LEN);

    /* send packet */
    sr_send_packet(sr, packet, packet_length, interface->name);

    /* freeing this based on sr_arpcache_lookup implementation */
    free(cached_entry);
  }
}
/* Custom method: returns 1 if routing succedeeds, 0 otherwise*/

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
  /* If the port is unreachable, send an icmp packet back to the host

  code 0
   - Sent if there is a non-existent route to the destination IP
   (no matching entry in the routing table when forwarding an IP packet).

    code 1
    - Sent if five ARP requests were sent to the next-hop IP without a response.
   */

  if (icmp_code == 3)
  {
    new_ip_hdr->ip_src = old_ip_hdr->ip_dst;
  }
  else
  {
    new_ip_hdr->ip_src = matched_entry_interface->ip;
  }

  new_ip_hdr->ip_dst = old_ip_hdr->ip_src;
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
  memmove(new_ethernet_hdr->ether_dhost, old_ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
}

void send_icmp_echo(struct sr_instance *sr, uint8_t *packet, unsigned int length, char *interface)
{
  printf("Sending ICMP Echo packet\n");

  uint8_t *new_pkt = malloc(length);
  sr_ethernet_hdr_t *old_eth_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)(new_pkt);
  /* set eth hdr*/
  new_eth_hdr->ether_type = htons(ethertype_ip);
  memcpy(new_eth_hdr->ether_shost, old_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(new_eth_hdr->ether_dhost, old_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  /* set icmp hdr */
  sr_icmp_hdr_t *new_icmp_hdr = (sr_icmp_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  new_icmp_hdr->icmp_type = 0;
  new_icmp_hdr->icmp_sum = 0;
  new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, length - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));

  print_hdrs(new_pkt, length);
  /*Outgoing interface is also the incoming interface since we want to send it back to the host that echoed*/
  forward_packet(sr, new_pkt, length, interface);
  /*sr_send_packet(sr, new_pkt, length, interface);*/
}

void send_icmp_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int length, char *interface, uint8_t code)
{

  printf("Send ICMP unreachable type: %d, code: %d\n", 3, code);
  sr_ethernet_hdr_t *old_eth_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  unsigned int new_pkt_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *new_pkt = malloc(new_pkt_length);
  sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)(new_pkt);
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* build eth hdr */
  new_eth_hdr->ether_type = htons(ethertype_ip);
  memcpy(new_eth_hdr->ether_shost, old_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(new_eth_hdr->ether_dhost, old_eth_hdr->ether_shost, ETHER_ADDR_LEN);

  /*build ip hdr*/
  new_ip_hdr->ip_v = 4;
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  new_ip_hdr->ip_ttl = 168; /* some large number within 8 bits*/
  new_ip_hdr->ip_tos = 0;
  new_ip_hdr->ip_id = htons(0);
  new_ip_hdr->ip_off = htons(IP_DF);
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_src = old_ip_hdr->ip_dst;
  new_ip_hdr->ip_dst = old_ip_hdr->ip_src;
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  /*build icmp t3 hdr*/
  new_icmp_t3_hdr->icmp_type = 3;
  new_icmp_t3_hdr->icmp_code = code;

  memcpy(new_icmp_t3_hdr->data, old_ip_hdr, ICMP_DATA_SIZE);
  new_icmp_t3_hdr->unused = 0;
  new_icmp_t3_hdr->next_mtu = 1500;
  new_icmp_t3_hdr->icmp_sum = 0;
  new_icmp_t3_hdr->icmp_sum = cksum(new_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));

  print_hdrs(new_pkt, new_pkt_length);
  if (code != 3)
  {
    /*Send to router need to get the interface that it's received from*/
    struct sr_if *if_curr = sr->if_list;
    while (if_curr) {
      if (if_curr->ip == old_ip_hdr->ip_src){
          break; 
      }
      if_curr = if_curr->next;
    }
    struct sr_if *sr_if = sr_get_interface(sr, if_curr->name);
    new_ip_hdr->ip_src = sr_if->ip;
  }
  if (code == 1)
  {
    struct sr_rt *rt_entry = get_longest_matched_prefix(old_ip_hdr->ip_src, sr);

    /*
    When code == 1, we pass in the outgoing interface

    But the destination interface of the send icmp unreachable methods (type 3, code 1) is the coming interface, this handles that edge case
    */
    forward_packet(sr, new_pkt, new_pkt_length, rt_entry->interface); /* TODO verify rt_entry-> interface is an array? Will there be memory issues*/
    return;
  }
  /*
  The interface variable is the name if the incoming interface
  Forward IP expects the interface to be the name of the destination interface

  Because the new ip_dst is the old ip_src, passing in the incoming interface and not changing it is fine

  */
  forward_packet(sr, new_pkt, new_pkt_length, interface);
}
void send_icmp_time_limit_exceeded(struct sr_instance *sr, uint8_t *packet, unsigned int length, char *interface)
{

  printf("TTL ICMP packet\n");

  sr_ethernet_hdr_t *old_eth_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  unsigned int new_pkt_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *new_pkt = malloc(new_pkt_length);
  sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)(new_pkt);
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* build eth hdr */
  new_eth_hdr->ether_type = htons(ethertype_ip);
  memcpy(new_eth_hdr->ether_shost, old_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(new_eth_hdr->ether_dhost, old_eth_hdr->ether_shost, ETHER_ADDR_LEN);

  /* build ip hdr*/
  new_ip_hdr->ip_v = 4;
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  new_ip_hdr->ip_ttl = 168; /* some large number within 8 bits*/
  new_ip_hdr->ip_tos = 0;
  new_ip_hdr->ip_id = htons(0);
  new_ip_hdr->ip_off = htons(IP_DF);
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_src = old_ip_hdr->ip_dst;
  new_ip_hdr->ip_dst = old_ip_hdr->ip_src;
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  /* build icmp hdr */
  new_icmp_t3_hdr->icmp_type = 11;
  new_icmp_t3_hdr->icmp_code = 0;

  memcpy(new_icmp_t3_hdr->data, old_ip_hdr, ICMP_DATA_SIZE);
  new_icmp_t3_hdr->unused = 0;
  new_icmp_t3_hdr->next_mtu = 1500;
  new_icmp_t3_hdr->icmp_sum = 0;
  new_icmp_t3_hdr->icmp_sum = cksum(new_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));

  print_hdrs(new_pkt, new_pkt_length);

  forward_packet(sr, new_pkt, new_pkt_length, interface);
  free(new_pkt);
}

void send_icmp(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint8_t *packet, unsigned int packet_length)
{

  printf("Send ICMP type: %d, code: %d\n", icmp_type, icmp_code);

  sr_ethernet_hdr_t *new_ethernet_hdr;
  sr_ip_hdr_t *new_ip_hdr;
  sr_icmp_t3_hdr_t *new_icmp_t3_hdr;

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

    new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    printf("Set packet's ethernet hdr\n");
    construct_icmp_ethr_hdr(new_ethernet_hdr, old_ethernet_hdr);

    printf("Set packet's IP hdr\n");
    construct_type_3_11_ip_hdr(new_ip_hdr, icmp_code, old_ip_hdr, sr, matched_entry_interface);

    printf("Set packet's ICMP3 hdr\n");
    construct_type_3_11_icmp_hdr(new_icmp_t3_hdr, icmp_code, icmp_type, old_ip_hdr);
    /*Above is fine*/

    print_hdr_eth((uint8_t *)new_ethernet_hdr);
    print_hdr_ip((uint8_t *)new_ip_hdr);
    print_hdr_icmp((uint8_t *)new_icmp_t3_hdr);

    check_arp_cache_send_packet(sr, new_packet, new_packet_length, matched_entry_interface, potential_matched_entry->gw.s_addr);
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
    check_arp_cache_send_packet(sr, echo_packet, packet_length, matched_entry_interface, potential_matched_entry->gw.s_addr);
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
    handle_ip_packet(sr, packet, len, interface);
  }
  else if (ethertype(packet) == ethertype_arp)
  {
    printf("This is an ARP Packet \n");
    handle_arp_packet(sr, packet, len, interface);
  }

  else
  {
    printf("Packet is of invalid type \n");
  }

} /* end sr_ForwardPacket */
