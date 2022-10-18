#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

unsigned char broadcast_addr[ETHER_ADDR_LEN] = {255, 255, 255, 255, 255, 255};

struct sr_arp_hdr *create_arp_request_packet(struct sr_arpreq *arpr, struct sr_instance *sr, struct sr_if *sif)
{
    struct sr_arp_hdr *hdr = malloc(sizeof(struct sr_arp_hdr));
    hdr->ar_hrd = (unsigned char)htons(arp_hrd_ethernet);                    /* Ethernet */
    hdr->ar_pro = (unsigned char)htons(ethertype_ip);                        /* IPv4 */
    hdr->ar_hln = (unsigned char)ETHER_ADDR_LEN;                             /* Ethernet protocol length */
    hdr->ar_pln = (unsigned char)sizeof(uint32_t);                           /* IPv4 protocol length */
    hdr->ar_op = (unsigned char)htons(arp_op_request);                       /* Should be 1 here */
    memmove(hdr->ar_sha, sif->addr, sizeof(unsigned char) * ETHER_ADDR_LEN); /* Use Interface Address */
    hdr->ar_sip = sif->ip;                                                   /* Sender IP from Interface */
    hdr->ar_tip = arpr->ip;                                                  /* Target IP from Request */
    memset(hdr->ar_tha, 0x00, ETHER_ADDR_LEN);                               /* set to 0 to be safe https://piazza.com/class/l5gx8w2al3g4zh/post/207*/
    return hdr;
}

void handle_arpreq(struct sr_arpreq *arpr, struct sr_instance *sr)
{
    time_t current_time;
    time(&current_time);
    if (difftime(current_time, arpr->sent) >= 1.0) /* Pseudocode says to use 1 piazza says >= https://piazza.com/class/l5gx8w2al3g4zh/post/150*/
    {
        if (arpr->times_sent >= 5)
        {
            /* Send ICMP unreachable*/
            printf("ICMP Host unreachable: ARP Request sent more than five times \n");
            printf("Empty arp queue\n");
            struct sr_packet *srp = arpr->packets;
            while (srp)
            {
                /**
                 * ICMP message
                 * type: 3
                 * code: 1
                 * Sent if five ARP requests were sent to the next-hop IP without a response.
                 */

                /*
                memcpy(eth_hdr->ether_shost, broadcast, sizeof(uint8_t) * ETHER_ADDR_LEN);  Dest Address will be broadcast 

                eth_hdr->ether_type = ethertype_ip;

                int total_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_icmp_hdr);
                uint8_t *buf = malloc(total_size);
                sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)buf;
                sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
                memcpy(ethernet_hdr, eth_hdr, sizeof(sr_ethernet_hdr_t));


                 Free buffer and ETH Header, not ICMP packet!
                free(buf);
                free(eth_hdr);
                */

                /* Send unreachable ICMP packet */
                struct sr_if* interface = sr_get_interface(sr, srp->iface);
                if (interface){
                    send_icmp(sr, 3, 1, srp->buf, srp->len);
                }

                /* Iterate linked list*/
                srp = srp->next;
            }
            /* Free ICMP header and destroy ARP Request*/
            sr_arpreq_destroy(&sr->cache, arpr);
        }
        else
        {
            /* Send ARP Request*/
            /* Construct ARP request see if a forward or reply.*/
            printf("=====Sending ARP Request======\n");

            struct sr_if *sif = sr_get_interface(sr, arpr->packets->iface);
            struct sr_arp_hdr *arp_hdr = create_arp_request_packet(arpr, sr, sif);
            struct sr_ethernet_hdr *eth_hdr = malloc(sizeof(struct sr_ethernet_hdr));
            memmove(eth_hdr->ether_shost, sif->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);      /* Source address same*/
            memmove(eth_hdr->ether_dhost, broadcast_addr, sizeof(uint8_t) * ETHER_ADDR_LEN); /* Dest Address will be broadcast*/
            eth_hdr->ether_type = ethertype_arp;

            int total_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
            uint8_t *buf = malloc(total_size);
            sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)buf;
            sr_arp_hdr_t *arp_reply_hdr = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
            memmove(ethernet_hdr, eth_hdr, sizeof(sr_ethernet_hdr_t));
            memmove(arp_reply_hdr, arp_hdr, sizeof(sr_arp_hdr_t));

            int res = sr_send_packet(sr, buf, total_size, sif->name);
            if (res != 0)
            {
                printf("Error: ARP request not sent successfully.\n");
            } else {
                printf("ARP request sent successfully \n");
            }
            arpr->sent = time(NULL);
            arpr->times_sent++;

            /* Free Malloced data*/
            free(eth_hdr);
            free(arp_hdr);
            free(buf);
        }
    }
}

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr)
{
    /* Fill this in */
    /* Fire A request off */

    struct sr_arpreq *curr = sr->cache.requests;

    while (curr)
    {
        handle_arpreq(curr, sr);
        curr = curr->next;
    }

    /* If this request is the sixth attempt, send host unreachable to all trying to contact this one*/
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++)
    {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip))
        {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry)
    {
        copy = (struct sr_arpentry *)malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet, /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next)
    {
        if (req->ip == ip)
        {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req)
    {
        req = (struct sr_arpreq *)calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface)
    {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next)
    {
        if (req->ip == ip)
        {
            if (prev)
            {
                next = req->next;
                prev->next = next;
            }
            else
            {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++)
    {
        if (!(cache->entries[i].valid))
            break;
    }

    if (i != SR_ARPCACHE_SZ)
    {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry)
{
    pthread_mutex_lock(&(cache->lock));

    if (entry)
    {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next)
        {
            if (req == entry)
            {
                if (prev)
                {
                    next = req->next;
                    prev->next = next;
                }
                else
                {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt)
        {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache)
{
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++)
    {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache)
{
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache)
{
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr)
{
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1)
    {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++)
        {
            if ((cache->entries[i].valid) && (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO))
            {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}
