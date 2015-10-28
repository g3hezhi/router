#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>

#include "sr_protocol.h"
#include "sr_nat.h"

static void sr_nat_mapping_sweepconns(struct sr_nat *nat, struct sr_nat_mapping *mapping);
static void sr_nat_connection_destroy(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_connection *entry);
static void sr_nat_mapping_destroy(struct sr_nat *nat, struct sr_nat_mapping *entry);
static uint16_t sr_nat_next_aux_ext(struct sr_nat *nat, sr_nat_mapping_type type);

int sr_nat_init(struct sr_nat *nat) {  /* Initializes the nat */

    assert(nat);
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(nat->attr));
    pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(nat->lock), &(nat->attr));
    
    /* Initialize timeout thread */
    
    pthread_attr_init(&(nat->thread_attr));
    pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);
    
    /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */
    
    nat->nat_mappings = NULL;
    /* Initialize any variables here */
    nat->next_icmp_id = NAT_AUX_MIN;
    nat->next_tcp_port = NAT_AUX_MIN;
    
    return success;
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

    pthread_mutex_lock(&(nat->lock));
    
    /* free nat memory here */
    
    pthread_kill(nat->thread, SIGKILL);
    return pthread_mutex_destroy(&(nat->lock)) && pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */

    struct sr_nat *nat = (struct sr_nat *)nat_ptr;
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(nat->lock));
        
        time_t curtime = time(NULL);
        
        /* handle periodic tasks here */
        struct sr_nat_mapping *mapping = NULL;
        struct sr_nat_mapping *next = NULL;
        
        mapping = nat->nat_mappings;
        
        while (mapping) {
            next = mapping->next;
            
            if (mapping->type == nat_mapping_icmp) {
                if (difftime(curtime, mapping->last_updated) > nat->icmp_query_timeout) {
                    sr_nat_mapping_destroy(nat, mapping);
                }
            } else if (mapping->type == nat_mapping_tcp) {
                sr_nat_mapping_sweepconns(nat, mapping);
                
                if (!mapping->conns) {
                    sr_nat_mapping_destroy(nat, mapping);
                }
            }
            
            mapping = next;
        }
        
        pthread_mutex_unlock(&(nat->lock));
    }
    
    return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat, uint16_t aux_ext, sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));
    
    /* handle lookup here, malloc and assign to copy */
    struct sr_nat_mapping *mapping = NULL;
    struct sr_nat_mapping *copy = NULL;
    
    struct sr_nat_mapping *mapping_walker = NULL;
    for (mapping_walker = nat->nat_mappings; mapping_walker != NULL; mapping_walker = mapping_walker->next) {
        if (mapping_walker->aux_ext == aux_ext && mapping_walker->type == type) {
            mapping = mapping_walker;
            break;
        }
    }
    
    if (mapping) {
        mapping->last_updated = time(NULL);
        
        copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
        memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
    }
    
    pthread_mutex_unlock(&(nat->lock));
    
    return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type )
{
    pthread_mutex_lock(&(nat->lock));
    
    /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_mapping *mapping = NULL;
    struct sr_nat_mapping *copy = NULL;
    
    struct sr_nat_mapping *mapping_walker = NULL;
    for (mapping_walker = nat->nat_mappings; mapping_walker != NULL; mapping_walker = mapping_walker->next) {
        if (mapping_walker->ip_int == ip_int && mapping_walker->aux_int == aux_int && mapping_walker->type == type) {
            mapping = mapping_walker;
            break;
        }
    }
    
    if (mapping) {
        mapping->last_updated = time(NULL);
        
        copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
        memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
    }
    
    pthread_mutex_unlock(&(nat->lock));
    
    return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));
    
    /* handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = NULL;
    struct sr_nat_mapping *copy = NULL;
    
    mapping = (struct sr_nat_mapping *)calloc(1, sizeof(struct sr_nat_mapping));
    
    mapping->type = type;
    mapping->ip_int = ip_int;
    mapping->aux_int = aux_int;
    mapping->aux_ext = sr_nat_next_aux_ext(nat, type);
    mapping->last_updated = time(NULL);
    mapping->next = nat->nat_mappings;
    
    nat->nat_mappings = mapping;
    
    copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
    
    pthread_mutex_unlock(&(nat->lock));
    
    return copy;
}

void sr_nat_mapping_sweepconns(struct sr_nat *nat, struct sr_nat_mapping *mapping)
{
    struct sr_nat_connection *conn = NULL;
    struct sr_nat_connection *next = NULL;
    
    conn = mapping->conns;
    
    while (conn) {
        next = conn->next;
        
        switch (conn->state) {
            case nat_connection_state_established:
            case nat_connection_state_fin_wait_1:
            case nat_connection_state_fin_wait_2:
            case nat_connection_state_close_wait: {
                if (conn->last_updated > nat->tcp_established_timeout) {
                    sr_nat_connection_destroy(nat, mapping, conn);
                }
                
                break;
            }
            case nat_connection_state_syn_sent:
            case nat_connection_state_syn_rcvd:
            case nat_connection_state_closing:
            case nat_connection_state_last_ack: {
                if (conn->last_updated > nat->tcp_transitory_timeout) {
                    sr_nat_connection_destroy(nat, mapping, conn);
                }
                
                break;
            }
        }
        
        conn = next;
    }
}

void sr_nat_connection_destroy(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_connection *entry)
{
    pthread_mutex_lock(&(nat->lock));
    
    if (entry) {
        struct sr_nat_connection *conn, *prev = NULL, *next = NULL;
        for (conn = mapping->conns; conn != NULL; conn = conn->next) {
            if (conn == entry) {
                if (prev) {
                    next = conn->next;
                    prev->next = next;
                } else {
                    next = conn->next;
                    mapping->conns = next;
                }
                
                break;
            }
            
            prev = conn;
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(nat->lock));
}

void sr_nat_mapping_destroy(struct sr_nat *nat, struct sr_nat_mapping *entry)
{
    pthread_mutex_lock(&(nat->lock));
    
    if (entry) {
        struct sr_nat_mapping *mapping, *prev = NULL, *next = NULL;
        for (mapping = nat->nat_mappings; mapping != NULL; mapping = mapping->next) {
            if (mapping == entry) {
                if (prev) {
                    next = mapping->next;
                    prev->next = next;
                } else {
                    next = mapping->next;
                    nat->nat_mappings = next;
                }
                
                break;
            }
            
            prev = mapping;
        }
        
        struct sr_nat_connection *conn, *nxt;
        for (conn = entry->conns; conn; conn = nxt) {
            nxt = conn->next;
            free(conn);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(nat->lock));
}

uint16_t sr_nat_next_aux_ext(struct sr_nat *nat, sr_nat_mapping_type type)
{
    uint16_t next_aux_ext = 0;
    
    if (type == nat_mapping_icmp) {
        next_aux_ext = nat->next_icmp_id;
    } else if (type == nat_mapping_tcp) {
        next_aux_ext = nat->next_tcp_port;
    }
    
    struct sr_nat_mapping *mapping_walker = nat->nat_mappings;
    
    while (mapping_walker) {
        if (mapping_walker->aux_ext == htons(next_aux_ext) && mapping_walker->type == type) {
            if (next_aux_ext == NAT_AUX_MAX) {
                next_aux_ext = NAT_AUX_MIN;
            } else {
                next_aux_ext++;
            }
            
            mapping_walker = nat->nat_mappings;
        } else {
            mapping_walker = mapping_walker->next;
        }
    }
    
    if (type == nat_mapping_icmp) {
        if (next_aux_ext == NAT_AUX_MAX) {
            nat->next_icmp_id = NAT_AUX_MIN;
        } else {
            nat->next_icmp_id = next_aux_ext + 1;
        }
    } else if (type == nat_mapping_tcp) {
        if (next_aux_ext == NAT_AUX_MAX) {
            nat->next_tcp_port = NAT_AUX_MIN;
        } else {
            nat->next_tcp_port = next_aux_ext + 1;
        }
    }
    
    return htons(next_aux_ext);
}
