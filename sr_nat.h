
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
    nat_connection_state_syn_sent,
    nat_connection_state_syn_rcvd,
    nat_connection_state_established,
    nat_connection_state_fin_wait_1,
    nat_connection_state_fin_wait_2,
    nat_connection_state_close_wait,
    nat_connection_state_closing,
    nat_connection_state_last_ack
} sr_nat_connection_state;

struct sr_nat_connection {
    /* add TCP connection state data members here */
    sr_nat_connection_state state;
    uint32_t ip_ext;
    uint16_t port_ext;
    time_t last_updated;
    struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_syn_mapping {
    uint8_t *buf;
    unsigned int len;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    time_t received;
    int drop;
    struct sr_syn_mapping *next;
};

#define NAT_INTERFACE_INT "eth1"
#define NAT_INTERFACE_EXT "eth2"
#define NAT_TCP_UNSOLICATED_TIMEOUT 6
#define NAT_AUX_MIN 1050
#define NAT_AUX_MAX 65535

struct sr_nat {
    /* add any fields here */
    int icmp_query_timeout;
    int tcp_established_timeout;
    int tcp_transitory_timeout;
    uint16_t next_icmp_id;
    uint16_t next_tcp_port;
    struct sr_nat_mapping *nat_mappings;
    struct sr_syn_mapping *syn_mappings;

    /* threading */
    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
    pthread_attr_t thread_attr;
    pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


#endif