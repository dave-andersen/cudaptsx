#ifndef _DEFS_H_
#define _DEFS_H_

/* Protoshares looks for a 50-bit collision using 2^26 trials */
#define MOMENTUM_BITS  50
#define NONCE_BITS 26
/* It creates 8 64-bit (reduced to 50) "birthday" values from each
 * 512-bit SHA512 */
#define BIRTHDAYS_PER_HASH 8

/* These parameters control the bucketization of output hashes
 * and the size of the filter table used for duplicate detection.
 * The output is sharded into 2^PARTITION_BITS partitions.
 * each filter is a 2-bit-per-entry data structure of
 * 2^COUNTBITS_SLOTS_POWER entries */

#define COUNTBITS_SLOTS_POWER 19 /* 2^20 bits = 128KB, fits in L2 */
/* The number of partitions balances cache and TLB pressure on output with
 * the size of the filter table needed.  10/19 is a nice balance because
 * an effective filter still fits in L2.  More partitions hurts the TLB on writes */
#define PARTITION_BITS 10 


#define MAX_MOMENTUM_NONCE (1<<NONCE_BITS) // 67.108.864
#define HASH_MASK ((1ULL<<(64-NONCE_BITS))-1)
#define NUM_PARTITIONS (1<<(PARTITION_BITS))

#endif /* _DEFS_H_ */
