#include"global.h"
#include "gpuhash.h"
#include "sha512.h"

#define SEARCH_SPACE_BITS		50
#define BIRTHDAYS_PER_HASH		8

thread_local uint32* __collisionMap = NULL;
thread_local uint64* __hashblock = NULL;
thread_local GPUHasher *__gpu = NULL;

bool protoshares_revalidateCollision(minerProtosharesBlock_t* block, uint8* midHash, uint32 indexA, uint32 indexB)
{
	uint8 tempHash[32+4];
	uint64 resultHash[8];
	memcpy(tempHash+4, midHash, 32);
	// get birthday A
	*(uint32*)tempHash = indexA&~7;
	sha512_ctx c512;
	sha512_init(&c512);
	sha512_update(&c512, tempHash, 32+4);
	sha512_final(&c512, (unsigned char*)resultHash);
	uint64 birthdayA = resultHash[indexA&7] >> (64ULL-SEARCH_SPACE_BITS);
	// get birthday B
	*(uint32*)tempHash = indexB&~7;
	sha512_init(&c512);
	sha512_update(&c512, tempHash, 32+4);
	sha512_final(&c512, (unsigned char*)resultHash);
	uint64 birthdayB = resultHash[indexB&7] >> (64ULL-SEARCH_SPACE_BITS);
	if( birthdayA != birthdayB )
	{
	  printf("Invalid collision\n");
		return false; // invalid collision
	}
	// birthday collision found
	totalCollisionCount += 2; // we can use every collision twice -> A B and B A
	//printf("Collision found %8d = %8d | num: %d\n", indexA, indexB, totalCollisionCount);
	// get full block hash (for A B)
	block->birthdayA = indexA;
	block->birthdayB = indexB;
	uint8 proofOfWorkHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80+8);
	sha256_final(&c256, proofOfWorkHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)proofOfWorkHash, 32);
	sha256_final(&c256, proofOfWorkHash);
	bool hashMeetsTarget = true;
	uint32* generatedHash32 = (uint32*)proofOfWorkHash;
	uint32* targetHash32 = (uint32*)block->targetShare;
	for(sint32 hc=7; hc>=0; hc--)
	{
		if( generatedHash32[hc] < targetHash32[hc] )
		{
			hashMeetsTarget = true;
			break;
		}
		else if( generatedHash32[hc] > targetHash32[hc] )
		{
			hashMeetsTarget = false;
			break;
		}
	}
	if( hashMeetsTarget )
	{
		//printf("[DEBUG] Submit Protoshares share\n");
		totalShareCount++;
		xptMiner_submitShare(block);
	}
	// get full block hash (for B A)
	block->birthdayA = indexB;
	block->birthdayB = indexA;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80+8);
	sha256_final(&c256, proofOfWorkHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)proofOfWorkHash, 32);
	sha256_final(&c256, proofOfWorkHash);
	hashMeetsTarget = true;
	generatedHash32 = (uint32*)proofOfWorkHash;
	targetHash32 = (uint32*)block->targetShare;
	for(sint32 hc=7; hc>=0; hc--)
	{
		if( generatedHash32[hc] < targetHash32[hc] )
		{
			hashMeetsTarget = true;
			break;
		}
		else if( generatedHash32[hc] > targetHash32[hc] )
		{
			hashMeetsTarget = false;
			break;
		}
	}
	if( hashMeetsTarget )
	{
		// printf("[DEBUG] Submit Protoshares share\n");
		totalShareCount++;
		xptMiner_submitShare(block);
	}
	return true;
}

#include "defs.h"
#include "shabits.h"


void set_or_double(uint32_t *countbits, uint32_t whichbit) {
  /* Saturating unary counter with overflow bit.  
   * First set is 00 -> 01.  Second set is 01 -> 11
   * Beyond that stays 11
   */
  uint32_t whichword = whichbit/16;
  uint32_t old = countbits[whichword];
  uint32_t bitpat = 1UL << (2*(whichbit%16));
  /* When in doubt for further optimizations, try getting rid of
   * conditionals! :-)  
   * (set 2nd bit of pair if 1st already set, 1st otherwise) */
  countbits[whichword] = old | (bitpat + (old&bitpat));
}

inline
void add_to_filter(uint32_t *countbits, const uint64_t hash) {
  uint32_t whichbit = (uint32_t(hash) & ((1UL<<COUNTBITS_SLOTS_POWER)-1));
  set_or_double(countbits, whichbit);
}

inline
bool is_in_filter_twice(const uint32_t *countbits, const uint64_t hash) {
  uint32_t whichbit = (uint32_t(hash) & ((1UL<<COUNTBITS_SLOTS_POWER)-1));
  uint32_t cbits = countbits[whichbit/16];
  return (cbits & (2UL<<(((whichbit&0xf)<<1))));
}

void
reset_filter(uint32_t *countbits) {
  size_t cbitsize = (1<<(COUNTBITS_SLOTS_POWER-2));
  memset(countbits, 0x00, cbitsize);
}

pthread_mutex_t gpu_lock = PTHREAD_MUTEX_INITIALIZER;
int gpu_count = 0; /* Global guarded by gpu_lock */

int get_gpu_id() {
  int g;
  pthread_mutex_lock(&gpu_lock);
  //if (gpu_count == 2) gpu_count++; /* XXX hack */
  g = gpu_count;
  gpu_count++;
  pthread_mutex_unlock(&gpu_lock);
  return g;
}


void protoshares_process_512(minerProtosharesBlock_t* block)
{
	// generate mid hash using sha256 (header hash)
	uint8 midHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	uint8 midHash_saved[32];
	for (int i = 0; i < 32; i++) {
	  midHash_saved[i] = midHash[i];
	}
	// init collision map
	if( __collisionMap == NULL )
	  __collisionMap = (uint32*)malloc(sizeof(uint32)*(1<<(COUNTBITS_SLOTS_POWER+1-2)));
	uint32* collisiontable = __collisionMap;
	
	if (__hashblock == NULL) {
	  __hashblock = (uint64*) malloc(sizeof(uint64) * GPUHasher::N_RESULTS*2);
	  printf("Allocated hashblock with %d slots\n", GPUHasher::N_RESULTS*2);
	}
	uint64* hashblock = __hashblock;

	if (__gpu == NULL) {
	  __gpu = new GPUHasher(get_gpu_id()); /* XXX */
	  __gpu->Initialize();
	}

	uint8 tempHash[32+4];
	memcpy(tempHash+4, midHash, 32);

	SHA512_Context c512;
  
	SHA512_Init(&c512);
	SHA512_Update_Simple(&c512, tempHash, 32+4);
	SHA512_PreFinal(&c512);

	*(uint32_t *)(&c512.buffer.bytes[0]) = 0;

	__gpu->ComputeHashes((uint64_t *)c512.buffer.bytes, (uint64_t *)hashblock);



	uint32_t n_hashes_plus_one = *((uint32_t *)hashblock);
  //printf("NHP1: %d\n", n_hashes_plus_one);


  uint32_t n_starting = n_hashes_plus_one-1;

  for (uint32_t filter_pass = 1; filter_pass <= 3; filter_pass++) {
    reset_filter(collisiontable);
    for (uint32_t i = 0; i < n_starting; i++) {
      uint64_t birthday = hashblock[1+i*2] * 0x9ddfea08eb382d69ULL; /* murmur */
      add_to_filter(collisiontable, birthday>>(filter_pass*13));
    }
    uint32_t n_remaining = 0;
    for (uint32_t i = 0; i < n_starting; i++) {
      uint64_t birthday = hashblock[1+i*2] * 0x9ddfea08eb382d69ULL; /* murmur */
      if (is_in_filter_twice(collisiontable, birthday>>(filter_pass*13))) {
	hashblock[1+n_remaining*2] = hashblock[1+i*2];
	hashblock[1+n_remaining*2+1] = hashblock[1+i*2+1];
	n_remaining++;
      }
    }
    n_starting = n_remaining;
  }

  if (n_starting == 0) { return; }
  /* n squared but n is small. :) */
  for (uint32_t i = 0; i < n_starting; i++) {
    if (hashblock[1+i*2] == 0) { continue; }
    for (uint32_t j = i+1; j < n_starting; j++) {
      if (hashblock[1+j*2] == 0) { continue; }
      if (hashblock[1+i*2] == hashblock[1+j*2]) {
	uint32_t mine = hashblock[1+i*2+1];
	uint32_t other = hashblock[1+j*2+1];
	//printf("revalidating %d %d\n", other, mine);
	protoshares_revalidateCollision(block, midHash_saved, mine, other);
	hashblock[1+j*2] = 0;
      }
    }
  }
}

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(26)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

void protoshares_process_256(minerProtosharesBlock_t* block)
{
  printf("process 256\n");
	// generate mid hash using sha256 (header hash)
	uint8 midHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	// init collision map
	if( __collisionMap == NULL )
		__collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
	uint32* collisionIndices = __collisionMap;
	memset(collisionIndices, 0x00, sizeof(uint32)*COLLISION_TABLE_SIZE);
	// start search
	uint8 tempHash[32+4];
	sha512_ctx c512;
	uint64 resultHashStorage[8*CACHED_HASHES];
	memcpy(tempHash+4, midHash, 32);

	for(uint32 n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH * CACHED_HASHES)
	{
		if( block->height != monitorCurrentBlockHeight )
			break;
		for(uint32 m=0; m<CACHED_HASHES; m++)
		{
			sha512_init(&c512);
			*(uint32*)tempHash = n+m*8;
			sha512_update_final(&c512, tempHash, 32+4, (unsigned char*)(resultHashStorage+8*m));
		}
		for(uint32 m=0; m<CACHED_HASHES; m++)
		{
			uint64* resultHash = resultHashStorage + 8*m;
			uint32 i = n + m*8;

			for(uint32 f=0; f<8; f++)
			{
				uint64 birthday = resultHash[f] >> (64ULL-SEARCH_SPACE_BITS);
				uint32 collisionKey = (uint32)((birthday>>18) & COLLISION_KEY_MASK);
				birthday %= COLLISION_TABLE_SIZE;
				if( collisionIndices[birthday] )
				{
					if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) != collisionKey) || protoshares_revalidateCollision(block, midHash, collisionIndices[birthday]&~COLLISION_KEY_MASK, i+f) == false )
					{
						// invalid collision -> ignore
						
					}
				}
				collisionIndices[birthday] = i+f | collisionKey; // we have 6 bits available for validation
			}
		}
	}
}

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(25)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

void protoshares_process_128(minerProtosharesBlock_t* block)
{
	// generate mid hash using sha256 (header hash)
	uint8 midHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	// init collision map
	if( __collisionMap == NULL )
		__collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
	uint32* collisionIndices = __collisionMap;
	memset(collisionIndices, 0x00, sizeof(uint32)*COLLISION_TABLE_SIZE);
	// start search
	// uint8 midHash[64];
	uint8 tempHash[32+4];
	sha512_ctx c512;
	uint64 resultHashStorage[8*CACHED_HASHES];
	memcpy(tempHash+4, midHash, 32);
	for(uint32 n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH * CACHED_HASHES)
	{
		if( block->height != monitorCurrentBlockHeight )
			break;
		for(uint32 m=0; m<CACHED_HASHES; m++)
		{
			sha512_init(&c512);
			*(uint32*)tempHash = n+m*8;
			sha512_update_final(&c512, tempHash, 32+4, (unsigned char*)(resultHashStorage+8*m));
		}
		for(uint32 m=0; m<CACHED_HASHES; m++)
		{
			uint64* resultHash = resultHashStorage + 8*m;
			uint32 i = n + m*8;
			for(uint32 f=0; f<8; f++)
			{
				uint64 birthday = resultHash[f] >> (64ULL-SEARCH_SPACE_BITS);
				uint32 collisionKey = (uint32)((birthday>>18) & COLLISION_KEY_MASK);
				birthday %= COLLISION_TABLE_SIZE;
				if( collisionIndices[birthday] )
				{
					if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) != collisionKey) || protoshares_revalidateCollision(block, midHash, collisionIndices[birthday]&~COLLISION_KEY_MASK, i+f) == false )
					{
						// invalid collision -> ignore
						
					}
				}
				collisionIndices[birthday] = i+f | collisionKey; // we have 6 bits available for validation
			}
		}
	}
}

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(23)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

void protoshares_process_32(minerProtosharesBlock_t* block)
{
	// generate mid hash using sha256 (header hash)
	uint8 midHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	// init collision map
	if( __collisionMap == NULL )
		__collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
	uint32* collisionIndices = __collisionMap;
	memset(collisionIndices, 0x00, sizeof(uint32)*COLLISION_TABLE_SIZE);
	// start search
	// uint8 midHash[64];
	uint8 tempHash[32+4];
	sha512_ctx c512;
	uint64 resultHashStorage[8*CACHED_HASHES];
	memcpy(tempHash+4, midHash, 32);
	for(uint32 n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH * CACHED_HASHES)
	{
		if( block->height != monitorCurrentBlockHeight )
			break;
		for(uint32 m=0; m<CACHED_HASHES; m++)
		{
			sha512_init(&c512);
			*(uint32*)tempHash = n+m*8;
			sha512_update_final(&c512, tempHash, 32+4, (unsigned char*)(resultHashStorage+8*m));
		}
		for(uint32 m=0; m<CACHED_HASHES; m++)
		{
			uint64* resultHash = resultHashStorage + 8*m;
			uint32 i = n + m*8;

			for(uint32 f=0; f<8; f++)
			{
				uint64 birthday = resultHash[f] >> (64ULL-SEARCH_SPACE_BITS);
				uint32 collisionKey = (uint32)((birthday>>18) & COLLISION_KEY_MASK);
				birthday %= COLLISION_TABLE_SIZE;
				if( collisionIndices[birthday] )
				{
					if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) != collisionKey) || protoshares_revalidateCollision(block, midHash, collisionIndices[birthday]&~COLLISION_KEY_MASK, i+f) == false )
					{
						// invalid collision -> ignore
						
					}
				}
				collisionIndices[birthday] = i+f | collisionKey; // we have 6 bits available for validation
			}
		}
	}
}

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(21)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

void protoshares_process_8(minerProtosharesBlock_t* block)
{
	// generate mid hash using sha256 (header hash)
	uint8 midHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	// init collision map
	if( __collisionMap == NULL )
		__collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
	uint32* collisionIndices = __collisionMap;
	memset(collisionIndices, 0x00, sizeof(uint32)*COLLISION_TABLE_SIZE);
	// start search
	// uint8 midHash[64];
	uint8 tempHash[32+4];
	sha512_ctx c512;
	uint64 resultHashStorage[8*CACHED_HASHES];
	memcpy(tempHash+4, midHash, 32);
	for(uint32 n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH * CACHED_HASHES)
	{
		if( block->height != monitorCurrentBlockHeight )
			break;
		for(uint32 m=0; m<CACHED_HASHES; m++)
		{
			sha512_init(&c512);
			*(uint32*)tempHash = n+m*8;
			sha512_update_final(&c512, tempHash, 32+4, (unsigned char*)(resultHashStorage+8*m));
		}
		for(uint32 m=0; m<CACHED_HASHES; m++)
		{
			uint64* resultHash = resultHashStorage + 8*m;
			uint32 i = n + m*8;

			for(uint32 f=0; f<8; f++)
			{
				uint64 birthday = resultHash[f] >> (64ULL-SEARCH_SPACE_BITS);
				uint32 collisionKey = (uint32)((birthday>>18) & COLLISION_KEY_MASK);
				birthday %= COLLISION_TABLE_SIZE;
				if( collisionIndices[birthday] )
				{
					if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) != collisionKey) || protoshares_revalidateCollision(block, midHash, collisionIndices[birthday]&~COLLISION_KEY_MASK, i+f) == false )
					{
						// invalid collision -> ignore
						
					}
				}
				collisionIndices[birthday] = i+f | collisionKey; // we have 6 bits available for validation
			}
		}
	}
}
