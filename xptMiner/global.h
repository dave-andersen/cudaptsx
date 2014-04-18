
#ifndef __INCLUDE_GLOBAL_H__
#define __INCLUDE_GLOBAL_H__
#include <algorithm>
#include <string.h>
#include <cstring>



#if defined(_WIN32) && !defined(__CYGWIN__)
#define NOMINMAX
#pragma comment(lib,"Ws2_32.lib")
#include<winsock2.h>
#include<ws2tcpip.h>
#include"mpir/mpir.h"
typedef __int64           sint64;
typedef unsigned __int64  uint64;
typedef __int32           sint32;
typedef unsigned __int32  uint32;
typedef __int16           sint16;
typedef unsigned __int16  uint16;
//typedef __int8            sint8;
//typedef unsigned __int8   uint8;

//typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

#if defined(__MINGW32__)
#define Sleep(x) usleep(x*1000)
#include<unistd.h>
#endif

#elif defined(__CYGWIN__)
#include"win.h" // port from windows
#include"mpir/mpir.h"
#else
#include"win.h" // port from windows

#ifndef USE_MPIR
#include <gmpxx.h>
#include <gmp.h>
#else
#include <mpirxx.h>
#include <mpir.h>
#endif
#endif

#ifndef thread_local
# if __STDC_VERSION__ >= 201112 && !defined __STDC_NO_THREADS__
#  define thread_local _Thread_local
# elif defined _WIN32 && ( \
       defined _MSC_VER || \
       defined __ICL || \
       defined __DMC__ || \
       defined __BORLANDC__ )
#  define thread_local __declspec(thread) 
/* note that ICC (linux) and Clang are covered by __GNUC__ */
# elif defined __GNUC__ || \
       defined __SUNPRO_C || \
       defined __xlC__
#  define thread_local __thread
# else
#  error "Cannot define thread_local"
# endif
#endif
#if defined(_MSC_VER)
#define _ALIGNED(x) __declspec(align(x))
#else
#if defined(__GNUC__)
#define _ALIGNED(x) __attribute__ ((aligned(x)))
#endif
#endif
#define _ALIGNED_TYPE(t,x) typedef t _ALIGNED(x)

#include<stdio.h>
#include<time.h>
#include<stdlib.h>
#include<set>

#include <iomanip>
#include"sha2.h"

#include"jhlib.h" // slim version of jh library

#include"openCL.h"

// connection info for xpt
typedef struct  
{
	char* ip;
	uint16 port;
	char* authUser;
	char* authPass;
	float donationPercent;
}generalRequestTarget_t;

#include"xptServer.h"
#include"xptClient.h"

#include"sha2.h"
#include"sph_keccak.h"
#include"sph_metis.h"
#include"sph_shavite.h"

#include"transaction.h"

// global settings for miner
typedef struct  
{
	generalRequestTarget_t requestTarget;
	uint32 protoshareMemoryMode;
	// GPU
	bool useGPU; // enable OpenCL
	// GPU (MaxCoin specific)

	float donationPercent;
}minerSettings_t;

extern minerSettings_t minerSettings;

#define PROTOSHARE_MEM_512		(0)
#define PROTOSHARE_MEM_256		(1)
#define PROTOSHARE_MEM_128		(2)
#define PROTOSHARE_MEM_32		(3)
#define PROTOSHARE_MEM_8		(4)

// block data struct

typedef struct  
{
	// block header data (relevant for midhash)
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	// birthday collision
	uint32	birthdayA;
	uint32	birthdayB;
	uint32	uniqueMerkleSeed;

	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
}minerProtosharesBlock_t;

typedef struct  
{
	// block header data
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	uint32	uniqueMerkleSeed;
	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
}minerScryptBlock_t;

typedef struct  
{
	// block header data
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	uint32	uniqueMerkleSeed;
	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
	// found chain data
	// todo
}minerPrimecoinBlock_t;

typedef struct  
{
	// block data (order and memory layout is important)
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	// remaining data
	uint32	uniqueMerkleSeed;
	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
}minerMetiscoinBlock_t; // identical to scryptBlock

typedef struct  
{
	// block data (order and memory layout is important)
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	// remaining data
	uint32	uniqueMerkleSeed;
	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
}minerMaxcoinBlock_t; // identical to scryptBlock


typedef struct  
{
	// block data (order and memory layout is important)
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nBits; // Riecoin has order of nBits and nTime exchanged
	uint64	nTime; // Riecoin has 64bit timestamps
	uint8	nOffset[32];
	// remaining data
	uint32	uniqueMerkleSeed;
	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	// uint8	target[32];
	// uint8	targetShare[32];
	// compact target
	uint32  targetCompact;
	uint32  shareTargetCompact;
}minerRiecoinBlock_t;

typedef struct
{
	uint32 ricPrimeTestsInitial;
	uint32 ricPrimeTestsUpper;
	uint32 ricUpperSteps;
	bool ricStepMethod;
}riecoinOptions_t;

#include"scrypt.h"
#include"algorithm.h"
#include"openCL.h"

void xptMiner_submitShare(minerProtosharesBlock_t* block);
void xptMiner_submitShare(minerScryptBlock_t* block);
void xptMiner_submitShare(minerPrimecoinBlock_t* block);
void xptMiner_submitShare(minerMetiscoinBlock_t* block);
void xptMiner_submitShare(minerMaxcoinBlock_t* block);
void xptMiner_submitShare(minerRiecoinBlock_t* block, uint8* nOffset);

// stats
extern volatile uint32 totalCollisionCount;
extern volatile uint32 totalShareCount;
extern volatile uint32 totalRejectedShareCount;
extern volatile uint32 total2ChainCount;
extern volatile uint32 total3ChainCount;
extern volatile uint32 total4ChainCount;


extern volatile uint32 monitorCurrentBlockHeight;
extern volatile uint32 monitorCurrentBlockTime;

#endif