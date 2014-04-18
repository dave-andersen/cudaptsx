#ifndef __WIN_H
#define __WIN_H

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>


#ifndef __APPLE__
   #include <malloc.h>
#endif

typedef void *LPVOID;
typedef uint32_t *LPDWORD;

typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;
typedef fd_set FD_SET;

typedef void *WSADATA;
#define WSAStartup(a, b)
#define MAKEWORD(a, b) a

#define ADDR_ANY INADDR_ANY
#define SOCKET_ERROR -1

#define strcpy_s(dst, n, src) \
    strncpy((dst), (src), (n))

#define RtlZeroMemory(s, size)\
    memset((s), 0, (size))

#define RtlCopyMemory(dest, src, size)\
    memcpy((dest), (src), (size))



#ifndef __CYGWIN__
#define FIONBIO 0
#endif

#define WSAIoctl(socket, ig1, ig2, ig3, ig4, ig5, ig6, ig7, ig8) \
fcntl(socket, F_SETFL, O_NONBLOCK)

#define WSAGetLastError() errno
#define WSAEWOULDBLOCK EWOULDBLOCK

#define closesocket(fd) close(fd)

typedef struct {
    pthread_mutex_t mutex;
    pthread_mutexattr_t attr;
} CRITICAL_SECTION;

void InitializeCriticalSection(CRITICAL_SECTION *s);

void EnterCriticalSection(CRITICAL_SECTION *s);

void LeaveCriticalSection(CRITICAL_SECTION *s);

typedef void *(*LPTHREAD_START_ROUTINE)(void *);

void CreateThread(LPVOID ig1, size_t ig2, LPTHREAD_START_ROUTINE func, LPVOID arg, uint32_t ig3,  LPDWORD tid);

#ifndef __CYGWIN__
#define __declspec(x) __##x
#endif

#define Sleep(x) usleep(x*1000)

#ifdef __APPLE__
   #define __debugbreak()
#else
   #define __debugbreak() raise(SIGTRAP)
#endif

#define GetTickCount() (uint32) (time(NULL) - 1383638888) * 1000 // A quick hack for time_t overflow


#define _strdup strdup

typedef struct {
    int dwNumberOfProcessors;
} SYSTEM_INFO;

#define GetSystemInfo(ps) \
    (ps)->dwNumberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN)

#define GetCurrentProcess() getpid()

#define BELOW_NORMAL_PRIORITY_CLASS 15

#define SetPriorityClass(pid, priority) \
    nice(priority)

typedef union _LARGE_INTEGER {
  struct {
	uint32_t  LowPart;
    int32_t  HighPart;
  };
  struct {
    uint32_t LowPart;
    int32_t  HighPart;
  } u;
  int64_t QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;
#ifdef __CYGWIN__
char *strdup(const char *str);
#endif
bool QueryPerformanceFrequency(_LARGE_INTEGER *frequency);
bool QueryPerformanceCounter(_LARGE_INTEGER *performance_count);

#endif