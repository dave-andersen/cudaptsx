#ifndef _SHABITS_H_
#define _SHABITS_H_

#define SWAP64(n) \
  (((n) << 56)                                        \
   | (((n) & 0xff00) << 40)                        \
   | (((n) & 0xff0000) << 24)                        \
   | (((n) & 0xff000000) << 8)                        \
   | (((n) >> 8) & 0xff000000)                        \
   | (((n) >> 24) & 0xff0000)                        \
   | (((n) >> 40) & 0xff00)                        \
   | ((n) >> 56))



#endif /* _SHABITS_H_ */
