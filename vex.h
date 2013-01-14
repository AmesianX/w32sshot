#ifndef VEX_H
#define VEX_H
#include <stdint.h>

#define VEX_GUEST_X86_GDT_NENT	8192
#define VEX_GUEST_X86_LDT_NENT	8192

typedef uint8_t		UChar;
typedef uint16_t	UShort;
typedef uint32_t	UInt;
typedef uint64_t	HWord;
typedef uint64_t	ULong;
struct U128 { char v[16]; };
#pragma pack(1)
struct VexGuestX86State {
      /* Event check fail addr and counter. */
      UInt  host_EvC_FAILADDR; /* 0 */
      UInt  host_EvC_COUNTER;  /* 4 */
      UInt  guest_EAX;         /* 8 */
      UInt  guest_ECX;
      UInt  guest_EDX;
      UInt  guest_EBX;
      UInt  guest_ESP;
      UInt  guest_EBP;
      UInt  guest_ESI;
      UInt  guest_EDI;         /* 36 */

      /* 4-word thunk used to calculate O S Z A C P flags. */
      UInt  guest_CC_OP;       /* 40 */
      UInt  guest_CC_DEP1;
      UInt  guest_CC_DEP2;
      UInt  guest_CC_NDEP;     /* 52 */
      /* The D flag is stored here, encoded as either -1 or +1 */
      UInt  guest_DFLAG;       /* 56 */
      /* Bit 21 (ID) of eflags stored here, as either 0 or 1. */
      UInt  guest_IDFLAG;      /* 60 */
      /* Bit 18 (AC) of eflags stored here, as either 0 or 1. */
      UInt  guest_ACFLAG;      /* 64 */

      /* EIP */
      UInt  guest_EIP;         /* 68 */

      /* FPU */
      ULong guest_FPREG[8];    /* 72 */
      UChar guest_FPTAG[8];   /* 136 */
      UInt  guest_FPROUND;    /* 144 */
      UInt  guest_FC3210;     /* 148 */
      UInt  guest_FTOP;       /* 152 */

      /* SSE */
      UInt  guest_SSEROUND;   /* 156 */
      U128  guest_XMM0;       /* 160 */
      U128  guest_XMM1;
      U128  guest_XMM2;
      U128  guest_XMM3;
      U128  guest_XMM4;
      U128  guest_XMM5;
      U128  guest_XMM6;
      U128  guest_XMM7;

      /* Segment registers. */
      UShort guest_CS;
      UShort guest_DS;
      UShort guest_ES;
      UShort guest_FS;
      UShort guest_GS;
      UShort guest_SS;
      /* LDT/GDT stuff. */
      HWord  guest_LDT; /* host addr, a VexGuestX86SegDescr* */
      HWord  guest_GDT; /* host addr, a VexGuestX86SegDescr* */

      /* Emulation warnings */
      UInt   guest_EMWARN;

      /* For clflush: record start and length of area to invalidate */
      UInt guest_TISTART;
      UInt guest_TILEN;

      /* Used to record the unredirected guest address at the start of
         a translation whose start has been redirected.  By reading
         this pseudo-register shortly afterwards, the translation can
         find out what the corresponding no-redirection address was.
         Note, this is only set for wrap-style redirects, not for
         replace-style ones. */
      UInt guest_NRADDR;

      /* Used for Darwin syscall dispatching. */
      UInt guest_SC_CLASS;

      /* Needed for Darwin (but mandated for all guest architectures):
         EIP at the last syscall insn (int 0x80/81/82, sysenter,
         syscall).  Used when backing up to restart a syscall that has
         been interrupted by a signal. */
      UInt guest_IP_AT_SYSCALL;

      /* Padding to make it have an 32-aligned size */
      UInt padding[5];
      char	x;
};
#pragma pack()

#endif
