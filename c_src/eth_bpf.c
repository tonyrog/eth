/*
 * Implementation of BPF machine
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "eth_bpf.h"

#define U8(p,i)  (p)[(i)]
#define U16(p,i) (((p)[(i)]<<8) | ((p)[(i)+1]))
#define U32(p,i) (((p)[(i)]<<24) | ((p)[(i)+1]<<16) | \
		  ((p)[(i)+2]<<8) | ((p)[(i)+3]))

#define BPF_CLASS(Code) ((Code) & 0x07)
#define BPF_LD	  0x00
#define BPF_LDX	  0x01
#define BPF_ST	  0x02
#define BPF_STX	  0x03
#define BPF_ALU	  0x04
#define BPF_JMP	  0x05
#define BPF_RET	  0x06
#define BPF_MISC  0x07

// ld/ldx fields
//  <<_:3,Size:2,Class:3>>
#define BPF_SIZE(Code)	((Code) & 0x18)
#define BPF_W 0x00
#define BPF_H 0x08
#define BPF_B 0x10

// <<Mode:3,Size:2,Class:3>>
#define BPF_MODE(Code) ((Code) & 0xe0)
#define BPF_IMM 0x00
#define BPF_ABS 0x20
#define BPF_IND 0x40
#define BPF_MEM 0x60
#define BPF_LEN 0x80
#define BPF_MSH 0xa0

// alu/jmp fields
// <<Mode:4,Src:1,Class:3>>
#define BPF_OP(Code) ((Code) & 0xf0)
#define BPF_ADD 0x00
#define BPF_SUB 0x10
#define BPF_MUL 0x20
#define BPF_DIV 0x30
#define BPF_OR  0x40
#define BPF_AND 0x50
#define BPF_LSH 0x60
#define BPF_RSH 0x70
#define BPF_NEG 0x80
#define BPF_JA  0x00
#define BPF_JEQ 0x10
#define BPF_JGT 0x20
#define BPF_JGE 0x30
#define BPF_JSET 0x40

#define BPF_SRC(Code) ((Code) & 0x08)
#define BPF_K 0x00
#define BPF_X 0x08

// ret - BPF_K and BPF_X also apply
// <<_:3,RVal:2,Class:3>>
#define BPF_RVAL(Code) ((Code) & 0x18)
#define BPF_A 0x10

// misc
// <<Op:1,_:4,Class:3>>
#define BPF_MISCOP(Code) ((Code) & 0xf8)
#define BPF_TAX 0x00
#define BPF_TXA 0x80

#define BPF_MEMWORDS 16

typedef struct _bpf_insn_t {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
} bpf_insn_t;
	
#define ERR(PC,E) do {				\
	*err = (E);				\
	*err_loc = (PC);			\
	return 0;				\
    } while(0)

#define LD(REG,P,L,K,SZ) do {						\
	if ((K)+(SZ) >= (L)) ERR(pc,ETH_BPF_PACKET_INDEX_OUT_OF_RANGE);	\
	switch((SZ)) {							\
	case 1: REG=(P)[(K)]; break;					\
	case 2: REG=((P)[(K)]<<8) | ((P)[(K)+1]); break;		\
	case 4: REG=((P)[(K)]<<24) | ((P)[(K)+1]<<16) |			\
		((P)[(K)+2]<<8) | ((P)[(K)+3]); break;			\
	}								\
    } while(0)

#define LDM(REG,I,M) do {						\
	if ((I) >= BPF_MEMWORDS)					\
	    ERR(pc,ETH_BPF_MEM_INDEX_OUT_OF_RANGE);			\
	REG=(M)[(I)];							\
    } while(0)

#define STM(REG,I,M) do {						\
	if ((I) >= BPF_MEMWORDS)					\
	    ERR(pc,ETH_BPF_MEM_INDEX_OUT_OF_RANGE);			\
	(M)[(I)]=REG;							\
    } while(0)

// list of supported instructions
#define LDAW   (BPF_LD | BPF_ABS | BPF_W)
#define LDAH   (BPF_LD | BPF_ABS | BPF_H)
#define LDAB   (BPF_LD | BPF_ABS | BPF_B)
#define LDIW   (BPF_LD | BPF_IND | BPF_W)
#define LDIH   (BPF_LD | BPF_IND | BPF_H)
#define LDIB   (BPF_LD | BPF_IND | BPF_B)
#define LDL    (BPF_LD | BPF_LEN | BPF_W)
#define LDC    (BPF_LD | BPF_IMM | BPF_W)
#define LDA    (BPF_LD | BPF_MEM | BPF_W)
#define LDXC   (BPF_LDX | BPF_IMM | BPF_W)
#define LDX    (BPF_LDX | BPF_MEM | BPF_W)
#define LDXL   (BPF_LDX | BPF_LEN | BPF_W)
#define LDXMSH (BPF_LDX | BPF_MSH | BPF_B) // should be BPF_B?
#define STA    (BPF_ST)   // other fields?
#define STX    (BPF_STX)  // other fields?
#define ADDK   (BPF_ALU | BPF_ADD | BPF_K)
#define SUBK   (BPF_ALU | BPF_SUB | BPF_K)
#define MULK   (BPF_ALU | BPF_MUL | BPF_K)
#define DIVK   (BPF_ALU | BPF_DIV | BPF_K)
#define ORK    (BPF_ALU | BPF_OR | BPF_K)
#define ANDK   (BPF_ALU | BPF_AND | BPF_K)
#define LSHK   (BPF_ALU | BPF_LSH | BPF_K)
#define RSHK   (BPF_ALU | BPF_RSH | BPF_K)
#define ADDX   (BPF_ALU | BPF_ADD | BPF_X)
#define SUBX   (BPF_ALU | BPF_SUB | BPF_X)
#define MULX   (BPF_ALU | BPF_MUL | BPF_X)
#define DIVX   (BPF_ALU | BPF_DIV | BPF_X)
#define ORX    (BPF_ALU | BPF_OR | BPF_X)
#define ANDX   (BPF_ALU | BPF_AND | BPF_X)
#define LSHX   (BPF_ALU | BPF_LSH | BPF_X)
#define RSHX   (BPF_ALU | BPF_RSH | BPF_X)
#define NEG    (BPF_ALU | BPF_NEG )
#define JMP    (BPF_JMP | BPF_JA | BPF_K)
#define JGTK   (BPF_JMP | BPF_JGT | BPF_K)
#define JGEK   (BPF_JMP | BPF_JGE | BPF_K)
#define JEQK   (BPF_JMP | BPF_JEQ | BPF_K)
#define JSETK  (BPF_JMP | BPF_JSET | BPF_K)
#define JGTX   (BPF_JMP | BPF_JGT | BPF_X)
#define JGEX   (BPF_JMP | BPF_JGE | BPF_X)
#define JEQX   (BPF_JMP | BPF_JEQ | BPF_X)
#define JSETX  (BPF_JMP | BPF_JSET | BPF_X)
#define RETA   (BPF_RET | BPF_A)
#define RETK   (BPF_RET | BPF_K)
#define TAX    (BPF_MISC | BPF_TAX)
#define TXA    (BPF_MISC | BPF_TXA)

char* eth_bpf_strerr(int err)
{
    switch(err) {
    case ETH_BPF_OK:
	return "ok";
    case ETH_BPF_PC_OUT_OF_RANGE:
	return "pc out of range";
    case ETH_BPF_PACKET_INDEX_OUT_OF_RANGE:
	return "packet index out of range";
    case ETH_BPF_MEM_INDEX_OUT_OF_RANGE:
	return "memory index out of range";
    case ETH_BPF_UNKNOWN_INSTRUCTION:
	return "unknown intruction";
    case ETH_BPF_DIVISION_BY_ZERO:
	return "division by zero";
    case ETH_BPF_INVALID_ARGUMENT:
	return "invalid argument";
    case ETH_BPF_LOOP_DETECTED:
	return "loop detected";
    default:
	return "unknown error";
    }
}

// check if j+1+k >= n
static int inline jump_out_of_range(uint32_t j, uint32_t k, uint32_t n)
{
    uint32_t a = j;
    a += k;
    if (a < k) return 1;  // wrapped
    a += 1;
    if (a < 1) return 1;  // wrapped
    if (a >= n) return 1;
    return 0;
}

// validate program in src and and write native endian in dst
// n is the number of instruction each of size 8
// if dst == NULL the program is not updated just check 
uint32_t eth_bpf_validate(uint8_t* src, uint8_t* dst, size_t n, 
			  int* err, uint32_t* err_loc)
{
    int i;
    uint32_t pc;
    uint32_t len = n << 3;
    bpf_insn_t* di;

    if ((((uintptr_t) dst) & 0x3) != 0)
	ERR(0,ETH_BPF_INVALID_ARGUMENT);
    di = (bpf_insn_t*) dst;
    for (i = 0, pc = 0; i < len; i += 8, pc++) {
	uint16_t code = U16(src,i);
	uint8_t  jt   = U8(src,i+2);
	uint8_t  jf   = U8(src,i+3);
	uint32_t k    = U32(src,i+4);

	printf("validate: %d: code=%x,jt=%u,jf=%u,k=%u\r\n", pc, code,jt,jf,k);
	       
	switch(code) {
	case LDAW: break;
	case LDAH: break;
	case LDAB: break;
	case LDIW: break;
	case LDIH: break;
	case LDIB: break;
	case LDL:  break;
	case LDC:  break;
	case LDXC: break;
	case LDXL: break;
	case LDXMSH: break;
	case LDA: case LDX: case STA: case STX:
	    if (k >= BPF_MEMWORDS)
		ERR(pc,ETH_BPF_MEM_INDEX_OUT_OF_RANGE);
	    break;
	case ADDK: break;
	case SUBK: break;
	case MULK: break;
	case DIVK: if (k == 0) ERR(pc,ETH_BPF_DIVISION_BY_ZERO); break;
	case ANDK: break;
	case ORK:  break;  
	case LSHK: break;
	case RSHK: break;
	case ADDX: break;
	case SUBX: break;
	case MULX: break;
	case DIVX: break;
	case ANDX: break;
	case ORX:  break;
	case LSHX: break;
	case RSHX: break;
	case NEG:  break;
	case JMP:
	    if (jump_out_of_range(pc, k, n))
		ERR(pc,ETH_BPF_PC_OUT_OF_RANGE); 
	    break;
	case JGTK: 
	case JGEK:
	case JEQK:
	case JSETK:
	case JGTX:
	case JGEX:
	case JEQX:
	case JSETX:
	    if (jump_out_of_range(pc, jt, n) ||
		jump_out_of_range(pc, jf, n))
		ERR(pc,ETH_BPF_PC_OUT_OF_RANGE); 
	    break;
	case RETA: break;
	case RETK: break;
	case TAX:  break;
	case TXA:  break;
	default: ERR(pc,ETH_BPF_UNKNOWN_INSTRUCTION);
	}
	if (di != NULL) {
	    di->code = code;
	    di->jt   = jt;
	    di->jf   = jf;
	    di->k    = k;
	    di++;
	}
    }
    *err = ETH_BPF_OK;
    return 1;
}

// validate must have been run before this call!
uint32_t eth_bpf_exec(uint8_t* ptr, size_t n, uint8_t* p, uint32_t len,
		      int* err, uint32_t* err_loc)
{
    bpf_insn_t* insns = (bpf_insn_t*) ptr;
    register uint32_t pc = 0;
    register uint32_t a;
    register uint32_t x;
    uint32_t mem[BPF_MEMWORDS];

    *err = ETH_BPF_OK;
    if ((ptr == NULL) || (n == 0))
	return (uint32_t) -1;

    while(n--) {  // n make sure we never get stuck
	uint32_t k;
	bpf_insn_t* i;
	i = &insns[pc++];
	k = i->k;
	switch(i->code) {
	case LDAW: LD(a,p,len,k,4);   break;
	case LDAH: LD(a,p,len,k,2);   break;
	case LDAB: LD(a,p,len,k,1);   break;
	case LDIW: LD(a,p,len,x+k,4); break;
	case LDIH: LD(a,p,len,x+k,2); break;
	case LDIB: LD(a,p,len,x+k,1); break;
	case LDL:  a=len;  break;
	case LDC:  a=k;    break;
	case LDA:  LDM(a,k,mem); break;
	case LDXC: x=k; break;
	case LDX:  LDM(x,k,mem); break;
	case LDXL: x=len; break;
	case LDXMSH: LD(x,p,len,k,1); x = 4*(x & 0xf); break;
	case STA:  STM(a,k,mem); break;
	case STX:  STM(x,k,mem); break;
	case ADDK: a += k; break;
	case SUBK: a -= k; break;
	case MULK: a *= k; break;
	case DIVK: a /= k; break;
	case ANDK: a &= k; break;
	case ORK:  a |= k; break;  
	case LSHK: a <<= k; break;
	case RSHK: a >>= k; break;
	case ADDX: a += x; break;
	case SUBX: a -= x; break;
	case MULX: a *= x; break;
	case DIVX: if (x == 0) ERR(pc,ETH_BPF_DIVISION_BY_ZERO);
	    a /= x; break;
	case ANDX:  a &= x; break;
	case ORX:   a |= x; break;
	case LSHX:  a <<= x; break;
	case RSHX:  a >>= x; break;
	case NEG:   a = -a; break;
	case JMP:   pc += k; break;
	case JGTK:  pc += (a > k) ? i->jt : i->jf;  break;
	case JGEK:  pc += (a >= k) ? i->jt : i->jf; break;
	case JEQK:  pc += (a == k) ? i->jt : i->jf; break;
	case JSETK: pc += (a & k) ? i->jt : i->jf; break;
	case JGTX:  pc += (a > x) ? i->jt : i->jf; break;
	case JGEX:  pc += (a >= x) ? i->jt : i->jf; break;
	case JEQX:  pc += (a == x) ? i->jt : i->jf; break;
	case JSETX: pc += (a & x) ? i->jt : i->jf; break;
	case RETA: return a;
	case RETK: return k;
	case TAX:  x=a; break;
	case TXA:  a=x; break;
	default: ERR(pc,ETH_BPF_UNKNOWN_INSTRUCTION);
	}
    }
    ERR(pc,ETH_BPF_LOOP_DETECTED);
}
