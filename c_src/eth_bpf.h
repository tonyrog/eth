/*
 *  Some bpf defintions
 */

#ifndef __ETH_BPF_H__
#define __ETH_BPF_H__

#define ETH_BPF_OK                         0
#define ETH_BPF_PC_OUT_OF_RANGE            1
#define ETH_BPF_PACKET_INDEX_OUT_OF_RANGE  2
#define ETH_BPF_MEM_INDEX_OUT_OF_RANGE     3
#define ETH_BPF_UNKNOWN_INSTRUCTION        4
#define ETH_BPF_DIVISION_BY_ZERO           5
#define ETH_BPF_INVALID_ARGUMENT           6
#define ETH_BPF_LOOP_DETECTED              7

extern char* eth_bpf_strerr(int err);

/* Validate must be run before using eth_bpf_exec. eth_bpf_exec may
 *   crash if non validated programs are run.
 * The program input is encoded in bigendian format like:
 * <<Code:16, Jt:8, Jf:8, K:32>> the program is the "unpacked"
 * into the dst pointer. If the program is checked only, then
 * a NULL pointer may be passed as 'dst' otherwise the 'dst' pointer 
 * must point to a memory with the size of a least n*8 in size 
 * and be word aligned.
 * 
 * If everything is ok then 1 is retured and 'err' is set to ETH_BPF_OK
 * On error 0 is returned and the erro may be found in the 'err' pointer
 * and error location in the program is returned in 'err_loc'
 * 
 */
extern uint32_t eth_bpf_validate(uint8_t* src, uint8_t* dst, size_t n, 
				 int* err, uint32_t* err_loc);
/*
 * Run the program, converted with eth_bpf_validate. eth_bpf_exec
 * return the value from the return instruction if everything is ok
 * and the 'err' is set to ETH_BPF_OK. Typically the BPF programs return
 * 0 to reject input and (uint32_t) -1 to accept input (all bytes).
 * In case of execution error 0 is returned and error cause is set in
 * the 'err' and location is inidicated in 'err_loc'
 * if 'ptr' is NULL or n is zero then the packet is accepted and -1 
 * is returned.
 */
extern uint32_t eth_bpf_exec(uint8_t* ptr, size_t n, uint8_t* p, uint32_t len,
			     int* err, uint32_t* err_loc);

#endif

