OPTIMISATION RULES
==================

# 1. Remove pointless loads

## 1a.

    L0: sta <k>
        lda <k>
=>

	L0: sta <k>
    
## 1b.

    L0: txa
        lda <k>

==>

    L0: txa
        ldx <k>

## 1c.

    L0: sta <k>
        ldx <k>

=>

    L0: sta <k>
        tax

## 1d.

if <insn> only affect A

    L0: sta <k>
	    <insn>
		lda <k>
=>

    L0: sta <k>
	
if <insn> affect A

    L0: sta <k>
	    <insn>
		lda <k>
=>

	L0: sta <k>
		<insn>
		
## 1e.

if <insn> only affect X

    L0: stx <k>
        <insn>
        ldx <k>
=>

	L0: stx <k>
        <insn>


# 2. Remove pointless store, register or mem is never referenced (or killed)

## 2.a

    L0: sta <k>

=>

	<empty>      if M[<k>] is never referenced
		
## 2.b

    L0: stx <k>
	
=>

	<empty>      if M[k] is never referenced

## 2.c

    L0: txa

=>

	<empty>      if A is never reference

## 2.d

    L0: ldc <k>

=>

	<empty>      if A is never reference

## 2.e  (tax)

    L0: tax
=>

	<empty>	     if X is never referenced
	    
## 2.f  (ldxc)

    L0: ldxc <k>
	
=>

	<empty>       if X is never reference

# 3. Remove multiple jumps

## 3.a short circuit multiple unconditional jumps

         jmp L1
    L1:  jmp L2
	
=>

	     jmp L2

## 3.a short circuit conditional branches

        jx  L1 L2
    L1: jmp L3
	
    =>
	
	    jx  L3 L2

## 3.b short circuit same condition

        jx L1 L2
    L1: jx L3 L4
	
    =>
	
        jx L3 L2
    L1: jx L3 L4

# 4. Remove unreachable code

Remove unreachable codes involve visting all nodes that can be reached
from the initial node. Then remove all nodes that was not visted.

    L1: jmp L3
    L2: bla bla
    L3: code
	
    =>
	
    L1: jmp L3
    L3: code

# 5. Constant propagation

Constant propagation includes calculating represent values that may be
loaded into register and memory locations, then use the knowledge of
the calculated value in registers and memory location to remove or
simplify instructions. All registers start as undefined, only PC=0
and input P[0]...P[L-1] are defined.
The constant propagation calculate values on A,X,M[i] and can
assume values that are either constant integer or expressions
in terms of indata P[i].

    ldc  #1    ( A=1 )
    add  #5    ( A=6 )
=>

    ldc  #6

	ldaw [5]    ( A = {p,5,4}
	add  #1     ( A = {'+',{p,5,4},1})
	sta  #3     ( M[3] = {'+',{p,5,4},1})
    ...

A matcher is used to recursivly to match complex term in case of jeq and jeqx.
The conditional jump expressions are calculated and stored to be used to
identify expression already calculated by parent nodes in the DAG.


# 6 Bitfield optimisation

## 6.a
    rshk <k>
    andk #1
    jgtk #0  jt=L1 jf=L2
	
=>

    jsetk #0x02 jt=L1 jf=L2     if A is not referenced in L1/L2

## 6.b
    L0: andk #<m>
	    jgtk #0 jt=L1 jf=L2
		
=>

    L0: jsetk #<m> jt=L1 jf=L2      if A is not referenced in L1/L2

## 6.c
    L0: rshk <k>
        jsetk #0x01 jt=L1 jf=L2     if A is not referenced in L1/L2
		
=>

	L0:  jsetk (#0x01<<k) jt=L1 jf=L2

## 6.d
    L0: jsetk #0x01 jt=L2 jf=L1
    L1: jsetk #0x02 jt=L2 jf=L3
	
=>

	L0: jsetk #0x03 jt=L2 jf=L3

## 6.e
    L0: jsetk #0x01 jt=L1 jf=L2
    L1: jsetk #0x02 jt=L3 jf=L2  if A is not referenced in L2/L3
	
=>

    L0: andk #0x03
	    jeqk #0x03 jt=L3 jf=L2

## 6.f
        andk #0x03
	L0: jeqk #0x03 jt=L1 jf=L3
    L1: jsetk #0x04 jt=L2 jf=L3  if A is not referenced in L2/L3
	
=>

	    andk #0x07
	L0: jeqk #0x07 jt=L2 jf=L3
