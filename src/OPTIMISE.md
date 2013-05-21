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

    M[<k>]=A, INSN, A=M[k]  => M[<k>]=A         if INSN only affect A

    M[<k>]=A, INSN, A=M[k]  => M[<k>]=A, INSN;  otherwise

## 1e.

    M[<k>]=X, INSN, X=M[<k>]  => M[<k>]=X;       if INSN only affect X
    M[<k>]=X, INSN, X=M[<k>]  => M[<k>]=X, INSN; otherwise

# 2. Remove pointless store, register or mem is never referenced (or killed)

## 2.a (st)

    M[<k>]=A =>       if M[k] is never referenced

## 2.b  (stx)

    M[k]=X   =>       if M[k] is never referenced

## 2.c  (txa)

    A=X      =>       if A is never reference

## 2.d  (ldc)

   A=<const>          if A is never reference

## 2.e  (tax)

   X=A     =>         if X is never referenced

## 2.f  (ldxc)
   X=<const>  =>      if X is never reference

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
simplify instructions.

    A=1
    A+=5
=>
    A=6

# 6 Bitfield optimisation

## 6.a
    A >>= <n>
    A &= 1
    if (A > 0) goto L1; else goto L2;
    =>
    if (A & 0x02) goto L1; else goto L2;    if A is not referenced in L1/L2

## 6.b
    A &= <m>
    if (A > 0) goto L1; else goto L2;
    =>
    if (A & <m>) goto L1; else goto L2;     if A is not referenced in L1/L2
