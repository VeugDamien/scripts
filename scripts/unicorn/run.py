#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *

# memory address where emulation starts
ADDRESS = 0x1000000

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
  print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
  # read this instruction code from memory
  tmp = uc.mem_read(address, size)
  print("*** EIP = %x *** :" %(address), end="")
  for i in tmp:
    print(" %02x" %i, end="")
  print("")


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
  print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing Linux interrupt
def hook_intr(uc, intno, user_data):
  # only handle Linux syscall
  if intno != 0x80:
    print("got interrupt %x ???" %intno);
    uc.emu_stop()
    return

  eax = uc.reg_read(UC_X86_REG_EAX)
  eip = uc.reg_read(UC_X86_REG_EIP)
  if eax == 1:    # sys_exit
    print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" %(eip, intno, eax))
    uc.emu_stop()
  elif eax == 4:    # sys_write
    # ECX = buffer address
    ecx = uc.reg_read(UC_X86_REG_ECX)
    # EDX = buffer size
    edx = uc.reg_read(UC_X86_REG_EDX)

    try:
      buf = uc.mem_read(ecx, edx)
      print(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = " %(eip, intno, ecx, edx), end="")
      for i in buf:
        print("%c" %i, end="")
      print("")
    except UcError as e:
      print(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = <unknown>\n" %(eip, intno, ecx, edx))
    else:
      print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" %(eip, intno, eax))


def hook_syscall(mu, user_data):
  rax = mu.reg_read(UC_X86_REG_RAX)
  print(">>> got SYSCALL with RAX = 0x%x" %(rax))
  mu.emu_stop()

# Test X86 32 bit
def test_i386(mode, code):
  print("Emulate x86 code")
  try:
    # Initialize emulator
    mu = Uc(UC_ARCH_X86, mode)

    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)

    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, code)

    # initialize stack
    mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x200000)

    # tracing all basic blocks with customized callback
    #mu.hook_add(UC_HOOK_BLOCK, hook_block)

    # tracing all instructions with customized callback
    #mu.hook_add(UC_HOOK_CODE, hook_code)

    # handle interrupt ourself
    #mu.hook_add(UC_HOOK_INTR, hook_intr)

    # handle SYSCALL
    #mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

    # emulate machine code in infinite time
    mu.emu_start(ADDRESS, ADDRESS + len(code))

    # now print out some registers
    print(">>> Emulation done")

  except UcError as e:
    print("ERROR: %s" % e)

if __name__ == '__main__':
  with open("./<name_of_the_binary>", "rb") as binary_file:
    binary = binary_file.read()
    #run(UC_MODE_32, binary)
    #run(UC_MODE_64, binary)
