set disassembly-flavor intel
break func
break jmp_xs
commands
  printf "saved_rsp = %lx\n", *((unsigned long*)0x403510)
  printf "*saved_rsp = %lx\n", *((unsigned long*)(*((unsigned long*)0x403510)))
  printf "*saved_rsp+0x10 = %lx\n", *((unsigned long*)(*((unsigned long*)0x403510) + 2))
  continue
end
