; Linux ELF parsing is the most insane nonsensical thing ever.
; Basically all fields I prefixed with underscore are all ignored.
; So in the future we could use parts of this to lower the file
; size even further.

use64
org     0x000400000

elf_header:
  ei_mag          db 0x7f, "ELF"
  _ei_class       db 2 ; ELFCLASS64
  _ei_data        db 1 ; ELFDATA2LSB
  _ei_version     db 1 ; EV_CURRENT
  _ei_osabi       db 0 ; ELFOSABI_NONE
  _ei_abiversion  db 0
  _ei_pad         db 0, 0, 0, 0, 0, 0, 0

  e_type          dw 2 ; ET_EXEC
  e_machine       dw 0x3e ; x86-64
one: ; needed for sys_setsockopt
  _e_version      dd 1 ; EV_CURRENT
epollfd:
  e_entry         dq start
  e_phoff         dq program_header - $$
  ;_e_shoff        dq 0 ; we don't have a section header
block_sigset dq 0x4002 ; SIGTERM | SIGINT
  _e_flags        dd 0 ; literally marked as unused
  e_ehsize        dw ELF_HEADER_SIZE
  e_phentsize     dw PROGRAM_HEADER_SIZE
  e_phnum         dw 1
  e_shentsize     dw 0
  e_shnum         dw 0
  e_shstrndx      dw 0
ELF_HEADER_SIZE = $ - elf_header

program_header:
  p_type          dd 1 ; PT_LOAD
  p_flags         dd 7 ; read(4) | write(2) | execute(1)
  p_offset        dq 0
  p_vaddr         dq $$
  p_paddr         dq $$
  p_filesz        dq TOTAL_FILE_SIZE
  p_memsz         dq TOTAL_FILE_SIZE
  _p_align        dq 0x1000 ; ignored for executables
PROGRAM_HEADER_SIZE = $ - program_header

virtual at program_header
  arena        dq ?
  null_ptr     dq ?
  arena_size   dq ?
  events       dq ?
  client_pool  dq ?
  clients      dq ?

  ; we use this buffer for like a billion things.
  ; it's gonna be allocated in the stack.
  buf          dq ?
  BUF_SIZE = 1024
end virtual

