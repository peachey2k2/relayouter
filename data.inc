
; some stuff we'll only use while starting the server
old_reusable:
server_addr:       ; 16 bytes
  dw 2          ; family: AF_INET
  dw 0x901F     ; port (htons(8080))
  dd 0x0100007F ; addr: 127.0.0.1
  dq 0          ; padding
SOCKADDR_LEN = $ - server_addr

sigaction:
  dq      exit_hook       ; sa_handler
  dq      0x04000000      ; sa_flags (SA_RESTORER)
  dq      signal_restorer ; sa_restorer
  dq      null_ptr        ; sa_mask
SIGSET_LEN = 8

NULL = 0

MAX_EVENTS = 2048
INIT_POOL_SIZE = 4096
INIT_CLIENT_COUNT = 4000

struc Context {
  .master_pid    rd 1
  .is_running    rd 1
  .pool_head     rq 1
  .pool_tail     rq 1
  .pool_len      rq 1
}

virtual at 0
  temp_cx Context
  Context.size = $ - temp_cx
end virtual

virtual at r11
  context Context
end virtual

CONTEXT_SIZE = 64 ; overallocate to keep 64 alignment i guess?
assert Context.size <= CONTEXT_SIZE

struc ClientEvent {
  .fd            rq 1
  .type          dq EVENT_CLIENT
  .state         rd 1
  ; 20

  .request       rb REQ_SIZE
  .request_len   rd 1
  ; REQ_SIZE + 4

  .header        rb HDR_SIZE
  .header_len    rd 1
  .header_pos    rd 1
  ; HDR_SIZE + 8

  .file_fd       rd 1
  .file_pos      rq 1
  .file_size     rq 1
  .file_type     rq 1
  ; 28
}
; total: 60 + REQ_SIZE + HDR_SIZE
REQ_SIZE = 3500
HDR_SIZE = 536
; with this, each instance will be 4KiB = 2^12 bytes

CLIENT_SIZE = 4096

virtual at 0
  temp_ce ClientEvent
  ClientEvent.size = $ - temp_ce
end virtual

virtual at r14
  client ClientEvent
end virtual

assert ClientEvent.size = CLIENT_SIZE

LOC_CONTEXT      = 0
LOC_CLIENT_POOL  = LOC_CONTEXT      + CONTEXT_SIZE
LOC_CLIENTS      = LOC_CLIENT_POOL  + INIT_POOL_SIZE * 4           ; word[INIT_POOL_SIZE]
LOC_ARENA_END    = LOC_CLIENTS      + INIT_POOL_SIZE * CLIENT_SIZE ; client_obj[INIT_POOL_SIZE]

INIT_ARENA_SIZE = LOC_ARENA_END

; basically we store the indexes of each client object in a
; ring buffer at `LOC_CLIENTS` and use it as a stack so we
; don't have fragmentation issues nor alloc/dealloc overhead

; 48 bytes of reusable space
; we could also use the elf header probably
virtual at old_reusable

end virtual

CPU_SET_CELL_CNT = 16
; cpu_set dq CPU_SET_CELL_CNT dup 0 ; unneeded anymore
CPU_SET_SIZE = CPU_SET_CELL_CNT*8

ev:
  ev_event dd 0
  ev_data  dq 0
EVENT_SIZE = $ - ev

struc Event type {
  .fd     rq 1
  .type   dq type
}

virtual at 0
  temp_ev Event 0
  Event.fd = temp_ev.fd
  Event.type = temp_ev.type
end virtual

; enums for each event type
EVENT_SERVER = 0
EVENT_CLIENT = 1
EVENT_SIGNAL = 2

ev_data_server Event EVENT_SERVER
; ev_data_client Event EVENT_CLIENT ; we use an extended struc for client
ev_data_signal Event EVENT_SIGNAL

; after the `setrlimit` call, we'll have 4096 bytes of stack for everything else
STACK_LEFTOVER = 4096
STACK_SIZE = (MAX_EVENTS*16) + BUF_SIZE + STACK_LEFTOVER
