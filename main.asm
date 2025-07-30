format ELF64 executable

segment readable
server_addr:       ; 16 bytes
  dw 2          ; family: AF_INET
  ; dw 0x5000     ; port (htons(80))
  dw 0x901F     ; port (htons(8080))
  dd 0x0100007F ; addr: 127.0.0.1
  dq 0          ; padding
SOCKADDR_LEN = $ - server_addr

sigaction:
  dq      exit_hook       ; sa_handler
  dq      0x04000000      ; sa_flags (SA_RESTORER)
  dq      signal_restorer ; sa_restorer
  dq      sa_mask         ; sa_mask
SIGSET_LEN = 8

sa_mask dq 0

one     dd 1
zero    dd 0

sleep_duration:
  dq 1 ; tv_sec
  dq 0 ; tv_nsec

NULL = 0

block_sigset dq 0x4002 ; SIGTERM | SIGINT

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
    ; Context.master_pid    = temp_cx.master_pid
    ; Context.is_running    = temp_cx.is_running
    ; Context.pool_head     = temp_cx.pool_head
    ; Context.pool_tail     = temp_cx.pool_tail
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

    ClientEvent.fd            = temp_ce.fd
    ClientEvent.type          = temp_ce.type
    ClientEvent.state         = temp_ce.state

    ClientEvent.request       = temp_ce.request
    ClientEvent.request_len   = temp_ce.request_len

    ClientEvent.header        = temp_ce.header
    ClientEvent.header_len    = temp_ce.header_len
    ClientEvent.header_pos    = temp_ce.header_pos

    ClientEvent.file_fd       = temp_ce.file_fd
    ClientEvent.file_pos      = temp_ce.file_pos
    ClientEvent.file_size     = temp_ce.file_size
    ClientEvent.file_type     = temp_ce.file_type
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

  ; basically we store the indexes of each client object in `LOC_CLIENTS`
  ; and use it as a stack (so we don't have fragmentation issues)



segment readable writable
; pid_main dd 0
; pid_cores dq 0 ;ptr
cpu_count dd 0

; is_running dq 1

buf dq 0
BUF_SIZE = 1024

cpu_set_cell_cnt = 16
cpu_set dq cpu_set_cell_cnt dup 0
cpu_set_size = cpu_set_cell_cnt*8

arena dq 0
arena_size dq 0

; arena pointers
events dq 0
client_pool dq 0
clients dq 0


ev:
  ev_event dd 0
  ev_data  dq 0
EVENT_SIZE = $ - ev

epollfd dq 0

struc Event type {
  .fd     rq 1
  .type   dq type
}

virtual at 0
  temp_ev Event 0
  Event.fd = temp_ev.fd
  Event.type = temp_ev.type
end virtual

EVENT_SERVER = 0
EVENT_CLIENT = 1
EVENT_SIGNAL = 2

ev_data_server Event EVENT_SERVER
; ev_data_client Event EVENT_CLIENT ; we use an extended struc for client
ev_data_signal Event EVENT_SIGNAL

; ev_data_server:
;   sockfd dq 0
;   EVENT_SERVER dq 0

; ; ev_data_client:
; ;   clientfd dq 0
; ;   EVENT_CLIENT dq 1

; ev_data_signal:
;   signalfd dq 0
;   EVENT_SIGNAL dq 2



segment readable executable
  entry start

include "macros.inc"
include "glibc_consts.inc"

exit_hook:
  mov         r11, [arena]
  mov         [context.is_running], 0
  ret

signal_restorer:
  ;; int sigreturn(...);
  Syscall     SYS_rt_sigreturn

start:
  ; allocate arena
  mov        [arena_size], INIT_ARENA_SIZE
  mov        r15, INIT_ARENA_SIZE
  call       alloc
  mov        [arena], r15

  mov        r11, [arena]

  add        r15, LOC_CLIENT_POOL
  mov        [client_pool], r15
  add        r15, LOC_CLIENTS
  mov        [clients],     r15

  mov        [context.is_running], 1
  mov        [context.pool_head], 0
  mov        [context.pool_tail], INIT_CLIENT_COUNT
  mov        [context.pool_len], INIT_POOL_SIZE

  ; initialize the pool
  mov        r15, INIT_CLIENT_COUNT
  mov        r14, [client_pool]
@@:
  dec        r15d
  mov        dword [r14 + 4*r15], r15d
  jnz        @b

  STACK_LEFTOVER = 4096
  STACK_SIZE = (MAX_EVENTS*16) + BUF_SIZE + STACK_LEFTOVER

  ; increase the stack size
  ;; int getrlimit(int resource, struct rlimit *rlim);
  lea        r15, [rsp - 64]
  Syscall    SYS_getrlimit, RLIMIT_STACK, r15
  cmp        rax, 0
  jge        @f
  error      "couldn't get stack size"
@@:

  mov        dword [r15], STACK_SIZE

  ;; int setrlimit(int resource, const struct rlimit *rlim);
  Syscall    SYS_setrlimit, RLIMIT_STACK, r15
  cmp        rax, 0
  jge        @f
  error      "couldn't set stack size"
@@:

  sub        rsp, MAX_EVENTS * 16
  mov        [events], rsp
  sub        rsp, BUF_SIZE
  mov        [buf], rsp

  ; get the main process pid
  ;; pid_t getpid(void);
  Syscall    SYS_getpid 
  mov        r11, [arena]
  mov        [context.master_pid], eax

  ; get the cpu thread count
  ;; int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
  Syscall    SYS_sched_getaffinity, qword [context.master_pid], cpu_set_size, cpu_set
  cmp        rax, 0
  jge        @f
  error      "couldn't retrieve cpu affinity mask"
@@:

  xor        r9,  r9
  xor        r12, r12
@@:
  popcnt     r10, [cpu_set + 8*r9]
  add        r12, r10
  inc        r9
  cmp        r9, cpu_set_cell_cnt
  jne        @b

  print      "Detected "
  print_int  r12
  print      " CPUs.", 10

  mov        [cpu_count], r12d

  ; create a socket
  ;; int socket(int domain, int type, int protocol);
  Syscall SYS_socket, AF_INET, SOCK_STREAM or SOCK_NONBLOCK, 0
  mov     [ev_data_server.fd], rax

  cmp     rax, 0
  jge     @f
  error   "couldn't create socket"
@@:

;   ; enable non blocing flag
;   ;; int fcntl(int fd, int op, ... /* arg */ );
;   Syscall SYS_fcntl, [ev_data_server.fd], F_GETFL
;   cmp     rax, 0
;   jge     @f
;   error   "couldn't get fd flags"
; @@:

;   mov     rdx, rax ; arg 3
;   xor     rdx, O_NONBLOCK

;   Syscall SYS_fcntl, [ev_data_server.fd], F_SETFL ; ,rdx
;   cmp     rax, 0
;   jge     @f
;   error   "couldn't set fd flags"
; @@:

  ;; int setsockopt(int sockfd, int level, int optname, const void optval[.optlen], socklen_t optlen);
  Syscall SYS_setsockopt, [ev_data_server.fd], SOL_SOCKET, SO_REUSEADDR, one, 4
  cmp     rax, 0
  jge     @f
  error   "couldn't set up socket opts"
@@:

  ; bind it
  ;; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  Syscall SYS_bind, [ev_data_server.fd], server_addr, SOCKADDR_LEN
  cmp     rax, 0
  jge     @f
  error   "failed to bind socket"
@@:

  ;; listen for connection
  ;; int listen(int sockfd, int backlog);
  Syscall SYS_listen, [ev_data_server.fd], 4096 ; current linux cap. clamped down by system if it's too high anyway
  cmp     rax, 0
  jnl     @f
  error   "failed to listen socket"
@@:

  print   "Socket created, listening...", 10

  ; set up signal hooks for exiting
  ;; int sigaction(int signum, const struct sigaction *_Nullable restrict act, struct sigaction *_Nullable restrict oldact);
  ;; NOTE: rt_sigaction also takes the length of `sigset_t`, which should be 8 bytes in x86-64
  Syscall SYS_rt_sigaction, SIGTERM, sigaction, NULL, SIGSET_LEN
  Syscall SYS_rt_sigaction, SIGINT,  sigaction, NULL, SIGSET_LEN
  Syscall SYS_rt_sigaction, SIGHUP,  sigaction, NULL, SIGSET_LEN
@@:

  ; clear the set so we have it empty for the children
  mov     rcx, cpu_set_cell_cnt
@@:
  dec     rcx
  mov     qword [cpu_set + 8*rcx], 0
  jnz     @b


  ; spawn the worker processes
  mov     r15, 0
.worker_init_loop:

  ;; pid_t fork(void);
  Syscall SYS_fork
  cmp     rax, 0
  jge     @f
  error   "failed to fork process"
@@:
  test    rax, rax
  jnz     .spawn_loop_cont

  ; set up the right cpu thread
  bts     [cpu_set], r15
  mov     r11, [arena]
  ;; int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
  Syscall SYS_sched_setaffinity, qword [context.master_pid], cpu_set_size, cpu_set
  cmp     rax, 0
  jge     @f
  error   "couldn't set cpu affinity mask"
@@:

  ;; int epoll_create1(int flags);
  Syscall SYS_epoll_create1, 0
  cmp     rax, 0
  jge     @f
  error   "failed to create the epoll"
@@:


  mov     [epollfd], rax


  ; set up the socket hook
  mov     [ev_event], EPOLLIN
  mov     [ev_data], ev_data_server

  ;; int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);
  Syscall SYS_epoll_ctl, [epollfd], EPOLL_CTL_ADD, [ev_data_server.fd], ev
  cmp     rax, 0
  jge     @f
  error   "failed to connect epoll to server socket"
@@:

  ; set up the signal hook (for shutdown)
  ;; int sigprocmask(int how, const sigset_t *_Nullable restrict set, sigset_t *_Nullable restrict oldset);
  ; last arg is for sigset length as usual
  Syscall SYS_rt_sigprocmask, SIG_BLOCK, block_sigset, NULL, SIGSET_LEN ; extra rt arg
  cmp     rax, 0
  jge     @f
  error   "failed to set blocked signals"
@@:

  ;; int signalfd(int fd, const sigset_t *mask, int flags);
  Syscall SYS_signalfd4, -1, block_sigset, SIGSET_LEN, 0 ; size as per family tradition, but not as the last arg cuz fuck you
  cmp     rax, 0
  jge     @f
  error   "failed to create signal fd"
@@:
  mov     [ev_data_signal.fd], rax

  mov     [ev_event], EPOLLIN
  mov     [ev_data], ev_data_signal
  ;; int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);
  Syscall SYS_epoll_ctl, [epollfd], EPOLL_CTL_ADD, [ev_data_signal.fd], ev
  cmp     rax, 0
  jge     @f
  error   "failed to connect epoll to signal socket"
@@:

  jmp .worker_loop

.spawn_loop_cont:

  inc     r15
  cmp     r15d, [cpu_count]
  jl      .worker_init_loop
  jmp     .master_loop
@@:




.master_loop:

@@:
  ;; int nanosleep(const struct timespec *duration, struct timespec *_Nullable rem);
  Syscall SYS_nanosleep, sleep_duration, NULL ; 1 sec

  mov     r11, [arena]
  cmp     [context.is_running], 0
  jne     @b

  ;; int kill(pid_t pid, int sig);
  ; pid: 0 means kill everything in group (in this case, all the children)
  Syscall SYS_kill, 0, SIGTERM

  cmp     rax, 0
  jge     @f
  warn    "failed to kill some child processes"
@@:

  ;; pid_t wait4(pid_t pid, int *_Nullable wstatus, int options, struct rusage *_Nullable rusage);
  ; pid: -1 means wait for any child
  Syscall SYS_wait4, -1, NULL, 0, NULL
  cmp     rax, 0
  jg      @b ; repeat until all children are done

  print   "main process exited successfully", 10

  ; TODO: exit without returning with an interrupt
  exit    0




.worker_loop:
  ;; int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
  Syscall SYS_epoll_wait, [epollfd], [events], MAX_EVENTS, -1
  cmp     rax, 0
  jge     @f
  error   "failed to wait for epoll"
@@:
  mov     r12, rax
  xor     r13, r13

.event_for_loop:
  mov     rsi, r13         ; idx
  sal     rsi, 4 ; *16     ; * sizeof(event)
  add     rsi, [events]    ; + events (ptr)

  push    r13
  push    r12

  mov     rax, [rsi]
  mov     [ev_event], eax
  mov     rax, [rsi + 4] ; HAHAHAHAHAHAHHAHAHAHHAHAHHAHAHAH
  mov     [ev_data], rax

  mov     r14, [rax + Event.fd] ; fd
  push    r14
  mov     r14, [rax + Event.type] ; event enum

  ; switch
  cmp     r14, EVENT_SERVER
  je      .server_event
  cmp     r14, EVENT_CLIENT
  je      .client_event
  cmp     r14, EVENT_SIGNAL
  je      .signal_event

  err_raw "event didn't match"

.server_event:
  pop     r14 ; socket fd
  ;; int accept4(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen, int flags);
  mov     r15, [buf]
  mov     dword [r15], SOCKADDR_LEN
  Syscall SYS_accept4, r14, NULL, NULL, SOCK_NONBLOCK
  cmp     rax, 0
  jge     @f

  ; this just means another thread already handled this
  cmp     rax, -EAGAIN ; EWOULDBLOCK also aliases to EAGAIN on linux
  je      .switch_end

  error   "failed to accept connection"
@@:

  push    rax ; fd

  ;; int setsockopt(int sockfd, int level, int optname, const void optval[.optlen], socklen_t optlen);
  Syscall SYS_setsockopt, r14, IPPROTO_TCP, TCP_NODELAY, one, 4
  cmp     rax, 0
  jge     @f
  error   "failed to set `TCP_NODELAY` on a socket"
@@:

  ; get a new object and fill it out
  call    acquire_client_obj

  mov     rdi, r15
  xor     rax, rax
  mov     rcx, 512 ; 4096/8
  rep     stosq ; we can probably do better than swar

  pop     rax
  mov     [r15 + ClientEvent.fd], rax
  mov     qword [r15 + ClientEvent.type], EVENT_CLIENT
  mov     qword [r15 + ClientEvent.state], CLIENT_RECV
  mov     dword [r15 + ClientEvent.file_fd], -1

  ; add it to epoll
  mov     qword [ev_event], EPOLLIN
  mov     qword [ev_data], r15
  ;; int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);
  Syscall SYS_epoll_ctl, [epollfd], EPOLL_CTL_ADD, [r15 + ClientEvent.fd], ev
  cmp     rax, 0
  jge     @f
  error   "failed to connect epoll to signal socket"
@@:



; -- end of server event branch

  jmp     .switch_end
.client_event:
  pop     r14 ; client event object
  mov     r14, rax

  ; cmp     [ev_event], EPOLLIN
  ; je      .client_in
  ; cmp     [ev_event], EPOLLOUT
  mov     r15d, [ev_event]
  bt      r15, 0 ; EPOLLIN
  jc      .client_recv
  bt      r15, 2 ; EPOLLOUT
  jc      .client_send


  err_raw "couldn't match a client event"
  
  CLIENT_RECV = 0
  CLIENT_SEND_HEADERS = 1
  CLIENT_SEND_FILE = 2
  CLIENT_SEND_ERR = 3
  
.client_recv:
  cmp     [client.state], CLIENT_RECV
  je      @f
  err_raw "invalid client state"
@@:
  ;; ssize_t recvfrom(int sockfd, void [buf][restrict .len], size_t len, int flags, struct sockaddr *_Nullable restrict src_addr, socklen_t *_Nullable restrict addrlen);
  lea     r11, [client.request]
  mov     eax, [client.request_len]
  add     r11, rax
  mov     r12, REQ_SIZE
  sub     r12, rax
  sub     r12, 1
  Syscall SYS_recvfrom, [client.fd], r11, r12, 0, NULL, NULL
  cmp     rax, 0
  jg      @f ; 0 also will lead to a close

  cmp     rax, -EAGAIN ; EWOULDBLOCK also aliases to EAGAIN on linux
  je      .switch_end

  jmp     .client_close
@@:
  mov     ebx, [client.request_len]
  add     rbx, rax
  cmp     rbx, REQ_SIZE
  mov     [client.request_len], ebx
  jl      @f
  httperr "403 Content Too Large" ; idk
  jmp     .switch_end
@@:
  lea     rdi, [client.request]
  ; rcx is already set
  call    find_CRLF_CRLF_in_str
  jnz     .switch_end ; no match

  call    parse_request

  ;; int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);
  mov     [ev_event], EPOLLOUT
  mov     [ev_data], r14
  Syscall SYS_epoll_ctl, [epollfd], EPOLL_CTL_MOD, [client.fd], ev

  jmp     .switch_end

.client_send:
  cmp     [client.state], CLIENT_SEND_HEADERS
  je      .client_send_headers
  cmp     [client.state], CLIENT_SEND_FILE
  je      .client_send_file
  cmp     [client.state], CLIENT_SEND_ERR
  je      .client_send_headers

  err_raw "invalid client state"

.client_send_headers:
  ;; ssize_t sendto(int sockfd, const void buf[.len], size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
  lea     rsi, [client.header]
  mov     eax, [client.header_pos]
  add     rsi, rax ; arg 2
  mov     edx, [client.header_len] ; arg 3
  mov     r10, 0 ; arg 4
  mov     r8, NULL ; arg 5
  mov     r9, 0 ; arg 6
  Syscall SYS_sendto, [client.fd]
  cmp     rax, 0
  jg      @f ; 0 also will lead to a close

  cmp     rax, -EAGAIN ; EWOULDBLOCK also aliases to EAGAIN on linux
  je      .switch_end

  jmp     .client_close
@@:
  add     eax, [client.header_pos]
  mov     [client.header_pos], eax
  cmp     eax, [client.header_len]
  jne     .switch_end

  cmp     [client.state], CLIENT_SEND_ERR
  je      .client_close

  mov     [client.state], CLIENT_SEND_FILE
  jmp     .client_send_file

.client_send_file:
  ;; ssize_t sendfile(int out_fd, int in_fd, off_t *_Nullable offset, size_t count);
  mov     esi, [client.file_fd] ; arg 2
  lea     rdx, [client.file_pos] ; arg 3
  mov     r10, [client.file_size]
  sub     r10, [client.file_pos] ; arg 4
  Syscall SYS_sendfile, [client.fd]
  cmp     rax, 0
  jg      @f ; 0 also will lead to a close

  cmp     rax, -EAGAIN ; EWOULDBLOCK also aliases to EAGAIN on linux
  je      .switch_end

  jmp     .client_close
@@:
  mov     rax, [client.file_pos]
  cmp     rax, [client.file_size]
  jne     .switch_end

  jmp     .client_close


.client_close:
  
  cmp     [client.file_fd], -1
  je      @f
  ;; int close(int fd);
  mov     edi, [client.file_fd] ; arg 1
  Syscall SYS_close
@@:
  mov     [client.file_fd], -1
  ;; int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);
  Syscall SYS_epoll_ctl, [epollfd], EPOLL_CTL_DEL, [client.fd], NULL
  Syscall SYS_close, [client.fd]
  mov     r15, r14
  call    drop_client_obj

  jmp     .switch_end
  



; -- end of client event branch
  
  jmp     .switch_end
; if we poll a signal, we exit the thread without even consuming it
; so other processes can do the same aswell
.signal_event:
  pop     r14
  ; mov     [is_running], 0
  jmp     .worker_cleanup
  


; -- end of signal event branch

.switch_end:
  pop     r12
  pop     r13

  inc     r13
  cmp     r13, r12
  jl      .event_for_loop

  mov     r11, [arena]
  cmp     [context.is_running], 0
  jne     .worker_loop

.worker_cleanup:

  ;; int close(int fd);
  Syscall SYS_close, [epollfd]
  cmp     rax, 0
  jge     @f
  error   "`close(epollfd)` returned with an error. some data may be lost."
@@:

  Syscall SYS_close, [ev_data_server.fd]
  ; TODO: look into `fsync` for error checking
  cmp     rax, 0
  jge     @f
  error   "`close(ev_data_server.fd)` returned with an error. some data may be lost."
@@:
  jmp     .worker_exit


  mov     r14, [arena_size]
  call    free

.worker_exit:
  print   "a worker has exited", 10
  exit 0

  
; end
