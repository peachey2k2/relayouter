format binary

include "header.inc"       ; ELF header
include "data.inc"         ; most constants and strucs
include "macros.inc"       ; macros and some common procedures
include "glibc_consts.inc" ; all the necessary constants for syscalls

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

  ; increase the stack size
  ;; int getrlimit(int resource, struct rlimit *rlim);
  lea        r15, [rsp - 64] ; cheeky deep stack access (very sussy)
  Syscall    SYS_getrlimit, RLIMIT_STACK, r15
  cmp        rax, 0
  jge        @f
  error      5, "couldn't get stack size"
@@:

  mov        dword [r15], STACK_SIZE

  ;; int setrlimit(int resource, const struct rlimit *rlim);
  Syscall    SYS_setrlimit, RLIMIT_STACK, r15
  cmp        rax, 0
  jge        @f
  error      6, "couldn't set stack size"
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
  mov        r15, rsp ; still holds `buf`
  Syscall    SYS_sched_getaffinity, qword [context.master_pid], CPU_SET_SIZE, r15
  cmp        rax, 0
  jge        @f
  error      7, "couldn't retrieve cpu affinity mask"
@@:
  xor        r9,  r9
  xor        r12, r12
@@:
  popcnt     r10, [r15 + 8*r9]
  add        r12, r10
  inc        r9
  cmp        r9, CPU_SET_CELL_CNT
  jne        @b

  print      "Detected "
  print_int  r12
  print      " CPUs", 10

  push       r12

  ; create a socket
  ;; int socket(int domain, int type, int protocol);
  Syscall SYS_socket, AF_INET, SOCK_STREAM or SOCK_NONBLOCK, 0
  mov     [ev_data_server.fd], rax

  cmp     rax, 0
  jge     @f
  error   8, "couldn't create socket"
@@:

  ;; int setsockopt(int sockfd, int level, int optname, const void optval[.optlen], socklen_t optlen);
  Syscall SYS_setsockopt, [ev_data_server.fd], SOL_SOCKET, SO_REUSEADDR, one, 4
  cmp     rax, 0
  jge     @f
  error   9, "couldn't set up socket opts"
@@:

  ; bind it
  ;; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  Syscall SYS_bind, [ev_data_server.fd], server_addr, SOCKADDR_LEN
  ; `server_addr` won't be used anymore
  cmp     rax, 0
  jge     @f
  error   10, "failed to bind socket"
@@:

  ;; listen for connection
  ;; int listen(int sockfd, int backlog);
  Syscall SYS_listen, [ev_data_server.fd], 4096 ; current linux cap. clamped down by system if it's too high anyway
  cmp     rax, 0
  jnl     @f
  error   11, "failed to listen socket"
@@:

  print   "listening...", 10

  ; set up signal hooks for exiting
  ;; int sigaction(int signum, const struct sigaction *_Nullable restrict act, struct sigaction *_Nullable restrict oldact);
  ;; NOTE: rt_sigaction also takes the length of `sigset_t`, which should be 8 bytes in x86-64
  mov     rdi, SIGTERM
  call    set_sigaction
  mov     rdi, SIGINT
  call    set_sigaction
  mov     rdi, SIGHUP
  call    set_sigaction

  mov     rcx, CPU_SET_CELL_CNT
  pop     rbx ; cpu count
  ; clear the set so we have it empty for the children
@@:
  dec     rcx
  mov     qword [r15 + 8*rcx], 0
  jnz     @b


  ; spawn the worker processes
  mov     r14, 0
.worker_init_loop:

  ;; pid_t fork(void);
  Syscall SYS_fork
  cmp     rax, 0
  jge     @f
  error   12, "failed to fork process"
@@:
  test    rax, rax
  jnz     .spawn_loop_cont

  ; set up the right cpu thread
  bts     qword [r15], r14
  mov     r11, [arena]
  ;; int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
  Syscall SYS_sched_setaffinity, qword [context.master_pid], CPU_SET_SIZE, r15
  cmp     rax, 0
  jge     @f
  error   13, "couldn't set cpu affinity mask"
@@:

  ;; int epoll_create1(int flags);
  Syscall SYS_epoll_create1, 0
  cmp     rax, 0
  jge     @f
  error   14, "failed to create the epoll"
@@:


  mov     [epollfd], rax


  ; set up the socket hook
  mov     [ev_event], EPOLLIN
  mov     [ev_data], ev_data_server

  ;; int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);
  Syscall SYS_epoll_ctl, [epollfd], EPOLL_CTL_ADD, [ev_data_server.fd], ev
  cmp     rax, 0
  jge     @f
  error   15, "failed to connect epoll to server socket"
@@:

  ; set up the signal hook (for shutdown)
  ;; int sigprocmask(int how, const sigset_t *_Nullable restrict set, sigset_t *_Nullable restrict oldset);
  ; last arg is for sigset length as usual
  Syscall SYS_rt_sigprocmask, SIG_BLOCK, block_sigset, NULL, SIGSET_LEN ; extra rt arg
  cmp     rax, 0
  jge     @f
  error   16, "failed to set blocked signals"
@@:

  ;; int signalfd(int fd, const sigset_t *mask, int flags);
  Syscall SYS_signalfd4, -1, block_sigset, SIGSET_LEN, 0 ; size as per family tradition, but not as the last arg cuz fuck you
  cmp     rax, 0
  jge     @f
  error   17, "failed to create signal fd"
@@:
  mov     [ev_data_signal.fd], rax

  mov     [ev_event], EPOLLIN
  mov     [ev_data], ev_data_signal
  ;; int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);
  Syscall SYS_epoll_ctl, [epollfd], EPOLL_CTL_ADD, [ev_data_signal.fd], ev
  cmp     rax, 0
  jge     @f
  error   18, "failed to connect epoll to signal socket"
@@:

  jmp .worker_loop

.spawn_loop_cont:

  inc     r14
  cmp     r14, rbx
  jl      .worker_init_loop
  jmp     .master_loop
@@:




.master_loop:
  mov     r15, [buf]
  mov     qword [r15], 1      ; tv_sec
  mov     qword [r15 + 8], 0  ; tv_nsec
@@:
  ;; int nanosleep(const struct timespec *duration, struct timespec *_Nullable rem);
  Syscall SYS_nanosleep, r15, NULL ; 1 sec

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

  ; print   "main process exited successfully", 10

  ; TODO: exit without returning with an interrupt
  exit    0




.worker_loop:
  ;; int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
  Syscall SYS_epoll_wait, [epollfd], [events], MAX_EVENTS, -1
  cmp     rax, 0
  jge     @f
  error   19, "failed to wait for epoll"
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

  error   20, "failed to accept connection"
@@:

  push    rax ; fd

  ;; int setsockopt(int sockfd, int level, int optname, const void optval[.optlen], socklen_t optlen);
  Syscall SYS_setsockopt, r14, IPPROTO_TCP, TCP_NODELAY, one, 4
  cmp     rax, 0
  jge     @f
  error   21, "failed to set `TCP_NODELAY` on a socket"
@@:

  ; fastopen needs to be enabled in the kernel for this
  ; `sudo sysctl -w net.ipv4.tcp_fastopen=3`
  ; TODO: add this as a config option
;   mov     dword [r15], 16 ; maximum length of pending SYNs
;   Syscall SYS_setsockopt, r14, IPPROTO_TCP, TCP_FASTOPEN, r15, 4
;   cmp     rax, 0
;   jge     @f
;   error   22, "failed to set `TCP_FASTOPEN` on a socket"
; @@:

  ; get a new object and fill it out
  call    acquire_client_obj

  mov     rdi, r15
  xor     rax, rax
  mov     rcx, 512 ; 4096/8
  rep     stosq ; we can probably do better than swar

  pop     rax
  mov     r14, r15
  mov     [client.fd], rax
  mov     qword [client.type], EVENT_CLIENT
  mov     qword [client.state], CLIENT_RECV
  mov     dword [client.file_fd], -1

  ; add it to epoll
  mov     qword [ev_event], EPOLLIN
  mov     qword [ev_data], r14
  ;; int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);
  Syscall SYS_epoll_ctl, [epollfd], EPOLL_CTL_ADD, [client.fd], ev
  cmp     rax, 0
  jge     @f
  error   23, "failed to connect epoll to signal socket"
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
  xor     r10, r10 ; arg 4
  xor     r8,  r8 ; arg 5
  xor     r9,  r9 ; arg 6
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
  error   24, "`close(epollfd)` returned with an error. some data may be lost."
@@:

  Syscall SYS_close, [ev_data_server.fd]
  ; TODO: look into `fsync` for error checking
  cmp     rax, 0
  jge     @f
  error   25, "`close(ev_data_server.fd)` returned with an error. some data may be lost."
@@:
  jmp     .worker_exit


  mov     r14, [arena_size]
  call    free

.worker_exit:
  ; print   "a worker has exited", 10
  exit 0

  
; end
TOTAL_FILE_SIZE = $ - $$
