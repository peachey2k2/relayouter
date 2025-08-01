
macro Syscall num*, arg1, arg2, arg3, arg4, arg5, arg6 {
  mov rax, num

  match _,arg1   \{ mov rdi, arg1 \}
  match _,arg2   \{ mov rsi, arg2 \}
  match _,arg3   \{ mov rdx, arg3 \}
  match _,arg4   \{ mov r10, arg4 \}
  match _,arg5   \{ mov r8 , arg5 \}
  match _,arg6   \{ mov r9 , arg6 \}

  Syscall
}

macro exit code* {
  Syscall  SYS_exit, code
}

__print_raw:
  push    rax 
  push    rdi

  xor     rax, rax
  inc     rax       ; Syscall: write
  mov     rdi, rax  ; fd: stdout
  syscall

  pop     rdi
  pop     rax

  ret

macro printn text*, len* {
  mov     rsi, text ; pointer to string
  mov     rdx, len  ; length of string
  call    __print_raw
}

macro print text*& {
  local .str, .end

  push    rsi
  push    rdx

  mov     rsi, .str             ; pointer to string
  mov     rdx, .end - .str      ; length of string
  call    __print_raw

  pop     rdx
  pop     rsi

  jmp     .end

.str:
  db      text
.end:
}

__int_to_str_inner:
  mov     r14, [buf]
  add     r14, BUF_SIZE
  push    r14
  mov     r15, 10    ; divisor

  ; mov     rax, num   ; divided, lower
@@:
  xor     rdx, rdx   ; divided, upper (also remainder)
  div     r15

  add     dl, '0'
  dec     r14
  mov     [r14], dl

  test    rax, rax
  jnz     @b

  mov     r15, BUF_SIZE
  pop     r15
  sub     r15, r14

  ret

;; <- r14 pos
;; <- r15 length
macro int_to_str num* {
  ; push    rax
  mov     rax, num   ; divided, lower
  call    __int_to_str_inner
  ; pop     rax
}

macro print_int num* {
  push        r14
  push        r15

  int_to_str  num
  printn      r14, r15 

  pop         r15
  pop         r14
}

macro error exitcode*, text* {
  neg        rax
  int_to_str rax
  mov        byte [r14 + r15], 10
  inc        r15
  printn     r14, r15

  exit exitcode
}

macro err_raw text* {
  print '0', 10
  exit 1
}

macro warn text* {
  print "[WARN] " # text
}

;; -> r15 - size
;; <- r15 - pointer
alloc:
  ;; void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);
  ; read: 1, write: 2, exec: 4
  ; shared: 1, private: 2, anonymous: 32
  ; with anonymous mmap call, fd should be -1 and offset 0
  Syscall SYS_mmap, NULL, r15, 3, 33, -1, 0
  cmp     rax, 0
  jge     @f
  error   3, "Allocation failed"
@@:
  mov     r15, rax
  ret

;; -> r15 - pointer
;; -> r14 - size
free:
  Syscall SYS_munmap, r15, r14
  cmp     rax, 0
  jge     @f
  error   4, "Failed to free"
@@:
  ret


;; <- r15 - pointer
acquire_client_obj:
  push       r14

  ; TODO: this check may give false negatives since it isn't atomic
  mov        r11, [arena]
  mov        r14, [context.pool_tail]
  cmp        [context.pool_head], r14
  jne        @f
  pop        r14
  err_raw    "a client pool was fully emptied"
@@:

  mov        r14, 1
  lock xadd  [context.pool_head], r14   ; get idx and increment
  and        r14, 111111111111b         ; clamp
  sal        r14, 2 ; *4
  add        r14, [client_pool]  

  xor        r15, r15
  mov        r15d, [r14] ; get index

  sal        r15, 12 ; *4096
  add        r15, [clients]

  pop        r14

  ret

;; -> r15 - pointer
drop_client_obj:
  push    r14

  mov        r11, [arena]

  ; we don't need to check for fullness since we'll never have
  ; more clients than the pool can hold

  mov        r14, 1
  lock xadd  [context.pool_tail], r14
  and        r14, 111111111111b
  sal        r14, 2 ; *4
  add        r14, [client_pool]

  sub        r15, [clients]
  sar        r15, 12 ; /4096

  mov        [r14], r15

  pop        r14

  ret

__httperr_inner:
  mov        [client.state], CLIENT_SEND_ERR

  lea        rdi, [client.header]

  mov        rcx, .text2 - .text1
  mov        rsi, .text1
  rep        movsb

  pop        rbx
  pop        rcx
  pop        rsi
  push       rbx
  rep        movsb

  mov        rcx, .end - .text2
  mov        rsi, .text2
  rep        movsb

  lea        rsi, [client.header]
  sub        rdi, rsi
  mov        [client.header_len], edi

  ret

.text1:
  db "HTTP/1.1 "
.text2:
  db CR, LF
  db "Content-Length: 0", CR, LF
  db "Content-Type: text/plain", CR, LF
  db "Connection: close", CR, LF
  db CR, LF
.end:

macro httperr type* {
  local .type, .end, LENGTH

  push       qword .type
  push       qword LENGTH
  call       __httperr_inner

  jmp        .end

  .type:
    db type
  .end:
  LENGTH = .end - .type
}

setup_http_header:
  push       r15
  
  lea        rdi, [client.header]

  mov        rcx, .text2 - .text1
  mov        rsi, .text1
  rep movsb

  mov        rax, [client.file_size]
  push       r14
  call       __int_to_str_inner 
  mov        rcx, r15
  mov        rsi, r14
  rep movsb
  pop        r14

  mov        rcx, .text3 - .text2
  mov        rsi, .text2
  rep movsb

  mov        rcx, 128
  mov        rsi, [client.file_type]
  jmp        @f
.filetype_loop:
  movsb
@@:
  cmp        byte [rsi], 0
  jnz        .filetype_loop

  mov        rcx, .end - .text3
  mov        rsi, .text3
  rep movsb

  lea        rax, [client.header]
  sub        rdi, rax
  mov        [client.header_len], edi

  pop        r15
  ret

.text1:
  db "HTTP/1.1 200 OK", CR, LF
  db "Content-Length: "
.text2:
  db CR, LF
  db "Content-Type: "
.text3:
  db CR, LF
  db "Connection: close", CR, LF
  db CR, LF
.end:

CR = 13
LF = 10

macro find_char_in_str needle*, haystack*, length* {
  mov        al, needle
  mov        rdi, haystack
  mov        ecx, length

  repne scasb
}

macro find_char_in_str_reverse needle*, haystack*, length* {
  mov        al, needle
  mov        rdi, haystack
  mov        ecx, length
  add        rdi, rcx
  dec        rdi

  std
  repne scasb
  cld
}

;; rcx -> length
;; rdi -> haystack
;; rdi <- pos
;; ZF  <- matched?
find_CRLF_in_str:
  mov        al, CR        ; needle

.loop:
  repne scasb              ; note that scasb sets zf only if it gets a match
  jz         @f            ; also note that jumps modify no flags if they don't trigger
  ret ; ZF = 0             ; neither do returns

@@:
  cmp       byte [rdi], LF ; also also note that `scasb` puts `rdi` one after the match
  jne       .loop

  ret ; ZF = 1
  
;; rcx -> length
;; rdi -> haystack
;; rdi <- pos
;; ZF  <- matched?
find_CRLF_CRLF_in_str:
  mov        al, 13        ; needle

.loop:
  repne scasb              ; note that scasb sets zf only if it gets a match
  jz         @f            ; also note that jumps modify no flags if they don't trigger
  ret ; ZF = 0             ; neither do returns

@@:
  cmp       dword [rdi-1], 0x0a0d0a0d ; CR LF CR LF
  jne       .loop

  ret ; ZF = 1

parse_request:
  ; request type
  lea        r9, [client.request]
  find_char_in_str ' ', r9, [client.request_len]
  jnz        .400
  mov        rax, "GET "
  cmp        dword [r9], eax
  jne        .501 ; nah

  ; path
  mov        r9, rdi
  find_char_in_str ' ', r9, [client.request_len]
  jnz        .400
  push       r9 ; path
  sub        r9, rdi
  ; neg        r9
  ; dec        r9
  not        r9 ; same as neg + dec
  push       r9 ; path length

  ; http version
  mov        r9, rdi
  find_char_in_str ' ', r9, [client.request_len]
  jnz        .400_pop
  mov        rax, "HTTP"
  cmp        dword [r9], eax
  jne        .400_pop ; ????
  mov        rax, "P/1."
  cmp        dword [r9 + 3], eax
  jne        .505_pop ; http version not supported

  ; decode the url
  mov        r9, "public"
  mov        r8, [buf]
  mov        qword [r8], r9
  ;lea        r8, [buf+6] ; dest
  add        r8, 6
  pop        r9 ; length
  pop        r10 ; raw path
  xor        rcx, rcx
  jmp        @f

.loop:
  mov        byte [r8], bl
  inc        rcx
  inc        r8
@@:
  cmp        rcx, r9
  jge        .end_loop

  cmp        byte [r10 + rcx], '%'
  jne        .no_hex

  add        rcx, 2
  cmp        rcx, r9
  jge        .400 ; invalid url

  ; %xx blocks to ascii
  mov        bx, word [r10 + rcx - 1] ; keep in mind it's still in LE
  or         rbx, 0010000000100000b
  bt         rbx, 6+8
  ; setc       al
  ; shl        rax, 8
  setc       ah
  bt         rbx, 6
  setc       al
  mov        rdx, 39
  mul        rdx ; rax * 39 -> rdx:rax
  sub        rbx, rbx
  and        rbx, 0000111100001111b
  mov        rax, rax
  shr        rax, 4
  or         rbx, rbx
  ror        bl, 4 ; fix the order
  jmp        .loop

.no_hex:
  cmp        byte [r10 + rcx], '+'
  jne        @f
  mov        bl, ' '
  jmp        .loop
@@:
  mov        bl, byte [r10 + rcx]
  jmp        .loop
  
.end_loop:
  cmp        byte [r8 - 1], '/'
  jne        @f
  mov        rax, "index.ht"
  mov        qword [r8], rax
  mov        rax, "ml"
  mov        word [r8 + 8], ax
  add        r8, 10
@@:
  mov        qword [r8], 0 ; I HATE NULL TERMINATION
  ; yes we overdo it on purpose btw, makes checking easier

  sub        r8, [buf]
  find_char_in_str_reverse '.', [buf], r8d
  mov        r8, rdi
  add        r8, 2
  push       qword [r8]

  ;; int open(const char *pathname, int flags, /* mode_t mode */ );
  Syscall    SYS_open, [buf], O_RDONLY, 0
  cmp        rax, 0
  jl         .404
  mov        r15, rax

  ; check if it's an actual file
  ;; int fstat(int fd, struct stat *statbuf);
  Syscall    SYS_fstat, r15, [buf]
  cmp        rax, 0
  jl         .404_close

  mov        rsi, [buf]
  mov        eax, dword [rsi + 24] ; st_mode 
  and        eax, S_IFMT ; yes this is what glibc does
  cmp        rax, S_IFREG
  jne        .404_close ; not an actual file

  mov        rax, qword [rsi + 48] ; st_size
  mov        [client.file_size], rax
  mov        [client.file_fd], r15d

  pop        rax
  call       set_mime_type

  call       setup_http_header

  mov        [client.state], CLIENT_SEND_HEADERS

  ret

.501:
  httperr    "501 Not Implemented"
.505_pop:
  add        rsp, 16
  httperr    "505 HTTP Version Not Supported"
.400_pop:
  add        rsp, 16
.400:
  httperr    "400 Bad Request"
  ret
.404_close:
  ;; int close(int fd);
  Syscall    SYS_close, r15
.404:
  add        rsp, 8
  httperr    "404 Not Found"
  ret


; rax will hold the extension with null bytes in the end
;; rax -> extension with trailing null bytes
set_mime_type:
  or         rax, [.filter]; all letters to lowercase
  mov        rdi, .exts
  mov        rcx, MIME_EXT_COUNT
  
  repne scasq ; insane
  jnz        @f
  sub        rcx, MIME_EXT_COUNT
  ; neg        rcx
  ; dec        rcx
  not        rcx ; index
  shl        rcx, 1 ; *2 for word
  xor        rax, rax
  mov        ax, word [rcx + .lookup]
  add        rax, .lookup
  mov        [client.file_type], rax
  ret
@@:
  mov        [client.file_type], .type_none
  ret

.filter dq 0x2020202020202020 
.exts:
  db "html",   4 dup 0x20
  db "htm",    5 dup 0x20
  db "css",    5 dup 0x20
  db "js",     6 dup 0x20
  db "json",   4 dup 0x20
  db "txt",    5 dup 0x20
  db "jpg",    5 dup 0x20
  db "jpeg",   4 dup 0x20
  db "png",    5 dup 0x20
  db "gif",    5 dup 0x20
  db "svg",    5 dup 0x20
  db "ico",    5 dup 0x20
  db "woff",   4 dup 0x20
  db "woff2",  3 dup 0x20
  db "ttf",    5 dup 0x20
  db "pdf",    5 dup 0x20
  db "zip",    5 dup 0x20
  MIME_EXT_COUNT = ($ - .exts) / 8

.lookup:
  dw .type_html      - .lookup
  dw .type_html      - .lookup
  dw .type_css       - .lookup
  dw .type_js        - .lookup
  dw .type_json      - .lookup
  dw .type_txt       - .lookup
  dw .type_jpg       - .lookup
  dw .type_jpg       - .lookup
  dw .type_png       - .lookup
  dw .type_gif       - .lookup
  dw .type_svg       - .lookup
  dw .type_ico       - .lookup
  dw .type_woff      - .lookup
  dw .type_woff2     - .lookup
  dw .type_ttf       - .lookup
  dw .type_pdf       - .lookup
  dw .type_zip       - .lookup

.types:
.type_html:   db "text/html", 0
.type_css:    db "text/css", 0
.type_js:     db "application/javascript", 0
.type_json:   db "application/json", 0
.type_txt:    db "text/plain", 0
.type_jpg:    db "image/jpeg", 0
.type_png:    db "image/png", 0
.type_gif:    db "image/gif", 0
.type_svg:    db "image/svg+xml", 0
.type_ico:    db "image/x-icon", 0
.type_woff:   db "font/woff", 0
.type_woff2:  db "font/woff2", 0
.type_ttf:    db "font/ttf", 0
.type_pdf:    db "application/pdf", 0
.type_zip:    db "application/zip", 0
.type_none:   db "application/octet-stream", 0
.end:


;; rdi -> signal
set_sigaction:
  ;; int sigaction(int signum, const struct sigaction *_Nullable restrict act, struct sigaction *_Nullable restrict oldact);
  mov     rax, SYS_rt_sigaction
  mov     esi, sigaction   ; arg2
  xor     rdx, rdx         ; arg3
  mov     r10, SIGSET_LEN  ; arg4
  syscall
  ret
