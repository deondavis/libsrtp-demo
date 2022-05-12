#include <stdio.h>  /* for printf, fprintf */
#include <stdlib.h> /* for atoi()          */
#include <errno.h>
#include <unistd.h>
#include <signal.h> /* for signal()        */

#include <string.h> /* for strncpy()       */
#include <time.h>   /* for usleep()        */

#include <fcntl.h> /* for open close files */
#include <sys/stat.h> /* for TO_FILE O_WRONLY O_CREAT O_EXCL */

#include <sys/socket.h> /* for socket calls */
#include <netinet/in.h> /* for inet address */

#include "srtp.h"    /* libsrtp includes */
#include "rtp.h"    /* convenience wrappers over libsrtp -- need refinement error fixes for making generic strcpy used*/
#include "util.h"   /* Utilities used by the test apps -- need refinement error fixes for making generic */

#define TO_FILE "der.txt"
#define BUFFER_SIZE 1024
#define USEC_RATE 100
#define PORT 12345
#define MAX_KEY_LEN 96
#define KEY_VAL "c1eec3717da76195bb878578790af71c4ee9f859e197a414a78d5abc7451"

int main()
{
   rtp_receiver_t rcvr;
   int sock, ret;
   char buf[BUFFER_SIZE];
   int fd_to;
   ssize_t nwritten;
   struct sockaddr_in name;
   srtp_policy_t policy;
   srtp_err_status_t status;
   uint32_t ssrc = 0xdeadbeef; /* ssrc value hardcoded for now */
   char key[MAX_KEY_LEN];
   int len,expected_len;
   char input_key[96];

   /* initialization */
   memset(&policy, 0x0, sizeof(srtp_policy_t));
   strncpy(input_key,KEY_VAL,MAX_KEY_LEN);
   printf("Using %s [0x%x]\n", srtp_get_version_string(), srtp_get_version());

   status = srtp_init();
   if (status) {
       printf("error: srtp initialization failed with error code %d\n", status);
       exit(1);
   }

   /* open socket */
   sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if (sock < 0) {
      fprintf(stderr, "couldn't open socket\n");
      exit(1);
   }
   memset(&name, 0, sizeof(struct sockaddr_in));
   name.sin_addr.s_addr = INADDR_ANY; /* since server we are binding to all available interfaces */
   /* reference: https://stackoverflow.com/questions/16508685/understanding-inaddr-any-for-socket-programming*/
   name.sin_family = PF_INET;
   name.sin_port = htons(PORT);
   if (bind(sock, (struct sockaddr *)&name, sizeof(name)) < 0) {
      close(sock);
      fprintf(stderr, "socket bind error\n");
      exit(1);
   }

   /* set up the srtp policy and master key */
   /* authentication and encription using 128 bit */
   //srtp_crypto_policy_set_aes_gcm_128_8_auth(&policy.rtp);
   srtp_crypto_policy_set_rtp_default(&policy.rtp);
   srtp_crypto_policy_set_rtcp_default(&policy.rtcp); //rtcp not used
   policy.ssrc.type = ssrc_specific;
   policy.ssrc.value = ssrc;
   policy.key = (uint8_t *)key;
   policy.next = NULL;
   policy.window_size = 128;
   policy.allow_repeat_tx = 0;
   policy.rtp.sec_serv = sec_serv_conf_and_auth;
   policy.rtcp.sec_serv = sec_serv_none; /* we don't do RTCP anyway */

   expected_len = policy.rtp.cipher_key_len * 2;
   len = hex_string_to_octet_string(key, input_key, expected_len);
   /* check that hex string is the right length */
   if (len < expected_len) {
      fprintf(stderr, "error: too few digits in key/salt (should be %d digits, found %d)\n",expected_len, len);
            exit(1);
   }
   if ((int)strlen(input_key) > policy.rtp.cipher_key_len * 2) {
      fprintf(stderr, "error: too many digits in key/salt (should be %d hexadecimal digits, found %u)\n",policy.rtp.cipher_key_len * 2, (unsigned)strlen(input_key));
            exit(1);
   }
   printf("set master key/salt to %s/", octet_string_hex_string(key, 16));
   printf("%s\n", octet_string_hex_string(key + 16, 14));


   /* main data pipeline */
   rcvr = rtp_receiver_alloc();
   if (rcvr == NULL) {
      fprintf(stderr, "error: malloc() failed\n");
      exit(1);
   }
   rtp_receiver_init(rcvr, sock, name, ssrc);
   status = rtp_receiver_init_srtp(rcvr, &policy);
   if (status) {
      fprintf(stderr, "error: srtp_create() failed with code %d\n", status);
      exit(1);
   }

   fd_to = open(TO_FILE, O_WRONLY | O_CREAT | O_APPEND | O_EXCL, 0666);
   if(fd_to < 1)
      return -1;

   while (1) {
      len = BUFFER_SIZE;
      nwritten = 0;
      memset(buf, 0, BUFFER_SIZE);
      if (rtp_recvfrom(rcvr, buf, &len) > -1){
         printf("Bytes received: %d \n", len);
         nwritten = write(fd_to, buf, len);
         printf("Bytes written: %d \n", nwritten);
      }
   }

   /* deinitialization */
   rtp_receiver_deinit_srtp(rcvr);
   rtp_receiver_dealloc(rcvr);
   close(fd_to);
   ret = close(sock);
   if (ret < 0) {
      fprintf(stderr, "Failed to close socket\n");
   }
   status = srtp_shutdown();
   if (status) {
       printf("error: srtp shutdown failed with error code %d\n", status);
       exit(1);
   }

   return 0;
}
