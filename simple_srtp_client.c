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
#include <arpa/inet.h>

#include "srtp.h"    /* libsrtp includes */
#include "rtp.h"    /* convenience wrappers over libsrtp -- need refinement error fixes for making generic strcpy used*/
#include "util.h"   /* Utilities used by the test apps -- need refinement error fixes for making generic */

#define FROM_FILE "dur.txt"
#define BUFFER_SIZE 1024
#define USEC_RATE 100
#define SERVER_ADDRESS "127.0.0.1"
#define PORT 12345
#define MAX_KEY_LEN 96
#define KEY_VAL "c1eec3717da76195bb878578790af71c4ee9f859e197a414a78d5abc7451"

int main()
{
   rtp_sender_t snd;
   int sock, ret;
   int fd_from;
   ssize_t nread;
   char buf[BUFFER_SIZE];
   struct sockaddr_in name;
   srtp_policy_t policy;
   srtp_err_status_t status;
   uint32_t ssrc = 0xdeadbeef; /* ssrc value hardcoded for now */
   struct in_addr rcvr_addr;
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

   if (0 == inet_aton(SERVER_ADDRESS, &rcvr_addr)) {
      fprintf(stderr, "cannot parse IP v4 address\n");
      exit(1);
   }
   if (rcvr_addr.s_addr == INADDR_NONE) {
      fprintf(stderr, "address error");
      exit(1);
   }

   /* open socket */
   sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if (sock < 0) {
      fprintf(stderr, "couldn't open socket\n");
      exit(1);
   }
   memset(&name, 0, sizeof(struct sockaddr_in));
   name.sin_addr = rcvr_addr;
   name.sin_family = PF_INET;
   name.sin_port = htons(PORT);

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
   snd = rtp_sender_alloc();
   if (snd == NULL) {
      fprintf(stderr, "error: malloc() failed\n");
      exit(1);
   }
   rtp_sender_init(snd, sock, name, ssrc);
   status = rtp_sender_init_srtp(snd, &policy);
   if (status) {
       fprintf(stderr, "error: srtp_create() failed with code %d\n", status);
       exit(1);
   }

   fd_from = open(FROM_FILE, O_RDONLY);
   if (fd_from < 1)
       return -1;
   
   while(nread = read(fd_from, buf, sizeof (buf)), nread > 0)
   {
      printf("Bytes read: %d \n", nread);
      rtp_sendto(snd, buf, nread);
      usleep(USEC_RATE);
   }

   /* deinitialization */
   rtp_sender_deinit_srtp(snd);
   rtp_sender_dealloc(snd);
   close(fd_from);
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
