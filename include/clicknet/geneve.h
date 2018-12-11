#ifndef CLICKNET_GENEVE_H
#define CLICKNET_GENEVE_H

/**@brief
 * https://tools.ietf.org/html/draft-ietf-nvo3-geneve-00#section-3.1
 */

struct click_geneve {
  uint8_t ver : 2;     /* 0: Ver */
  uint8_t opt_len : 6; /* Opt Len */
  uint8_t ocrsvd;      /* 1: o c rsvd */
  uint16_t protocol;   /* 2-3: Protocol Type */
  uint32_t vni_rvd;    /* 4-7: Virtual Network Identifier (VNI), Reserved */
  uint8_t opt[0];      /* Variable Length Options */
};

#endif
