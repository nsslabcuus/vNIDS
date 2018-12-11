// -*- c-basic-offset: 4 -*-
/*
 * settimestamp.{cc,hh} -- set timestamp annotations
 * Douglas S. J. De Couto, Eddie Kohler
 * based on setperfcount.{cc,hh}
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2005 Regents of the University of California
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/logger.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>

#include "signature_hw.hh"

CLICK_DECLS

SignatureDetector::SignatureDetector() {
  std::string sig(
      "BvOt8TlPN8qv6+clMm2MSXU2XvJaWVoKi2svokE1MyXOKmQ+0QGcOk+6qIcYO4tDieki+4pQ8K4c8i99B8TGDA== \
        EjE8pNnVRCnWz7ppsuOmA4IMz3YG3CkursXp8et7C7ZUSnXtQHCM9cfRFKWQ0aQT8TZV+McatJMlzb4dSCPACw== \
        rkMleTBaU5CdrIYBdDc3avyNFT4CEZhl1afgCAMkgdAOpgmbkMnhrFT09nDLxHCr3IKoxNfiRtZf2X2OfU8xBA== \
        SAq1vCpdMxgww2GDQnKwmTXcfIkxIlZf7SmehMx3w6iRR0swNjBQHIO8EoT0+sb3M/iUIFIXAvQiOwYF8DhvCQ== \
        TfBW43Zne3NZo0fWejxlix1WnTokx8VM1Uo2AAST5vovPqR2pR6npuAMqaaW2Uix7HucYoLzEdrwU7D9l/OuDQ== \
        ng9eNvAYL9g2EG7OTCQvcQFyeL3juoVJWtsES/Nv2s50a+HdBPmNHXAUTeroaOBLyUmtjtozE8IUDdr+BrcxCA== \
        IfSouOs5CTkJOMfn8Zgy20kYO5xH7uy+8bnE//ljkNETeC1JRFfl1yGuzqmthe0NJDiIQeMRMI74DtuwHliXBA== \
        qDJ+8pqt3v4rJI+nNpqpNpnzKCLXnbRFeof/DGVNNSZP2Z1lqf4K6eAJfIUdH3nojtG5TOk9FJwpUzh0un71Dw== \
        wZu91CZUd5R+hLCJWfi3u75RipPp7sKeUET3FPdzC+SH9nI/8+BqK1wvFoCLOG65vMKZmT6Ly+F+D6XdFBOZDg== \
        ZSHlbeXojQn/8PJ7QHa9n9UaNBQYAOMCnSdiRtRkjYMGHgOxXbO6M+A66ojUj8NahC25hovesws1eaqNvGL/BQ== \
        GmaONq4YuJDbcjW4blJU1pZ+1BpNQ1qSFajxoiTMjbfpHZayl7m4hLzI74J+hPQx+1wzxrvGpCf6EQ7NievzCQ== \
        2VOyuTSBvhZ3ehTTDTWaqUmd4JhcuBW9hAqLBILuf/0gnxQaRadZ/a3qVOQbMThzWA+pRbZZ6DX8N7JZwxr6AA== \
        4Ab/8hoNpYZwAJwvP4wOLgm9plTkVMZ1KCZrj9SsJfjg75xbccuo/kkmhOEPOivR4Yb8efRx+grHNUWr9KMVAg== \
        oLQ+BQjfUq7PPShwcmTgQ97n09gv182wfeCJXFA4OKKtALkowBsNVJuVvA4QWXP7uNZpkWF0aCeSDJMJSMQACA== \
        pcq8FR0/p7E+spbcRqNUE9Jle3+jiDXxkR0iG9j2nSSNNeaEyfhESEEKOFFCSPaDg4TocJmAklOvvJ5MZDbqDg== \
        FepDNcjQRzZ0sRDylij6pM6RfNbXiaziWAS1RbZKDSWDKy358qH0OGFsilQ1xsQSooeZyOjU53ZwKoLgNP0eDw== \
        2I62GjT389hD0KhnwRwgmZmP6TNQsyKNQ7loRuWN+T101bFfdDHnOILE/IhYUeHfWsBehMdk0LEp/DuDNP/hAA== \
        kjQUI6eKaqv0Qp+jDTooBsW38fVHfzjh0NTsMRLYxd1fd5zsbsq+gAbreVKEN5CEXpARQS4Zrz9T//6NC3WEDw== \
        F2lyvHMNMysfbDdQB7g+o1QgpWgGlya4aKazgt+AiACKUm4L+54TKGCjM66lr/doP9UoLWGmr0Jru8aK3GTqBw== \
        vw+EZJpB7Xlk6dAD6gXDlD3xYn5LOJD3a+jjKofdHazK3++VSlOTDG25z5MKjx8zmjNyM1TPW7hGFzDSSF56Dw== \
        cmuw2iMLj39JhegnEshSk15qoUOYHw90jv7EWXiBIrEFd1PbkXHOYfa840XttigAATb7hRnFknFhByrrMecZCQ== \
        zBvJxCHGFsym9vfEjiF9mnxyLs8FWYAGWr0e9AjqDnOaxZIzGsRMTwu1rpaBurPlYLrn+NAQdXoHd8KG0hWsCA== \
        7JQLT4n/cowUb5C+OzJIKtxYtgcYbb7w2vRpPYnmocEaYj+vKS/PsHgN+4sTTxfuQmKnv38O6jx1eRjN7oH/BQ== \
        IjRUlR9YGH2qsu1waZVnE6HpkOkD+dR7T7SFd54oHRI8+6V1mpgOba601ck14FwbF9Nfdc8c2G4KSjpSxHPuBg== \
        Vo1ZP6Q3s1BP1Z2XQtydjKjQan4o4EVDD7K2P0BamDlEEmPdtJrM+gdgEa1LH+4Sn3oNmuMAs45UrAl8gJUTDQ== \
        LQh02zxcLj0IWJUCP5FDdAbRtb4L+Rys7zXQ2oca8N5q6FDdn52QbEEW/CkDEYpN2+EOkKsnylEeuDhGSBZECQ== \
        lt47SwpWPCfE0T8SZ04Gam8xaCDTz5ZoPolfqNXylHo4GSIGwB2l6Tzk865iqbbZSbOjUBSznaIzCr8kZ1oyCg== \
        iKMoek0iL1FVZR/hE7b+t2aqgQoQyTwKwejGfGED+Qm1pTYrGbqDsugRKU1y8KeVQAFZ0rx3U1pLKLP2r/HNCA== \
        e/PqAQZgWTGd/Rao0qS6WaBDtLKnyNQN0wyptlDk61N518+IUj3sBAoGN17viS/BcNdeIOK++cgEVySrM3oWAQ== \
        YJHSsCGaq4dn1ofADUtAp2Xna6XNg19S7o/7t72C6FMOpJ/GPigN0YvABRPH1XxKsO3LSOlBgTJHXILNljNFAQ== \
        U/ejNJFasoIsJqpUEmVEfoHID7FBUMbyR8E8oULOcj0c2Y8lB1gGiWfoL98+FLa5nCoz4N04KOnpbuRiiwmLCw== \
        6G3gzxM2q8x1q5gzKEBoseFwEqhzvHxTvlExfEQSYWmu/1xb6ikWGY1uktxDBG2/wX/dyy3KHYA6R31084IvCg== \
        vmUcL2ZSP3dyrK8FCaELPlfGazaKfQbX8v5F6WpR0CfzwoukBAtsC6j08GU3AWb9xq8vDMsuAuNtt9ZMGMrQBQ== \
        qv5jQmYQ7dmaITmj79u3F/9sCyndAJ1asoBiZoXY4c0ImJ9xUTE5H9EJCY/mAEAOhT1xueDNd3BBdam+vzSqBQ== \
        YNJP4QYB1+jE3L1p3O2RZfYmb81dVN18+8XvjE0XmUH6HfjEZOE2RsyOAyT6PwWTqrErZ34Wb25dR/97YV+SCw== \
        DVv2R+BCmLVQEDlZtZ1Xckw0CKcvdmmY81f9PCJwxNCtjw6Lo5XE6kRq67GmTXn7Z9ItRP9qEDChPvPdyQppBA== \
        utQinIQOZJI3Kp/NFWQu7rW6cuRy5QAVqCxbc8tBu/J7nnQj+YKymQYyT5sjf8s/uNZyWwyR2rmTYnFufRU/Cw== \
        ATWi5co5zr9bncm/Q1HZ0qZrqkGSCI7huxCkE9Drwz2aTHBrIl7fJmy09PIER55s9vYaRfCaLCbznIbqWdqRCQ== \
        7Ua11lFHsp/w50uKgFWGb0ceB6gAqSsSTCi0TZAEPUjad5h+wddm/bJSyj17GWEaE1pdooCFHE5Rw9+AlvTtCQ== \
        8Ulv7SRyl95YscWQwzlNIbAiG+DN6qtBQKf9bgbixB9hFk2yvZW4djFh1w/NIiPO5aE8+kYWZmnGMc+Iv590Dg==");
  std::stringstream ss(sig);

  std::string str;
  while (ss >> str) {
    signatures.push_back(str);
  }
}

void SignatureDetector::get_next(std::string& pattern, std::vector<int>& next) {
  size_t len = pattern.size();

  for (size_t i = 0; i < len; next.push_back(0), ++i)
    ;

  next[0] = -1;

  int k = -1;
  size_t j = 0;

  while (j < len - 1) {
    if (k == -1 || pattern[j] == pattern[k]) {
      ++j;
      ++k;

      if (pattern[j] != pattern[k]) {
        next[j] = k;
      } else {
        next[j] = next[k];
      }
    } else {
      k = next[k];
    }
  }
}

void SignatureDetector::get_nexts() {
  for (size_t i = 0; i < signatures.size(); i++) {
    std::vector<int> next;
    get_next(signatures[i], next);
    nexts.push_back(next);
  }
}

int SignatureDetector::initialize(ErrorHandler*) {
  get_nexts();

  return 0;
}

bool SignatureDetector::compare(std::string& str1, std::string& str2,
                                std::vector<int>& next) {
  int i = 0, j = 0, len1 = str1.size(), len2 = str2.size();

  while (i < len1 && j < len2) {
    if (j == -1 || str1[i] == str2[j]) {
      i++;
      j++;
    } else {
      j = next[j];
    }
  }

  return j == len2;
}
bool SignatureDetector::compare(std::string& str) {
  for (size_t i = 0; i < signatures.size(); ++i) {
    if (compare(str, signatures[i], nexts[i])) {
      return true;
    }
  }

  return false;
}

Packet* SignatureDetector::simple_action(Packet* p) {
  const unsigned char* data = p->data();
  std::string str((char*)data);

  if (compare(str)) {
    p->kill();
  }

  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SignatureDetector)
