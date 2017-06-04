#include "ReSession.h"

int main() {
  ReSession res;

  // Result saves in test/test1.pcap.txt
  res.analyze_pcap_file("test/test.pcap","test/pcap/");

  system("pause");
  return 0;
}