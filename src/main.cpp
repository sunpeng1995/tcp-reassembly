#include "ReSession.h"

int main() {
  ReSession res;

  // Result saves in test/test1.pcap.txt
  res.analyze_pcap_file("test/test1.pcap");

  system("pause");
  return 0;
}