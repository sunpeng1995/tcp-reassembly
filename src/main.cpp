#include "ReSession.h"

int main() {
  ReSession res;
  res.analyze_pcap_file("../test/test_gethtml_stream1.pcap");
  system("pause");
  return 0;
}