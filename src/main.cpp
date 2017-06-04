#include "ReSession.h"

int main() {
  ReSession res;
  res.analyze_pcap_file("../test/test1.pcap");
  system("pause");
  return 0;
}