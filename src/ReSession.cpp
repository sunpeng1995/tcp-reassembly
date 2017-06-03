#include "ReSession.h"
#define DEBUG

void ReSession::analyze_pcap_file(std::string path) {
  in.open(path, std::ios::binary);
  pcap_hdr_t fileh;
  in.read(any2char<pcap_hdr_t*>(&fileh), sizeof(fileh));
  if (fileh.magic_number != pcapfile_magic_number) {
#ifdef DEBUG
    std::cout << "not a pcap file" << std::endl;
#endif // DEBUG
    return;
  }

  //if (!in.eof()) {
  //  analyze_pcaprec();
  //}
  analyze_pcaprec();
  analyze_pcaprec();
}

void ReSession::analyze_pcaprec() {
  pcaprec_hdr_t pcaprec;
  in.read(any2char<pcaprec_hdr_t*>(&pcaprec), sizeof(pcaprec));
  std::streampos next = in.tellg() + static_cast<std::streampos>(pcaprec.incl_len);

  analyze_ether_pac();



  in.seekg(next);
  
}

void ReSession::analyze_ether_pac() {
  ether_hdr_t etherh;
  in.read(any2char<ether_hdr_t*>(&etherh), sizeof(etherh));
#ifdef DEBUG
  std::cout << "type:" << std::hex << std::setw(2) << std::setfill('0') << +etherh.type[0];
  std::cout << std::hex << std::setw(2) << std::setfill('0') << +etherh.type[1] << std::endl;
#endif // DEBUG
  if (etherh.type[0] != 0x08 || etherh.type[1] != 0) {
    return;
  }

  analyze_ip_pac();
}

void ReSession::analyze_ip_pac() {
  ip_hdr_t iph;
  in.read(any2char<ip_hdr_t*>(&iph), sizeof(iph));

  if (iph.protocol != 0x06) { // TCP protocol number
    return;
  }

  int r = (iph.ver_ihl & 0x0f) - 5;
  if (r) {
    in.seekg(in.tellg() + static_cast<std::streampos>(r * 4));
  }

  pack_struct ph;
  ph.ip_dest = iph.dest_ip;
  ph.ip_src = iph.src_ip;

  int ip_header_len = (5 + r) * 4;
  int tcp_header_len;

  analyze_tcp_pac(ph, tcp_header_len);

  swap16(any2char<uint16_t*>(&iph.tot_len));

  ph.offset_beg = in.tellg();
  ph.offset_end = in.tellg() + static_cast<std::streampos>(iph.tot_len - ip_header_len - tcp_header_len);
#ifdef DEBUG
  std::cout << std::dec << "ip_dest:" 
    << (ph.ip_dest & 0x000000ff) << "."
    << (ph.ip_dest>>8 & 0x000000ff) << "."
    << (ph.ip_dest>>16 & 0x000000ff) << "."
    << (ph.ip_dest>>24 & 0x000000ff) << std::endl;
  std::cout << "port_dest:" << ph.port_dest << std::endl;

  std::cout << std::dec << "ip_src :" 
    << (ph.ip_src & 0x000000ff) << "."
    << (ph.ip_src>>8 & 0x000000ff) << "."
    << (ph.ip_src>>16 & 0x000000ff) << "."
    << (ph.ip_src>>24 & 0x000000ff) << std::endl;
  std::cout << "port_src :" << ph.port_src << std::endl;
  std::cout << "offset_beg:" << ph.offset_beg << std::endl;
  std::cout << "offset_end:" << ph.offset_end << std::endl;
  std::cout << std::hex << "seq_num:" << ph.seq_num << std::endl;
  std::cout << "ack_num:" << ph.ack_num << std::endl << std::endl;
#endif // DEBUG

}

void ReSession::analyze_tcp_pac(pack_struct& ph, int& tcp_header_len) {
  tcp_hdr_t tcph;
  in.read(any2char<tcp_hdr_t*>(&tcph), sizeof(tcph));

  int r = (tcph.offset>>4 & 0xf) - 5;
  if (r) {
    in.seekg(in.tellg() + static_cast<std::streampos>(r * 4));
  }
  swap16(any2char<uint16_t*>(&tcph.dest_port));
  swap16(any2char<uint16_t*>(&tcph.src_port));
  swap32(any2char<uint32_t*>(&tcph.seq_num));
  swap32(any2char<uint32_t*>(&tcph.ack_num));
  ph.port_dest = tcph.dest_port;
  ph.port_src = tcph.src_port;
  ph.seq_num = tcph.seq_num;
  ph.ack_num = tcph.ack_num;

  tcp_header_len = (5 + r) * 4;
}
