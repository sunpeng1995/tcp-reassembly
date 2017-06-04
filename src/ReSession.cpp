#include "ReSession.h"
//#define DEBUG
//#define RESULT_PRINT

int ReSession::analyze_pcap_file(std::string path, std::string out_path) {
  in.open(path, std::ios::binary);
  out.open(path + ".txt");
  pcap_hdr_t fileh;
  in.read(any2char<pcap_hdr_t*>(&fileh), sizeof(fileh));

  // check the file format
  if (fileh.magic_number != pcapfile_magic_number) {
#ifdef RESULT_PRINT
    std::cout << "not a pcap file" << std::endl;
#endif // RESULT_PRINT
    return 1;
  }
  _fileh = fileh;
  _path_prefix = out_path;

  // analyze the packet layer by layer
  while (!in.eof()) {
    analyze_pcaprec();
  }

  // reassemble segment
  reassemble_seg();

  in.close();
  out.close();
  return 0;
}

void ReSession::analyze_pcaprec() {
  pcaprec_hdr_t pcaprec;
  in.read(any2char<pcaprec_hdr_t*>(&pcaprec), sizeof(pcaprec));
  if (in.eof()) {
    return;
  }
  std::streampos next = in.tellg() + static_cast<std::streampos>(pcaprec.incl_len);

  pack_struct ph;
  ph.pcap_offset_beg = in.tellg() - static_cast<std::streampos>(sizeof(pcaprec));
  ph.pcap_len = pcaprec.incl_len + sizeof(pcaprec);

  analyze_ether_pac(ph);

  // Seek to next pcaprec
  in.seekg(next);
}

void ReSession::analyze_ether_pac(pack_struct& ph) {
  ether_hdr_t etherh;
  in.read(any2char<ether_hdr_t*>(&etherh), sizeof(etherh));
#ifdef DEBUG
  std::cout << "type:" << std::hex << std::setw(2) << std::setfill('0') << +etherh.type[0];
  std::cout << std::hex << std::setw(2) << std::setfill('0') << +etherh.type[1] << std::endl;
#endif // DEBUG

  // if packet is not ip packet, throw it
  if (etherh.type[0] != 0x08 || etherh.type[1] != 0) {
    return;
  }

  analyze_ip_pac(ph);
}

void ReSession::analyze_ip_pac(pack_struct& ph) {
  ip_hdr_t iph;
  in.read(any2char<ip_hdr_t*>(&iph), sizeof(iph));

  // if packet is not tcp packet, throw it
  if (iph.protocol != 0x06) { // TCP protocol number
    return;
  }

  int r = (iph.ver_ihl & 0x0f) - 5;
  if (r) {
    in.seekg(in.tellg() + static_cast<std::streampos>(r * 4));
  }

  ph.ip_dest = iph.dest_ip;
  ph.ip_src = iph.src_ip;

  int ip_header_len = (5 + r) * 4;
  int tcp_header_len;

  analyze_tcp_pac(ph, tcp_header_len);

  swap16(any2char<uint16_t*>(&iph.tot_len));

  // record tcp payload data length
  uint64_t data_len = iph.tot_len - ip_header_len - tcp_header_len;
  ph.offset_beg = in.tellg();
  ph.data_len = data_len;

  hash_packet(ph);

  add_to_bucket(ph);

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
  std::cout << "ack_num:" << ph.ack_num << std::endl;
  std::cout << "data_len:" << ph.data_len << std::endl;
  std::cout << "hash_code:" << ph.hash_code << std::endl;
  std::cout << "psh_flag:" << ph.psh_flag << std::endl;
  std::cout << std::endl;
#endif // DEBUG

}

void ReSession::analyze_tcp_pac(pack_struct& ph, int& tcp_header_len) {
  tcp_hdr_t tcph;
  in.read(any2char<tcp_hdr_t*>(&tcph), sizeof(tcph));

  int r = (tcph.offset>>4 & 0xf) - 5;
  if (r) {
    in.seekg(in.tellg() + static_cast<std::streampos>(r * 4));
  }

  // convert network digital pattern to integer
  swap16(any2char<uint16_t*>(&tcph.dest_port));
  swap16(any2char<uint16_t*>(&tcph.src_port));
  swap32(any2char<uint32_t*>(&tcph.seq_num));
  swap32(any2char<uint32_t*>(&tcph.ack_num));

  ph.port_dest = tcph.dest_port;
  ph.port_src = tcph.src_port;
  ph.seq_num = tcph.seq_num;
  ph.ack_num = tcph.ack_num;

  // record PSH flag, will be used in reassembling
  ph.psh_flag = tcph.flags & 0b00001000;

  tcp_header_len = (5 + r) * 4;
}

// use seq_num and ack_num to order the tcp packet
void ReSession::add_to_bucket(pack_struct& ph) {
  if (tcp_bucket.find(ph.hash_code) == tcp_bucket.end()) {
    tcp_bucket[ph.hash_code] = std::vector<pack_struct>();
  }
  std::vector<pack_struct> *v = &tcp_bucket[ph.hash_code];
  if (v->empty()) {
    v->push_back(ph);
  }
  if (v->back().ip_dest == ph.ip_dest) {
    // The packet behind the last packet in vector
    if (v->back().seq_num + v->back().data_len <= ph.seq_num) {
      v->push_back(ph);
    }
    // Find the position where the packet should be
    else {
      for (int i = v->size() - 2; i >= 0; i--) {
        if ((*v)[i].ip_dest == ph.ip_dest 
          && (*v)[i].seq_num + (*v)[i].data_len <= ph.seq_num) {
          v->insert(v->begin() + i + 1, ph);
          break;
        }
        // If have not match, throw the packet
      }
    }
  }
  else {
    if (v->back().ack_num == ph.seq_num) {
      v->push_back(ph);
    }
    // Else throw the packet
  }
}

void ReSession::reassemble_seg() {
  for (auto it : tcp_bucket) {
    if (!it.second.empty() &&
      (it.second[0].port_dest == 80 || it.second[0].port_src == 80)) {
      in.clear();

      print_pentuple(it.second[0]);

      std::stringstream ss;
      ss << _path_prefix;
      if (it.second[0].ip_dest < it.second[0].ip_src) {
        ss << "TCP[" << ip2str(it.second[0].ip_dest) << "]["
          << it.second[0].port_dest << "]["
          << ip2str(it.second[0].ip_src) << "]["
          << it.second[0].port_src << "].pcap";
      }
      else {
        ss << "TCP[" << ip2str(it.second[0].ip_src) << "]["
          << it.second[0].port_src << "]["
          << ip2str(it.second[0].ip_dest) << "]["
          << it.second[0].port_dest << "].pcap";
      }
      // Log subfile to ui
      _sub_pcap_files << ss.str() << std::endl;

      std::ofstream pcap_out(ss.str(), std::ios::binary);
      pcap_out.write(any2char<pcap_hdr_t*>(&_fileh), sizeof(_fileh));

      bool start = false;
      char http_h[4], data[2048];
      for (auto v : it.second) {
        // find a http request, start from there
        if (!start) {
          in.seekg(v.offset_beg);
          in.read(http_h, 3);
          http_h[3] = 0;
          start = check_http_h(http_h);
        }
        if (start) {
          //in.seekg(v.offset_beg);
          in.seekg(v.pcap_offset_beg);
          //in.read(data, v.data_len);
          in.read(data, v.pcap_len);
#ifdef RESULT_PRINT
          data[v.data_len] = 0;
          std::cout << data;
#endif // RESULT_PRINT
          out.write(data + (v.offset_beg - v.pcap_offset_beg), v.data_len);
          pcap_out.write(data, v.pcap_len);
          if (v.psh_flag) {
#ifdef RESULT_PRINT
            std::cout << std::endl << std::endl;
#endif // RESULT_PRINT
            out << std::endl;
          }
        }
      }
      pcap_out.close();
    }
  }
}

void ReSession::print_pentuple(pack_struct& ph) {
#ifdef RESULT_PRINT
  std::cout << std::endl << std::endl << "TCP ";
  std::cout << std::dec << "ip1:" 
    << (ph.ip_dest & 0x000000ff) << "."
    << (ph.ip_dest>>8 & 0x000000ff) << "."
    << (ph.ip_dest>>16 & 0x000000ff) << "."
    << (ph.ip_dest>>24 & 0x000000ff) << " ";
  std::cout << "port1:" << ph.port_dest << " ";
  std::cout << std::dec << "ip2:" 
    << (ph.ip_src & 0x000000ff) << "."
    << (ph.ip_src>>8 & 0x000000ff) << "."
    << (ph.ip_src>>16 & 0x000000ff) << "."
    << (ph.ip_src>>24 & 0x000000ff) << " ";
  std::cout << "port2:" << ph.port_src << std::endl << std::endl;
#endif // RESULT_PRINT

  out << std::endl << std::endl << "TCP ";
  out << std::dec << "ip1:" << ip2str(ph.ip_dest) << " ";
  out << "port1:" << ph.port_dest << " ";
  out << std::dec << "ip2:" << ip2str(ph.ip_src) << " ";
  out << "port2:" << ph.port_src << std::endl << std::endl;
}
