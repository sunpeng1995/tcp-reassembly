#include <iostream>
#include <fstream>
#include <iomanip>
#include <unordered_map>
#include <vector>
#include <cstring>

typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct ether_hdr_s {
  uint8_t dest[6];
  uint8_t src[6];
  uint8_t type[2];
  //uint16_t type;
} ether_hdr_t;

typedef struct ip_hdr_s {
  uint8_t ver_ihl;
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t flags;
  uint8_t tol;
  uint8_t protocol;
  uint16_t h_sum;
  uint32_t src_ip;
  uint32_t dest_ip;
} ip_hdr_t;

typedef struct tcp_hdr_s {
  uint16_t src_port;
  uint16_t dest_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint8_t offset;
  uint8_t flags;
  uint16_t win_size;
  uint32_t sum_pointer;
} tcp_hdr_t;

typedef struct {
  uint32_t ip_src;
  uint32_t ip_dest;
  uint16_t port_src;
  uint16_t port_dest;
  uint32_t seq_num;
  uint32_t ack_num;
  uint32_t data_len;
  uint64_t time_stamp;
  uint64_t hash_code;
  bool psh_flag;
  std::streampos offset_beg;
  std::streampos offset_end;
} pack_struct;

typedef struct {
  uint8_t a;
  uint8_t b;
  uint8_t c;
  uint8_t d;
} ip_struct;

class ReSession {
public:

  void analyze_pcap_file(std::string path);

private:
  std::ifstream in;
  std::ofstream out;

  const uint32_t pcapfile_magic_number = 0xa1b2c3d4;
  const char http_methods[8][4] = { "GET", "HEA", "POS", "PUT", "DEL", "CON", "OPT", "TRA" };

  std::unordered_map<uint64_t, std::vector<pack_struct>> tcp_bucket;


  void analyze_pcaprec();
  void analyze_ether_pac();
  void analyze_ip_pac();
  void analyze_tcp_pac(pack_struct& ph, int& tcp_header_len);
  void add_to_bucket(pack_struct& ph);
  void reassemble_seg();
  void print_pentuple(pack_struct& ph);



  template<typename T>
  inline char* any2char(T t) {
    return static_cast<char*>(static_cast<void*>(t));
  }

  inline void swap16(char* in) {
    uint8_t t = in[0];
    in[0] = in[1];
    in[1] = t;
  }
  inline void swap32(char* in) {
    uint8_t t0 = in[0], t1 = in[1];
    in[0] = in[3], in[1] = in[2];
    in[3] = t0, in[2] = t1;
  }

  inline void hash_packet(pack_struct& ph) {
    uint64_t hash = 17;
    if (ph.ip_src < ph.ip_dest) {
      hash = hash * 31 + ph.ip_src;
      hash = hash * 31 + ph.ip_dest;
    }
    else {
      hash = hash * 31 + ph.ip_dest;
      hash = hash * 31 + ph.ip_src;
    }
    if (ph.port_src < ph.port_dest) {
      hash = hash * 31 + ph.port_src;
      hash = hash * 31 + ph.port_dest;
    }
    else {
      hash = hash * 31 + ph.port_dest;
      hash = hash * 31 + ph.port_src;
    }
    ph.hash_code = hash;
  }

  inline bool check_http_h(char* h) {
    for (int i = 0; i < 8; i++) {
      if (strcmp(h, http_methods[i])) {
        return true;
      }
    }
    return false;
  }
};