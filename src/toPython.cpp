#include "ReSession.h"

extern "C" {
    ReSession* ReSession_new() {
        return new ReSession();
    }

    int ReSession_analyze(ReSession* obj, char* file, char* output_path) {
        return obj->analyze_pcap_file(file, output_path);
    }
}