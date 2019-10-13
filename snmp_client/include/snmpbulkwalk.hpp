#ifndef SNMPBULKWALK_H
#define SNMPBULKWALK_H

#include <string>
#include <iostream>
#include <vector>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <thread>
#include <sstream>

using namespace std;

#define ifIndex "1.3.6.1.2.1.2.2.1.1"
#define ifCRCError  "1.3.6.1.2.1.2.2.1.14"
#define ifHighSpeed "1.3.6.1.2.1.31.1.1.1.15"
#define ifHCInOctets "1.3.6.1.2.1.31.1.1.1.6"
#define ifHCOutOctets "1.3.6.1.2.1.31.1.1.1.10"
#define ifName "1.3.6.1.2.1.31.1.1.1.1"



namespace luzhcs {

    class snmpbulkwalk{
        struct port_stat {
            string port_id;
            uint64_t rx_byte;
            uint64_t tx_byte;
            uint64_t speed; 
            uint64_t crc_error;
        };
        struct snmp_info {
            string mgmt_ip;
            vector<snmpbulkwalk::port_stat> port_stat_list;
        };

        struct oid_info {
            string oid_str;
            oid root[MAX_OID_LEN];
            size_t rootlen = MAX_OID_LEN;
        };

        public:
            vector<string> oid_if_list = {ifName, ifCRCError, ifHighSpeed, ifHCInOctets, ifHCOutOctets};
            
            vector<snmpbulkwalk::snmp_info> snmp_info_list;
            snmpbulkwalk(vector<string>  mgmt_ip_list);
            void get_switch_snmp_info(string mgmt_ip, struct snmp_session * ss);
            vector<string> get_index_list(string mgmt_ip, struct snmp_session *ss);
            void get_port_stat_list();
    };
}


#endif /* SNMPBULKWALK_H */