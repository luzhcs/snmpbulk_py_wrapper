#include "snmpbulkwalk.hpp"

int main (){

    vector<string> mgmt_list_sample;

    mgmt_list_sample.push_back("demo.snmplabs.com");
    //mgmt_list_sample.push_back("demo.snmplabs.com");

    luzhcs::snmpbulkwalk test_snmp(mgmt_list_sample);

    return 0;
}