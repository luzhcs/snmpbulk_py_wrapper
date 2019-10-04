project(snmp_mon)

LINK_LIBRARIES ( netsnmp )
add_executable(snmp_mon snmp_client/simple_snmp_mon.cpp )