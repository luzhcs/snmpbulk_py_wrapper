project(snmpbulkwalk)

 include(CheckCXXCompilerFlag)
 CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
 CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
 if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
  elseif(COMPILER_SUPPORTS_CXX0X)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
 else()
    message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C    ++ compiler.")
 endif()

INCLUDE_DIRECTORIES(snmp_client/include/)
LINK_LIBRARIES ( netsnmp pthread )
add_executable(snmpbulkwalk snmp_client/snmpbulkwalk.cpp  snmp_client/main.cpp)

#ADD_LIBRARY ( snmp_mon SHARED snmp_client/simple_snmp_mon.cpp )