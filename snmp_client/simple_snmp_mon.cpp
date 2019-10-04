
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <iostream>
#include <chrono>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <net-snmp/net-snmp-includes.h>


int numprinted = 0;
int reps = 3, non_reps = 0;
   
static void
snmp_get_and_print(netsnmp_session * ss, oid * theoid, size_t theoid_len)
{
    netsnmp_pdu    *pdu, *response;
    netsnmp_variable_list *vars;
    int             status;

    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, theoid, theoid_len);

    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        for (vars = response->variables; vars; vars = vars->next_variable) {
            numprinted++;
            print_variable(vars->name, vars->name_length, vars);
        }
    }
    if (response) {
        snmp_free_pdu(response);
    }
}

class snmpbulkwalk {

};

int main (){

    struct snmp_session session, *ss;
    struct snmp_pdu *pdu;
    struct snmp_pdu *response;
    
            
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;
    
    struct variable_list *vars;
    
    oid             name[MAX_OID_LEN];
    size_t          name_length;
    oid             root[MAX_OID_LEN];
    size_t          rootlen;

    int             count;
    int             running;
    int             status = STAT_ERROR;
    int             check;
    int             exitval = 0;

    snmp_sess_init( &session );                   
    session.peername = "demo.snmplabs.com";
    session.version=SNMP_VERSION_2c;
    session.community = (u_char *)"public";
    session.community_len = strlen((char*) session.community);

    ss = snmp_open(&session);
    if (!ss) {
      snmp_sess_perror("ack", &session);
      SOCK_CLEANUP;
      exit(1);
    } else {
        std::cout<<session.peername << " is connected!" <<std::endl;
    }

    pdu = snmp_pdu_create(SNMP_MSG_GETBULK);

    std::cout<<"parsing oid ... "<<std::endl;
    rootlen = MAX_OID_LEN;

    if (snmp_parse_oid(".1.3.6.1.2.1.31.1.1.1.1", root, &rootlen) == NULL) {
      snmp_perror(".1.3.6.1.2.1.31.1.1.1.1");
      SOCK_CLEANUP;
      exit(1);
    }

    std::cout<<"parsing oid completed "<<std::endl;


    memmove(name, root, rootlen * sizeof(oid));
    name_length = rootlen;

    running = 1;
    std::cout<<"running snmpbulkwalk ... "<<std::endl;
    
    
    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
    while (running) {
        /*
         * create PDU for GETBULK request and add object name to request 
         */
        pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
        pdu->non_repeaters = non_reps;
        pdu->max_repetitions = reps;    /* fill the packet */
        snmp_add_null_var(pdu, name, name_length);

        /*
         * do the request 
         */
        status = snmp_synch_response(ss, pdu, &response);
        if (status == STAT_SUCCESS) {
            if (response->errstat == SNMP_ERR_NOERROR) {
                /*
                 * check resulting variables 
                 */
                for (vars = response->variables; vars;
                     vars = vars->next_variable) {
                    if ((vars->name_length < rootlen)
                        || (memcmp(root, vars->name, rootlen * sizeof(oid))
                            != 0)) {
                        /*
                         * not part of this subtree 
                         */
                        running = 0;
                        continue;
                    }
                    numprinted++;
                    print_variable(vars->name, vars->name_length, vars);
                    if ((vars->type != SNMP_ENDOFMIBVIEW) &&
                        (vars->type != SNMP_NOSUCHOBJECT) &&
                        (vars->type != SNMP_NOSUCHINSTANCE)) {
                        /*
                         * not an exception value 
                         */
                        if (check
                            && snmp_oid_compare(name, name_length,
                                                vars->name,
                                                vars->name_length) >= 0) {
                            fprintf(stderr, "Error: OID not increasing: ");
                            fprint_objid(stderr, name, name_length);
                            fprintf(stderr, " >= ");
                            fprint_objid(stderr, vars->name,
                                         vars->name_length);
                            fprintf(stderr, "\n");
                            running = 0;
                            exitval = 1;
                        }
                        /*
                         * Check if last variable, and if so, save for next request.  
                         */
                        if (vars->next_variable == NULL) {
                            memmove(name, vars->name,
                                    vars->name_length * sizeof(oid));
                            name_length = vars->name_length;
                        }
                    } else {
                        /*
                         * an exception value, so stop 
                         */
                        running = 0;
                    }
                }
            } else {
                /*
                 * error in response, print it 
                 */
                running = 0;
                if (response->errstat == SNMP_ERR_NOSUCHNAME) {
                    printf("End of MIB\n");
                } else {
                    fprintf(stderr, "Error in packet.\nReason: %s\n",
                            snmp_errstring(response->errstat));
                    if (response->errindex != 0) {
                        fprintf(stderr, "Failed object: ");
                        for (count = 1, vars = response->variables;
                             vars && count != response->errindex;
                             vars = vars->next_variable, count++)
                            /*EMPTY*/;
                        if (vars)
                            fprint_objid(stderr, vars->name,
                                         vars->name_length);
                        fprintf(stderr, "\n");
                    }
                    exitval = 2;
                }
            }
        } else if (status == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No Response from %s\n",
                    session.peername);
            running = 0;
            exitval = 1;
        } else {                /* status == STAT_ERROR */
            snmp_sess_perror("snmpbulkwalk", ss);
            running = 0;
            exitval = 1;
        }
        if (response)
            snmp_free_pdu(response);
    }

    if (numprinted == 0 && status == STAT_SUCCESS) {
        snmp_get_and_print(ss, root, rootlen);
    }

    std::chrono::system_clock::time_point end = std::chrono::system_clock::now();

    std::chrono::duration<double> sec = std::chrono::system_clock::now() - start;

    std::cout << "elapsed time : " << sec.count() << " seconds" << std::endl;

    snmp_close(ss);

    SOCK_CLEANUP;
    return exitval;


    

    return 0;
}
