#include "snmpbulkwalk.hpp"

 vector<string> inline split(string str, char delimiter) {
    vector<string> internal;
    stringstream ss(str);
    string temp;
 
    while (getline(ss, temp, delimiter)) {
        internal.push_back(temp);
    }
 
    return internal;
}

namespace luzhcs {
    snmpbulkwalk::snmpbulkwalk(vector<string>  mgmt_ip_list){
        std::vector<std::thread> thread_list;
        struct snmp_session session, *ss;
        SOCK_STARTUP;
        for (int i = 0; i < mgmt_ip_list.size(); ++i){
            std::cout<<mgmt_ip_list[i]<<std::endl;
            snmp_sess_init( &session );                   
            session.peername = (char *) mgmt_ip_list[i].c_str();
            session.version=SNMP_VERSION_2c;
            session.community = (u_char *)"public";
            session.community_len = strlen((char*) session.community);

            ss = snmp_open(&session);
            if (!ss) {
                snmp_sess_perror("ack", &session);
            } else {
                std::cout<<session.peername << " is connected!" <<std::endl;
            }

            thread_list.push_back(thread(&luzhcs::snmpbulkwalk::get_switch_snmp_info, this, mgmt_ip_list[i], ss));
        }

        std::chrono::system_clock::time_point start = std::chrono::system_clock::now();

        for (int i = 0; i < thread_list.size(); ++i){
            thread_list[i].join();
        }

        std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
        std::chrono::duration<double> sec = std::chrono::system_clock::now() - start;
        std::cout << "elapsed time : " << sec.count() << " seconds" << std::endl;

        SOCK_CLEANUP;
    }

    vector<string> snmpbulkwalk::get_index_list(string mgmt_ip, struct snmp_session *ss){

        if (!ss) std::cout<<"mgmt_ip : "<<mgmt_ip<<" has errors"<<std::endl;
        
        struct snmp_pdu *pdu;
        struct snmp_pdu *response;
        struct variable_list *vars;
        vector<string> ifindxs;
        
        int             count;
        int             running;
        int             status = STAT_ERROR;
        int             check;
        int             exitval = 0;

        int             numprinted = 0;
        int             reps = 3, non_reps = 0;

        oid root[MAX_OID_LEN];
        size_t rootlen = MAX_OID_LEN;
        oid name[MAX_OID_LEN];
        size_t name_length;
        
        char temp_buf[BUFSIZ];
        size_t temp_buf_len = BUFSIZ;

        pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
        pdu->non_repeaters = non_reps;
        pdu->max_repetitions = reps;    /* fill the packet */

        
        
        if (snmp_parse_oid(ifIndex, root, &rootlen) == NULL) {
            snmp_perror(ifIndex);
            SOCK_CLEANUP;
        }


        snmp_add_null_var(pdu, root, rootlen);

        memmove(name, root, rootlen * sizeof(oid));
        name_length = rootlen;

        running = 1;

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
                        //print_variable(vars->name, vars->name_length, vars);
                        
                        snprint_variable(temp_buf, temp_buf_len, vars->name, vars->name_length, vars);
                        cout<< temp_buf <<endl;

                         vector<string> tmp = split(temp_buf, ': ');
                         ifindxs.push_back(tmp[tmp.size() - 1]);

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
                        ss->peername);
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
        
        for (int i = 0; i < ifindxs.size(); ++i){
            cout<<"index: "<<ifindxs[i]<<endl;
        }

        return ifindxs;

    }

    void snmpbulkwalk::get_switch_snmp_info(string mgmt_ip, struct snmp_session *ss){
        if (!ss) std::cout<<"mgmt_ip : "<<mgmt_ip<<" has errors"<<std::endl;
        
        struct snmp_pdu *pdu;
        struct snmp_pdu *response;
        struct variable_list *vars;
        
        int             count;
        int             running;
        int             status = STAT_ERROR;
        int             check;
        int             exitval = 0;

        int             numprinted = 0;
        int             reps = 3, non_reps = 0;

        oid root[MAX_OID_LEN];
        size_t rootlen = MAX_OID_LEN;
        
        char temp_buf[BUFSIZ];
        size_t temp_buf_len = BUFSIZ;

        vector<oid_info> oid_info_list;
        oid_info tmp_oid;

        pdu = snmp_pdu_create(SNMP_MSG_GET);
        pdu->non_repeaters = non_reps;
        pdu->max_repetitions = reps;    /* fill the packet */

        vector<string> ifindxs = get_index_list(mgmt_ip, ss);

        for (int j =0 ; j < ifindxs.size(); j++){
            for (int i =0; i < oid_if_list.size(); i ++ ){
                oid root[MAX_OID_LEN];
                size_t rootlen = MAX_OID_LEN;
                string tmp = oid_if_list[i] + "." + ifindxs[j];
                if (snmp_parse_oid(tmp.c_str(), root, &rootlen) == NULL) {
                    snmp_perror(tmp.c_str());
                    SOCK_CLEANUP;
                }
                snmp_add_null_var(pdu, root, rootlen);
            }
        }
        
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
                    vars = vars->next_variable)
                    print_variable(vars->name, vars->name_length, vars);
            } else {
                /*
                * error in response, print it 
                */
                if (response->errstat == SNMP_ERR_NOSUCHNAME) {
                    printf("End of MIB.\n");
                } else {
                    fprintf(stderr, "Error in packet.\nReason: %s\n",
                            snmp_errstring(response->errstat));
                    if (response->errindex != 0) {
                        fprintf(stderr, "Failed object: ");
                        for (count = 1, vars = response->variables;
                            vars && (count != response->errindex);
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
                    ss->peername);
            exitval = 1;
        } else {                    /* status == STAT_ERROR */
            snmp_sess_perror("snmpbulkget", ss);
            exitval = 1;
        }

        if (response)
            snmp_free_pdu(response);

        snmp_close(ss);

       
    }

    void snmpbulkwalk::get_port_stat_list(){

    }
}