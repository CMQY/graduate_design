#/**
# *  * filter policy
# *   */
S_ADDR_S=1
S_ADDR_M=2
D_ADDR_S=3
D_ADDR_M=4
DPORT_AND_PROTO=5
PROTO=6
S_ADDR_AND_DPORT_AND_PROTO_S=7
S_ADDR_AND_DPORT_AND_PROTO_M=8
S_ADDR_AND_PROTO_S=9
S_ADDR_AND_PROTO_M=10
D_ADDR_AND_DPORT_AND_PROTO_S=11
D_ADDR_AND_DPORT_AND_PROTO_M=12
D_ADDR_AND_PROTO_S=13
D_ADDR_AND_PROTO_M=14


#/*************************************
# *  * user space controller commond
# *   ************************************/

LSP_RULE_DEL=30
LSP_RULE_DEL_ALL=31

#/*************************************
# * responses from hook functions
# ************************************/
NF_DROP=0
NF_ACCEPT=1
NF_STOLEN=2
NF_QUEUE=3
NF_REPEAT=4
NF_STOP=5
