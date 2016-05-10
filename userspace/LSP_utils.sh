#! /bin/sh

lsp_parse_argment()
{
cmd=`echo  $1 | awk '{split($0,a,"="); print "LSP_cmd="a[1] "; LSP_val="a[2]}'`
eval ${cmd}
}

lsp_ip2int() {
    echo $1 | sed 's/\./ /g' | while read x1 x2 x3 x4
    do
        echo $((($x1<<24) + ($x2<<16) + ($x3<<8) + $x4))
    done
}

lsp_int2ip()
{
    x1=$(($1 >> 24))
    x2=$((($1 >> 16) & 0xFF))
    x3=$((($1 >> 8) & 0xFF))
    x4=$(($1 & 0xFF))
    [ $x1 -lt 0 ] && x1=$(($x1 + 256))
    [ $x2 -lt 0 ] && x2=$(($x2 + 256))
    [ $x3 -lt 0 ] && x3=$(($x3 + 256))
    [ $x4 -lt 0 ] && x4=$(($x4 + 256))
    echo $x1.$x2.$x3.$x4
}

lsp_parse_dash()
{
    local _index
    _index=`expr index "$1" -`
    _index=$((_index-1))
    lsp_start=`echo $1 |cut -c1-$_index`
    _index=$((_index+2))
    lsp_end=`echo $1 |cut -c$_index-`
}
    

lsp_parse_ip()
{
    local _i
    local _isRange
    local _start
    local _end
    local _startIp
    local _endIp

    for _i in $1; do
        _isRange=`expr index "$_i" -`
        if [ $_isRange -eq 0 ]; then
            echo $_i
        else
            _start=`echo $_i | awk '{sub("-"," "); print $1}'`
            _end=`echo $_i | awk '{sub("-"," "); print $2}'`
            _startIp=`apx_ip2int $_start`
            _endIp=`apx_ip2int $_end`
            apx_int2ip _startIp
            while [ $_startIp -ne $_endIp ]; do
                _startIp=$(($_startIp + 1))
                apx_int2ip $_startIp
            done
        fi
    done
}


