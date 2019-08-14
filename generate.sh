#!/bin/sh

usage() {
        echo "Usage: $0 [-f > 0] [-p > 0] [-a <-syn_flood>]";
        echo "-f: number of flows to generate";
        echo "-p: lower bound of packets to generate";
        echo "-m: upper bound for heavy hitter size, lower bound is 1";
        echo "-g: the gap between different flow groups, small gap is more close to power law, vice versa";
        echo "-e: exponent of power law distribution";
        echo "-a: <optional> include attack in the generated trace:";
        echo "-s: <optional> determine if you want to show the plot of distribution, default is True, pass any string to block";
        echo "  syn_flood | slowloris | udp_traffic_assymetry | superspreader | dns_tunneling | malicious_domain"
        exit 1; }

while getopts "h:f:p:m:g:e:c:a:s:" opt; do
    case "$opt" in
        f)
            f=${OPTARG}
            ;;
        p)
            p=${OPTARG}
            ;;
        a)
            a=${OPTARG}
            ;;
        m)
            m=${OPTARG}
            ;;
        g)
            g=${OPTARG}
            ;;
        e)
            e=${OPTARG}
            ;;
        s)
            s=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z "${f}" ] || [ -z "${p}" ] || [ -z "${m}" ] || [ -z "${e}" ]; then
    echo "${f} ${p} ${m} ${e}"
    usage
fi

if [ -n "${a}" ]; then
    case $a in
        syn_flood)
            echo "attack: syn_flood"
            ;;
        slowloris)
            echo "attack: slowloris"
            ;;
        udp_traffic_assymetry)
            echo "attack: udp_traffic_assymetry"
            ;;
        superspreader)
            echo "attack: superspreader"
            ;;
        dns_tunneling)
            echo "attack: dns_tunneling"
            ;;
        malicious_domain)
            echo "attack: malicious_domain"
            ;;
        *)
            usage
            ;;
    esac
fi
echo ""
echo "***********************************"
if [ -z "${a}" ];then
    a="None"
    echo "generating trace with no attack"
else
    echo "generating trace with attack of $a"
fi
if [ -z "${s}" ];then
    s="True"
else
    s="False"
fi
echo "***********************************"
echo ""
./generate.py $f $p $a $m $g $e $s




