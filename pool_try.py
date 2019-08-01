import ssl
import time

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter

import dns.resolver
import requests
import urllib3
import multiprocessing.pool
import collections
import itertools
import shlex
from subprocess import Popen, PIPE, STDOUT


def get_simple_cmd_output(cmd, stderr=STDOUT):
    """
    Execute a simple external command and get its output.
    """
    args = shlex.split(cmd)
    return str(Popen(args, stdout=PIPE, stderr=stderr).communicate()[0])


def get_ping_time_winsows(host):
    cmd = "ping {host}".format(host=host)
    ping_res_str = get_simple_cmd_output(cmd)
    return int(ping_res_str.split()[-1].replace("ms\\r\\n'", ""))


AMOUNT_OF_RESOLVERS = 50

TLS_SUPPORT_RESOLVERS_MAP = {
    'google_1': ('8.8.8.8', '2001:4860:4860::8888'),
    'google_2': ('8.8.4.4', '2001:4860:4860::8844'),
    # 'Fondation RESTENA': ('158.64.1.29', '2001:a18:1::29'),
    # 'Surfnet1': ('145.100.185.18', '2001:610:1:40ba:145:100:185:18'),
    # 'Surfnet2': ('145.100.185.17', '2001:610:1:40ba:145:100:185:17'),
    # 'dkg': ('199.58.81.218', '2001:470:1c:76d::53'),
    # 'dns.larsdebruin.net': ('51.15.70.167', None)
    'jolteon.boothlabs.me': ('198.100.148.224', None),
    'arthur.applied-wizardry.net': ('85.214.41.155', None),
    'orion.boothlabs.me': ('85.214.41.155', None),
    '.cust.bahnhof.se.': ('158.174.122.199', None),
    'pdns0.grnet.gr.': ('62.217.126.164', None),

}

SITES_LIST = [
    'Google.com',
    'Youtube.com',
    'Facebook.com',
    'Wikipedia.org',
    'Twitter.com',
    'Reddit.com',
    'Instagram.com',
    'Yahoo.com',
    'Amazon.com'
]


def get_ip_from_resolver_and_measure_the_time(url, resolver_ip):
    """
    The function takes a url and a IP of resolver and get the IP of the given domain from the resolver
    :param url: the url
    :param resolver_ip: the ip of the resolver
    :return: the ip of the domain behind the url
    """
    new_resolver = dns.resolver.Resolver(configure=False)
    new_resolver.nameservers = [resolver_ip]
    new_resolver.timeout = 1
    new_resolver.lifetime = 1
    response = new_resolver.query(url)
    ip = 'http://' + response.rrset.items[0].address
    time_it_took = response.response.time
    return ip, time_it_took


def get_ip_from_resolver(url, resolver_ip):
    """
    The function takes a url and a IP of resolver and get the IP of the given domain from the resolver
    :param url: the url
    :param resolver_ip: the ip of the resolver
    :return: the ip of the domain behind the url
    """
    new_resolver = dns.resolver.Resolver(configure=False)
    new_resolver.nameservers = [resolver_ip]
    new_resolver.timeout = 1
    new_resolver.lifetime = 1
    response = new_resolver.query(url)
    return response.rrset.items[0].address


"""
Measure the amount of time elapsed between sending the request and the arrival of the response (as a timedelta). 
This property specifically measures the time taken between sending the first byte of the request and finishing parsing the headers. 
It is therefore unaffected by consuming the response content or the value of the stream keyword argument.
"""


def get_response_from_ip_and_measure_time(ip_address):
    """
    send get HTTP request and return the time it took
    :param ip_address: the IP to send get request to
    :return: the time it took to get the response
    :raise:  requests.exceptions.ConnectionError - case the page did not respond with 200 status code
    """
    try:
        response = requests.get(ip_address, verify=False, timeout=3)
        if response.status_code == 200:
            time_it_took = response.elapsed.total_seconds()
            return time_it_took
        else:
            raise requests.RequestException
    except requests.RequestException as e:
        response = requests.get(ip_address.replace("http", "https"), verify=False, stream=False, timeout=3)
        if response.status_code == 200:
            time_it_took = response.elapsed.total_seconds()
            return time_it_took
        else:
            raise requests.RequestException


def get_resolver_map(filename, amount_to_sample=AMOUNT_OF_RESOLVERS, same_country=False, DNSSEC=False):
    """
    gets the ips of public resolvers that:
    their reliability parameter is higher the 0.6
    their country is the same as the resolver - depend on the flag same_country
    they support DNSSEC
    :param filename: the csv with the public DNS resolvers
    :param amount_to_sample: the amount of resolvers to sample
    :param same_country: false gets resolver from anywhere. otherwise, get resolver from the given country
    :return: numpy array with the ips of the chosen public resolvers
    """

    data = pd.read_csv(filename, index_col=None)
    data = data.drop(['created_at', 'checked_at', 'error', 'version', 'city'], axis=1)
    if DNSSEC:
        data = data[data.dnssec != False]
    if same_country:
        data = data[data.country_id == same_country]
    data = data[data.reliability > 0.9]
    data = data.drop(['dnssec', 'reliability'], axis=1)
    ASNS = data.ASN.drop_duplicates().sample(n=amount_to_sample)
    data = data.groupby(by=ASNS).apply(lambda grp: grp.sample(n=1))
    return np.array(data.ip)


def print_resolvers_time_comparison_on_general(amount_of_resolvers):
    plt.bar(['{0} resolvers mean'.format(amount_of_resolvers)] + ["default resolver mean"],
            [np.mean(other_res_time)] + [np.mean(def_res_time)])
    plt.ylabel('seconds')
    plt.title('RTT comparison results {0} resolvers VS default resolver'.format(amount_of_resolvers))
    plt.show()

def print_amount_of_reslovers_time_comparison(resolvers_time, def_resolver_time):
    plt.plot(range(10, 101, 20), resolvers_time)
    plt.plot(range(10, 101, 20), def_resolver_time)
    plt.ylabel('seconds')
    plt.xlabel('amount of resolvers')
    plt.title('time comparison between the default resolver \n to X amount of public DNS\'s')
    plt.show()

def print_ping_comparison(def_ping_time, majority_ping_time):
    plt.bar(['majority ip'] + ["default resolver ip"],
            [np.mean(def_ping_time)] + [np.mean(majority_ping_time)])
    plt.ylabel('Ms')
    plt.title('latency of pings to ips from the majority \nof the DNS resolvers compare to default resolver')
    plt.show()


def print_resolvers_time_comparison_per_site(site, dns_rtt_list, def_resolver_time):
    plt.bar(['sum of all', 'other resolvers mean'] + ["default resolver"], [np.sum(dns_rtt_list)] +
            [np.mean(dns_rtt_list)] + [def_resolver_time])
    plt.ylabel('dns RTT (time units')
    plt.title('RTT comparison results for the site: {0}'.format(site))
    plt.show()


def print_ips_per_site_bar(ips_list, site):
    ips_plot = pd.Series(ips_list).value_counts().plot('bar', title='amount results per ip os site: {0}'.format(site))
    ips_plot.plot()
    plt.xlabel('ips')
    plt.ylabel('counter')
    plt.show()

def get_ping_time_linux(host):
    cmd = "ping {host} -c 3".format(host=host)
    result = str(get_simple_cmd_output(cmd))
    avg_time = result.split('/')[-3]
    if len(avg_time) > 0:
        return avg_time
    else:
        raise Exception('could not get ping time!')



def get_sites_ips(resolvers_ips):
    """
    The function get ips of resolvers and output a graph with RTT comparison between the resolvers to the default
    resolvers.
    :param resolvers_ips: the ips of the resolvers
    :return: The ip of the sires from the default resolver and the ip that the majority of the resolvers agreed on
    """

    def_resolver_ips_list = []
    most_common_ip_list = []
    def_resolver_time_list = []
    majority_ip_list = []
    time_for_all_resolvers = []
    for site in SITES_LIST:
        resolvers_problem_flag = True
        while resolvers_problem_flag:
            start_time = time.time()
            ips_list = resolve_dns_parallel(site, resolvers_ips)
            if ips_list:
                resolvers_problem_flag = False
                most_common = Counter(ips_list).most_common(1)[0]
                time_for_all_resolvers.append(time.time() - start_time)
                most_common_ip_list.append(Counter(ips_list).most_common(1)[0][0])
                majority_ip_list.append(most_common[1])
    start_time = time.time()
    try:
        for site in SITES_LIST:
            # get the ip of the site and the time it took from the default DNS resolver
            default_res = dns.resolver.query(site)
            def_resolver_ips_list.append(default_res.rrset.items[0].address)
            def_resolver_time_list.append(default_res.response.time)
        time_for_default_resolvers = time.time() - start_time
    except dns.exception.Timeout or dns.resolver.NoNameservers:
        time_for_default_resolvers = 1
        pass

    print("the mean majority of the most common ip is: {0}".format(np.mean(majority_ip_list)))
    def_res_time.append(time_for_default_resolvers)
    other_res_time.append(np.mean(time_for_all_resolvers))
    print("default resolver time: {0}, other resolver time: {1}".format(def_res_time[-1],
                                                                        other_res_time[-1]))
    # print_resolvers_time_comparison_on_general(time_for_all_resolvers, time_for_default_resolvers)
    return most_common_ip_list, def_resolver_ips_list


def worker(args):
    """query dns for (hostname, qname) and return (qname, [rdata,...])"""
    try:
        site, resolver_ip = args[0], args[1]
        new_resolver = dns.resolver.Resolver(configure=False)
        new_resolver.nameservers = [resolver_ip]
        new_resolver.timeout = 1
        new_resolver.lifetime = 1
        response = new_resolver.query(site)
        return [response.rrset.items[0].address]
    except dns.exception.Timeout or dns.resolver.NoNameservers:
        return []
    except:
        return []


def resolve_dns_parallel(site, resolver_ips):
    """Given a list of hosts, return dict that maps qname to
    returned rdata records.
    """
    ip_list = []
    pool = multiprocessing.pool.ThreadPool(processes=AMOUNT_OF_RESOLVERS)
    args_for_worker = [(site, resolver_ip) for resolver_ip in resolver_ips]
    # args_for_worker = np.array(([site]*len(resolver_ips), resolver_ips)).T
    try:
        for ip in pool.imap(
                worker,
                args_for_worker):
            ip_list.extend(ip)
        pool.close()
        return ip_list
    except Exception:
        print("pool exception")


def main():
    global def_res_time
    global other_res_time
    def_res_time = []
    other_res_time = []
    def_ping_latency = []
    majority_ping_latency = []
    time_per_amount_of_resolvers = []
    def_resolver_time_vs_each_amount_of_resolvers = []
    for amount_of_resolvers in range(10, 101,  20):
        print("check comparison with {0} DNS servers".format(amount_of_resolvers))
        for i in range(4):
            resolver_ips = get_resolver_map(r"C:\Users\1212\Desktop\studies\third year\semester b\lab\dns_scrypts\try.csv",
                                            amount_of_resolvers)
            most_common_ip_list, def_resolver_ips_list = get_sites_ips(resolver_ips)
        print_resolvers_time_comparison_on_general(amount_of_resolvers)
        time_per_amount_of_resolvers.append(np.mean(other_res_time))
        def_resolver_time_vs_each_amount_of_resolvers.append(np.mean(def_res_time))
        other_res_time = []
        def_res_time = []
    print_amount_of_reslovers_time_comparison(def_resolver_time_vs_each_amount_of_resolvers, time_per_amount_of_resolvers)
    for i in range(len(most_common_ip_list)):
        majority_ping_latency.append(get_ping_time_linux(most_common_ip_list[i]))
        def_ping_latency.append(get_ping_time_linux(def_resolver_ips_list[i]))
    print_ping_comparison(majority_ping_latency, def_ping_latency)


if __name__ == '__main__':
    main()
