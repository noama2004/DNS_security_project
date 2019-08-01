import ipwhois
import pandas as pd
import numpy as np
# obj = IPWhois("8.8.8.8")
# q = obj.lookup_rdap(depth=1)
# q.get('asn')
# '15169'




def main():
    file_name = r"C:\Users\1212\Desktop\studies\third year\semester b\lab\nameservers.csv"
    public_dns_data = pd.read_csv(file_name, index_col=None)
    ips = np.array(public_dns_data.ip)
    asns = []
    for ip in ips:
        try:
            if ip.startswith("192.168."):
                raise Exception
            obj = ipwhois.IPWhois(ip)
            q = obj.lookup_rdap(depth=1)
            asns.append(q.get('asn'))
        except Exception as exc:
            public_dns_data = public_dns_data[public_dns_data.ip != ip]
    public_dns_data['ASN'] = asns
    public_dns_data.to_csv('try.csv')



if __name__ == '__main__':
    main()