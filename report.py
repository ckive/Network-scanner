import texttable, json, sys, os
from pathlib import Path
import pandas as pd

def usage():
    print("python report.py [input_file.json] [output_file.txt]")
    return

#validates extension and existence of paths, if outpath not exist, create it. if exists, overwrite it.
def validate(inpath, outpath) -> bool:
    if not inpath.endswith('.json') or not outpath.endswith('.txt'):
        print("wrong path extensions")
        return False
    if os.path.exists(inpath):
        if not os.path.exists(outpath):
            #outpath DNE, create it, if exists, write over it
            Path(outpath).touch()
        return True
    else:
        #inpath DNE, error
        print("input_file does not exist. Please check again.")
        return False



def main():
    if len(sys.argv) != 3:
        usage()
        sys.exit(1)
    infile = sys.argv[1]
    outfile = sys.argv[2]
    if not validate(infile, outfile):
        sys.exit(1)

    with open(infile, "r") as f:
        #df is already what we want for 1. Just use texttable to transform it
        df = pd.read_json(infile).transpose()


    #Table 1
    table = texttable.Texttable()
    table.set_max_width(150)
    headers = df.columns.tolist()
    headers.insert(0, "domain")
    table.header(headers)
    try:
        for i in range(0, df.shape[0]):
            rowSeries = df.iloc[i]
            cur_row = rowSeries.values.tolist()
            cur_domain = df.index.values[i]
            cur_row.insert(0, cur_domain)
            table.add_row(cur_row) 
    except Exception as e:
        print("Error: Check if json file is corrupted")
        print(e)
    finally:
        print(table.draw() + "\n")
        f = open(outfile, "w")
        f.write(table.draw() + "\n")
        f.close()

    #Table 2
    table = texttable.Texttable()
    table.set_max_width(150)
    table.header(['domain', 'rtt_min', 'rtt_max'])
    
    #filter out any empty rtt_range
    df_n = df[~df['rtt_range'].isnull()]

    try:
        #https://stackoverflow.com/questions/35491274/pandas-split-column-of-lists-into-multiple-columns/35491399
        df_n[['rtt_min', 'rtt_max']] = pd.DataFrame(df_n.rtt_range.tolist(), index=df_n.index)
        df_t2 = pd.DataFrame(df_n['rtt_range'].to_list(), columns=['rtt_min','rtt_max'], index=df_n.index)
        ### rtt_min     rtt_max
        #0     2            20
        #1     2            20

        #sort INPLACE by ascending
        df_t2.sort_values(by=['rtt_min'], inplace=True)
        
        for i in range(0, df_t2.shape[0]):
            rtt_min = df_t2.iloc[i][0]
            rtt_max = df_t2.iloc[i][1]
            cur_domain = df_t2.index.values[i]
            # domain, rtt_min, rtt_max
            cur_row = [cur_domain, rtt_min, rtt_max]
            table.add_row(cur_row) 
    except Exception as e:
        print("Error: Check if there are any rtt_range data available")
    finally:
        print(table.draw() + "\n")
        f = open(outfile, "a")
        f.write(table.draw() + "\n")
        f.close()

    #Table 3
    table = texttable.Texttable()
    table.set_max_width(150)
    table.header(['Root CAs', 'Occurances'])
    df_t3 = df['root_ca'].value_counts(ascending=False)

    try:
        for i in range(0, df_t3.shape[0]):
            root_ca = df_t3.index.values[i]
            occurance = df_t3.iloc[i]
            cur_row = [root_ca, occurance]
            table.add_row(cur_row)
    except Exception as e:
        print("Error: Check if there are any root_cas scanned")
    finally:
        print(table.draw() + "\n")
        f = open(outfile, "a")
        f.write(table.draw() + "\n")
        f.close()

    #Table 4
    table = texttable.Texttable()
    table.set_max_width(150)
    table.header(['Server Types', 'Occurances'])
    df_t4 = df['http_server'].value_counts(ascending=False)

    try:
        for i in range(0, df_t4.shape[0]):
            server = df_t4.index.values[i]
            occurance = df_t4.iloc[i]
            cur_row = [server, occurance]
            table.add_row(cur_row)
    except Exception as e:
        print("Error: Check if there are any http_server type scanned")
    finally:
        print(table.draw() + "\n")
        f = open(outfile, "a")
        f.write(table.draw() + "\n")
        f.close()
        
    table = texttable.Texttable()
    table.set_max_width(150)
    table.header(['Feature', 'Percent of websites supporting'])
    denominator = df.shape[0]
    try:
        only_tls = df['tls_versions']
        tls_dict = dict()
        for i in range(only_tls.shape[0]):
            for version in only_tls[i]:
                if version in tls_dict:
                    tls_dict[version] += 1
                else:
                    tls_dict[version] = 1
        all_tls = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3', 'SSLv2', 'SSLv3']
        for tls in all_tls:
            if tls in tls_dict:
                table.add_row([tls, (tls_dict[tls] / denominator) * 100])
            else:
                table.add_row([tls, 0])
    except Exception as e:
        print('tls is wrong')
        f = open(outfile, "a")
        f.write(table.draw() + "\n")
        f.close()

    df_plain = df['insecure_http'].value_counts(ascending=False)
    num_plain = df_plain[True]
    table.add_row(['Plain HTTP', (num_plain / denominator) * 100])

    df_redirect = df['redirect_to_https'].value_counts(ascending=False)
    num_redirect = df_redirect[True]
    table.add_row(['Redirect to HTTPS', (num_redirect / denominator) * 100])

    df_hsts = df['hsts'].value_counts(ascending=False)
    num_hsts = df_hsts[True]
    table.add_row(['HSTS', (num_hsts / denominator) * 100])

    df_ipv6 = df[df['ipv6_addresses'].map(lambda d: len(d)) > 0]
    num_ipv6 = df_ipv6.shape[0]
    table.add_row(['IPv6', (num_ipv6 / denominator) * 100])

    print(table.draw() + "\n")
    f = open(outfile, "a")
    f.write(table.draw() + "\n")
    f.close()




if __name__ == '__main__':
    main()