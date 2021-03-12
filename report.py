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

    #Table 2
    table = texttable.Texttable()
    table.set_max_width(150)
    table.header(['domain', 'rtt_min', 'rtt_max'])
    
    #filter out any empty rtt_range
    df_n = pd.DataFrame(df[df['rtt_range'].map(len) > 0])
    
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
        


if __name__ == '__main__':
    main()