import pandas as pd

def group_consecutive(seq_list):
    groups = []
    group = [seq_list[0]]
    for i in range(1, len(seq_list)):
        if seq_list[i] == seq_list[i-1] + 1:
            group.append(seq_list[i])
        else:
            groups.append(group)
            group = [seq_list[i]]
    groups.append(group)
    return groups

def get_consecutive_df(df):
    result = []
    for dst, group in df.groupby('dst'):
        seqs = sorted(group['seq'].tolist())
        grouped_seqs = group_consecutive(seqs)
        for g in grouped_seqs:
            result.append({
                'dst': dst,
                'seqs': g,
                'len': len(g)
            })

    return pd.DataFrame(result)
