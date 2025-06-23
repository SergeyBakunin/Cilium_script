#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, re
import pandas as pd
import yaml

# ---- config ----
BASE_SRCKEYWORD = 'все поды в namespace'
DEFAULT_RULES = {
    'd8-monitoring/app:prometheus': {
        'direction': 'ingress',
        'port': '15020',
        'protocol': 'TCP',
        'labels': {
            'io.kubernetes.pod.namespace': 'd8-monitoring',
            'app.kubernetes.io/name': 'prometheus'
        }
    },
    'kube-system/node-local-dns': {
        'direction': 'egress',
        'port': '53',
        'protocol': 'UDP',
        'labels': {
            'io.kubernetes.pod.namespace': 'kube-system',
            'k8s-app': 'node-local-dns'
        },
        'rules': {
            'dns': [{'matchPattern': '*'}]
        }
    },
    'd8-istio/istiod': {
        'direction': 'egress',
        'port': '15012',
        'protocol': 'TCP',
        'labels': {
            'io.kubernetes.pod.namespace': 'd8-istio',
            'app': 'istiod'
        }
    }
}

# split 'k1:v1,k2:v2' or with newlines into dict

def split_labels(s):
    parts = re.split(r'[,\n]+', s)
    labels = {}
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if ':' in p:
            k, v = p.split(':', 1)
            labels[k.strip()] = v.strip()
    return labels

# detect if dest is fqdn, cidr or label

def detect_type(dest):
    dest = dest.strip()
    if re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', dest):
        return 'cidr', dest
    if '.' in dest and ':' not in dest:
        return 'fqdn', dest.lower()
    return 'label', dest

# build ingress rule, supports custom labels and additional rules

def make_ingress_rule(r):
    rule = {}
    if 'labels' in r:
        rule['fromEndpoints'] = [{'matchLabels': r['labels']}]
    else:
        dtype, val = detect_type(r['source'])
        if dtype == 'label':
            rule['fromEndpoints'] = [{'matchLabels': split_labels(val)}]
        elif dtype == 'fqdn':
            rule['fromFQDNs'] = [{'matchName': val}]
        else:
            rule['fromCIDRSet'] = [{'cidr': val}]
    port_block = {'port': str(r['port'])}
    if r['protocol'].upper() != 'ANY':
        port_block['protocol'] = r['protocol'].upper()
    rule['toPorts'] = [{'ports': [port_block]}]
    if 'rules' in r:
        rule['rules'] = r['rules']
    return rule

# build egress rule, supports custom labels and additional rules

def make_egress_rule(r):
    rule = {}
    if 'labels' in r:
        rule['toEndpoints'] = [{'matchLabels': r['labels']}]
    else:
        dtype, val = detect_type(r['destination'])
        if dtype == 'label':
            rule['toEndpoints'] = [{'matchLabels': split_labels(val)}]
        elif dtype == 'fqdn':
            rule['toFQDNs'] = [{'matchName': val}]
        else:
            rule['toCIDRSet'] = [{'cidr': val}]
    port_block = {'port': str(r['port'])}
    if r['protocol'].upper() != 'ANY':
        port_block['protocol'] = r['protocol'].upper()
    rule['toPorts'] = [{'ports': [port_block]}]
    if 'rules' in r:
        rule['rules'] = r['rules']
    return rule

# parse excel into namespace and groups by column C (label key)

def parse_excel(path):
    df = pd.read_excel(path, header=None, dtype=str).fillna('')
    ns_cell = df.iat[1, 0].strip()
    if ':' not in ns_cell:
        sys.exit("Ошибка: не найден 'namespace:' во второй строке")
    namespace = ns_cell.split(':', 1)[1].strip()
    groups = {}
    for i in range(2, len(df)):
        row = df.iloc[i]
        if not str(row[0]).strip():
            continue
        entry = {
            'protocol': row[1].strip(),
            'source': row[2].strip(),
            'direction': row[3].strip().lower(),
            'destination': row[4].strip(),
            'port': row[5].strip()
        }
        key = row[2].strip() or BASE_SRCKEYWORD
        groups.setdefault(key, []).append(entry)
    return namespace, groups

# build a single CiliumNetworkPolicy dict

def build_policy(namespace, label_k, rules):
    labels = split_labels(label_k) if label_k != BASE_SRCKEYWORD else {}
    suffix = next(iter(labels.values())) if labels else 'default'
    policy = {
        'apiVersion': 'cilium.io/v2',
        'kind': 'CiliumNetworkPolicy',
        'metadata': {'name': f"{namespace}-{suffix}", 'namespace': namespace},
        'spec': {'endpointSelector': labels and {'matchLabels': labels} or {}}
    }
    ingress, egress = [], []
    for r in rules:
        if r['direction'] == 'ingress':
            ingress.append(make_ingress_rule(r))
        else:
            egress.append(make_egress_rule(r))
    if ingress:
        policy['spec']['ingress'] = ingress
    if egress:
        policy['spec']['egress'] = egress
    return policy

# main execution

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input.xlsx>")
        sys.exit(1)

    namespace, groups = parse_excel(sys.argv[1])

    # log creation and base check
    out_file = f"{namespace}.yaml"
    print(f"Файл создан: {out_file}")
    found = [d for d, cfg in DEFAULT_RULES.items()
             if any(r['destination'] == d and r['direction'] == cfg['direction']
                    for grp in groups.values() for r in grp)]
    if len(found) == len(DEFAULT_RULES):
        print("Базовые правила обнаружены и добавлены в конфигурацию.")
    else:
        print("Не обнаружены базовые правила, добавлены в конфигурацию.")

    # override default group with only DEFAULT_RULES entries
    default_entries = []
    for dest, cfg in DEFAULT_RULES.items():
        entry = {
            'protocol': cfg['protocol'],
            'source': BASE_SRCKEYWORD,
            'direction': cfg['direction'],
            'destination': dest,
            'port': cfg['port'],
            'labels': cfg['labels']
        }
        if 'rules' in cfg:
            entry['rules'] = cfg['rules']
        default_entries.append(entry)
    groups[BASE_SRCKEYWORD] = default_entries

    # generate policies: default first
    order = [BASE_SRCKEYWORD] + [k for k in groups if k != BASE_SRCKEYWORD]
    policies = [build_policy(namespace, k, groups[k]) for k in order]

    # write all
    with open(out_file, 'w', encoding='utf-8') as f:
        yaml.dump_all(policies, f, sort_keys=False, allow_unicode=True)

if __name__ == '__main__':
    main()
