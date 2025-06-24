#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
import pandas as pd
import yaml

# ---- Конфигурация базовых правил ----
# Здесь задаются политики, которые должны присутствовать всегда.
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
        'rules': {  # Дополнительные правила DNS должны идти внутри блока toPorts
            'dns': [
                {'matchPattern': '*'}
            ]
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

# ---- Утилиты для разбора и сборки правил ----

def split_labels(raw: str) -> dict:
    """
    Преобразует строку меток вида 'k1:v1,k2:v2' или с переносами строк
    в словарь {k1: v1, k2: v2}.
    """
    parts = re.split(r'[,\n]+', raw)
    labels = {}
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if ':' in part:
            key, val = part.split(':', 1)
            labels[key.strip()] = val.strip()
    return labels


def detect_type(value: str) -> (str, str):
    """
    Определяет тип строки: CIDR, FQDN или label.
    Возвращает кортеж (тип, значение).
    """
    v = value.strip()
    if re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', v):
        return 'cidr', v
    if '.' in v and ':' not in v:
        return 'fqdn', v.lower()
    return 'label', v


def make_ingress_rule(entry: dict) -> dict:
    """
    Формирует один ingress блок для CiliumNetworkPolicy.
    Вложение 'rules' происходит внутри объекта toPorts.
    """
    rule = {}

    # FROM
    if 'labels' in entry:
        rule['fromEndpoints'] = [{'matchLabels': entry['labels']}]
    else:
        dtype, val = detect_type(entry['source'])
        if dtype == 'label':
            rule['fromEndpoints'] = [{'matchLabels': split_labels(val)}]
        elif dtype == 'fqdn':
            rule['fromFQDNs'] = [{'matchName': val}]
        else:
            rule['fromCIDRSet'] = [{'cidr': val}]

    # TO PORTS + вложенные правила (если есть)
    port_block = {
        'ports': [
            {
                'port': str(entry['port']),
                **({'protocol': entry['protocol'].upper()} if entry['protocol'].upper() != 'ANY' else {})
            }
        ]
    }
    if 'rules' in entry:
        # Вложение блока rules внутри toPorts
        port_block['rules'] = entry['rules']
    rule['toPorts'] = [port_block]

    return rule


def make_egress_rule(entry: dict) -> dict:
    """
    Формирует один egress блок для CiliumNetworkPolicy.
    Аналогично ingress.
    """
    rule = {}

    # TO
    if 'labels' in entry:
        rule['toEndpoints'] = [{'matchLabels': entry['labels']}]
    else:
        dtype, val = detect_type(entry['destination'])
        if dtype == 'label':
            rule['toEndpoints'] = [{'matchLabels': split_labels(val)}]
        elif dtype == 'fqdn':
            rule['toFQDNs'] = [{'matchName': val}]
        else:
            rule['toCIDRSet'] = [{'cidr': val}]

    # TO PORTS + вложенные правила
    port_block = {
        'ports': [
            {
                'port': str(entry['port']),
                **({'protocol': entry['protocol'].upper()} if entry['protocol'].upper() != 'ANY' else {})
            }
        ]
    }
    if 'rules' in entry:
        port_block['rules'] = entry['rules']
    rule['toPorts'] = [port_block]

    return rule


def parse_excel(path: str) -> (str, dict):
    """
    Читает Excel-файл без заголовков.
    Namespace во второй строке (колонка А).
    Группирует правила по ключу из колонки C.
    """
    df = pd.read_excel(path, header=None, dtype=str).fillna('')
    raw_ns = df.iat[1, 0].strip()
    if ':' not in raw_ns:
        sys.exit("Ошибка: не найден 'namespace:' во второй строке")
    namespace = raw_ns.split(':', 1)[1].strip()

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


def build_policy(namespace: str, key: str, rules: list) -> dict:
    """
    Собирает CiliumNetworkPolicy dict для одной группы.
    """
    labels = split_labels(key) if key != BASE_SRCKEYWORD else {}
    suffix = next(iter(labels.values())) if labels else 'default'
    policy = {
        'apiVersion': 'cilium.io/v2',
        'kind': 'CiliumNetworkPolicy',
        'metadata': {'name': f"{namespace}-{suffix}", 'namespace': namespace},
        'spec': {'endpointSelector': labels and {'matchLabels': labels} or {}}
    }

    ingress_list, egress_list = [], []
    for entry in rules:
        if entry['direction'] == 'ingress':
            ingress_list.append(make_ingress_rule(entry))
        else:
            egress_list.append(make_egress_rule(entry))

    if ingress_list:
        policy['spec']['ingress'] = ingress_list
    if egress_list:
        policy['spec']['egress'] = egress_list

    return policy


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input.xlsx>")
        sys.exit(1)

    # Парсим Excel
    namespace, groups = parse_excel(sys.argv[1])

    # Лог создания файла
    output = f"{namespace}.yaml"
    print(f"Файл создан: {output}")

    # Проверка базовых правил в Excel
    found = [name for name, cfg in DEFAULT_RULES.items()
             if any(r['destination'] == name and r['direction'] == cfg['direction']
                    for grp in groups.values() for r in grp)]
    if len(found) == len(DEFAULT_RULES):
        print("Базовые правила обнаружены и добавлены в конфигурацию.")
    else:
        print("Не обнаружены базовые правила, добавлены в конфигурацию.")
        # Заменяем группу default только на базовые правила
        groups[BASE_SRCKEYWORD] = []
        for name, cfg in DEFAULT_RULES.items():
            entry = {
                'protocol': cfg['protocol'],
                'source': BASE_SRCKEYWORD,
                'direction': cfg['direction'],
                'destination': name,
                'port': cfg['port'],
                'labels': cfg['labels']
            }
            if 'rules' in cfg:
                entry['rules'] = cfg['rules']
            groups[BASE_SRCKEYWORD].append(entry)

    # Генерируем политики: default сначала
    order = [BASE_SRCKEYWORD] + [k for k in groups if k != BASE_SRCKEYWORD]
    policies = [build_policy(namespace, k, groups[k]) for k in order]

    # Сохраняем в YAML с явными отступами
    with open(output, 'w', encoding='utf-8') as f:
        yaml.dump_all(
            policies, f,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,  # блочный стиль
            indent=2  # два пробела для вложенности
        )

if __name__ == '__main__':
    main()
