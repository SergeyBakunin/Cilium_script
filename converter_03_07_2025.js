#!/usr/bin/env node

/**
 * Скрипт конвертации Excel → CiliumNetworkPolicy YAML
 * Использует:
 *   npm install xlsx js-yaml
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const XLSX = require('xlsx');
const yaml = require('js-yaml');

// ---- Загрузка default.yaml ----
const defaultYamlPath = path.join(__dirname, 'default.yaml');
if (!fs.existsSync(defaultYamlPath)) throw new Error('❌ Не найден default.yaml');
const defaultDocs = yaml.loadAll(fs.readFileSync(defaultYamlPath, 'utf8'));

// ---- Утилиты ----
const splitLabels = raw => raw
  .split(/[\n,]+/)
  .map(s => s.trim())
  .filter(s => s.includes(':'))
  .reduce((o, p) => {
    const [k, ...v] = p.split(':');
    o[k.trim()] = v.join(':').trim();
    return o;
  }, {});

// Новая функция определения типа содержимого ячейки
const detectType = v0 => {
  const v = (v0||'').trim();
  if (!v) return ['empty', null];

  // разбиваем по запятым или переводам строки
  const items = v.split(/[\r\n,]+/).map(s => s.trim()).filter(Boolean);

  // если всё — валидные IP или CIDR, возвращаем список
  const allIPs = items.every(it => /^\d+\.\d+\.\d+\.\d+(?:\/\d+)?$/.test(it));
  if (allIPs && items.length > 1) {
    return ['cidrList', items.map(it => it.includes('/') ? it : `${it}/32`)];
  }
  // одиночный CIDR
  if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(v))      return ['cidr', v];
  // одиночный IP
  if (/^\d+\.\d+\.\d+\.\d+$/.test(v))          return ['cidr', v + '/32'];
  // FQDN — строка с точкой и хотя бы одной буквой
  if (/[a-zA-Z]/.test(v) && v.includes('.'))   return ['fqdn', v.toLowerCase()];

  // всё остальное — метки
  return ['label', v];
};

/** Формирует правило ingress/egress */
const makeRule = e => {
  const { direction, sourceLabel, destLabel, port, protocol } = e;
  const prefix = direction === 'ingress' ? 'from' : 'to';
  const cell = direction === 'ingress' ? sourceLabel : destLabel;
  const r = {};
  let labels = {};

  if (cell) {
    const [detType, detValue] = detectType(cell);

    switch (detType) {
      case 'fqdn':
        r[`${prefix}FQDNs`] = [{ matchName: detValue }];
        break;
      case 'cidrList':
        r[`${prefix}CIDR`] = detValue;
        break;
      case 'cidr':
        r[`${prefix}CIDR`] = [detValue];
        break;
      default:
        // метки: возможно namespace/label
        if (cell.includes('/') && !cell.startsWith('app.kubernetes.io/')) {
          const [nsPart, labPart] = cell.split('/');
          labels = {
            'io.kubernetes.pod.namespace': nsPart.trim(),
            ...splitLabels(labPart)
          };
        } else {
          labels = splitLabels(cell);
        }
    }
  }

  if (Object.keys(labels).length) {
    r[`${prefix}Endpoints`] = [{ matchLabels: labels }];
  }

  // Порты (всегда добавляем вместе с любым из above)
  const portList = String(port).split(/[\r\n,]+/).map(s=>s.trim()).filter(Boolean);
  const portsArray = portList.map(pv => {
    const po = { port: pv };
    if (protocol && protocol.toUpperCase() !== 'ANY') po.protocol = protocol.toUpperCase();
    return po;
  });
  r.toPorts = [{ ports: portsArray }];

  return r;
};

// ---- Парсинг Excel ----
function parseExcel(file) {
  const wb = XLSX.readFile(file);
  const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header:1, blankrows:false });
  const nsRaw = String(rows[1]?.[0]||'').trim();
  if (!nsRaw.includes(':')) throw new Error('❌ Неверный формат namespace в строке 2');
  const namespace = nsRaw.split(':').slice(1).join(':').trim();

  const groups = {}, entries = [], missingNums = [];
  for (let i = 2; i < rows.length; i++) {
    const row = rows[i] || [];
    const hasData = row.slice(1,6).some(c => c && String(c).trim());
    if (hasData && !row[0]) missingNums.push(i+1);
    if (!hasData) continue;

    const [ , proto, groupKey, dirRaw, other, port ] = row.map(c=>String(c||'').trim());
    const direction = dirRaw.toLowerCase();
    let sourceLabel='', destLabel='';
    if (direction === 'ingress') { sourceLabel=other; destLabel=groupKey; }
    else                         { sourceLabel=groupKey; destLabel=other; }

    const e = { protocol: proto, sourceLabel, destLabel, direction, port, rowNum:i+1 };
    entries.push(e);
    (groups[groupKey] ||= []).push(e);
  }
  return { namespace, groups, entries, missingNums };
}

// ---- Валидация ----
function validate(entries) {
  const bad = entries.filter(e => /[А-Яа-яЁё]/.test(
    e.sourceLabel + e.destLabel + e.protocol + e.direction + e.port));
  if (bad.length) {
    console.error('❌ Кириллица на строках: ' + bad.map(e=>e.rowNum).join(', '));
    process.exit(1);
  }
  const seen = {}, dups = [];
  entries.forEach(e => {
    const key = [e.direction, e.sourceLabel, e.destLabel, e.port,
      (e.protocol||'ANY').toUpperCase()].join('|');
    if (seen[key]) dups.push(`${seen[key]} & ${e.rowNum}`); else seen[key]=e.rowNum;
  });
  if (dups.length) {
    console.warn('⚠️ Дубликаты правил в строках: ' + dups.join(', '));
  }
}

// ---- Построение CiliumNetworkPolicy ----
const buildPolicy = (ns, groupKey, ents) => {
  const labels = splitLabels(groupKey);
  const suffix = Object.values(labels).length
    ? Object.values(labels).join('-')
    : 'default';
  const name = `${ns}-${suffix}`;
  const spec = { endpointSelector: Object.keys(labels).length
    ? { matchLabels: labels } : {} };

  const ingress = [], egress = [];
  ents.forEach(e => {
    const rule = makeRule(e);
    (e.direction === 'ingress' ? ingress : egress).push(rule);
  });
  if (ingress.length) spec.ingress = ingress;
  if (egress.length)  spec.egress  = egress;

  return { apiVersion:'cilium.io/v2', kind:'CiliumNetworkPolicy',
    metadata:{ name, namespace:ns }, spec };
};

// ---- Основная логика ----
function main() {
  const file = process.argv[2];
  if (!file || !/\.xlsx$/i.test(file)) {
    console.error('❌ Укажите путь к .xlsx'); process.exit(1);
  }
  if (!fs.existsSync(file)) {
    console.error(`❌ Файл ${file} не найден`); process.exit(1);
  }

  const { namespace, groups, entries, missingNums } = parseExcel(file);
  if (missingNums.length) {
    console.error('❌ Номера правил отсутствуют в строках: ' + missingNums.join(', '));
    process.exit(1);
  }

  validate(entries);

  // Добавление default-политик
  const defaultPolicies = defaultDocs.map(doc => ({
    ...doc,
    metadata:{ name:`${namespace}-default`, namespace }
  }));

  const excelPolicies = Object.entries(groups)
    .map(([k, ents]) => buildPolicy(namespace, k, ents));

  // Сборка YAML
  const allDocs = [...defaultPolicies, ...excelPolicies]
    .map(doc => yaml.dump(doc, { sortKeys:false, noRefs:true, indent:2, lineWidth:-1 }));

  const out = `${namespace}.yaml`;
  const writeOut = () => {
    fs.writeFileSync(out, allDocs.join('---\n'), 'utf8');
    console.log(`✅ ${out} создан`);
  };

  if (fs.existsSync(out)) {
    readline.createInterface({ input:process.stdin, output:process.stdout })
      .question(`⚠️ ${out} уже существует. Перезаписать? (y/n): `, ans => {
        if (ans.toLowerCase().startsWith('y')) writeOut();
        else console.log('❌ Отменено.');
        process.exit(0);
      });
  } else writeOut();
}

if (require.main === module) main();
