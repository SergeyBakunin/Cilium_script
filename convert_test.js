#!/usr/bin/env node

/**
 * Скрипт конвертации Excel → CiliumNetworkPolicy YAML
 * Использует:
 *   npm install xlsx js-yaml
 *
 * Особенности:
 * - Чтение дефолтных политик из default.yaml
 * - Проверка расширения .xlsx и существования файла
 * - Валидация наличия номеров правил в колонке A
 * - Проверка отсутствия кириллицы, поиск дубликатов
 * - Поддержка namespace/label:val для селекторов
 * - Обработка множественных портов и IP/CIDR-списков
 * - Подтверждение перезаписи выходного YAML
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const XLSX = require('xlsx');
const yaml = require('js-yaml');

// ---- Загрузка default.yaml и сбор базовых правил ----
const defaultYamlPath = path.join(__dirname, 'default.yaml');
if (!fs.existsSync(defaultYamlPath)) throw new Error('❌ Не найден default.yaml');
const defaultDocs = yaml.loadAll(fs.readFileSync(defaultYamlPath, 'utf8'));
const DEFAULT_RULES = defaultDocs.flatMap(doc => {
  const regs = [];
  (doc.spec.ingress || []).forEach(rule => {
    const p = rule.toPorts[0].ports[0];
    regs.push({ direction: 'ingress', port: String(p.port), protocol: (p.protocol||'ANY').toUpperCase() });
  });
  (doc.spec.egress || []).forEach(rule => {
    const p = rule.toPorts[0].ports[0];
    regs.push({ direction: 'egress', port: String(p.port), protocol: (p.protocol||'ANY').toUpperCase() });
  });
  return regs;
});

// ---- Утилиты ----
const splitLabels = raw => raw
  .split(/[\n,]+/)             // по запятым или переносам строки
  .map(s => s.trim())
  .filter(s => s.includes(':'))
  .reduce((o, p) => {
    const [k, ...v] = p.split(':');
    o[k.trim()] = v.join(':').trim();
    return o;
  }, {});

const detectType = v0 => {
  const v = (v0||'').trim();
  if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(v)) return ['cidr', v];
  if (/^\d+\.\d+\.\d+\.\d+$/.test(v)) return ['cidr', v + '/32'];
  if (v.includes('.') && !v.includes(':')) return ['fqdn', v.toLowerCase()];
  return ['label', v];
};

/** Формирует правило ingress/egress */
const makeRule = e => {
  const { direction, sourceLabel, destLabel, port, protocol, rules } = e;
  const r = {};
  const prefix = direction === 'ingress' ? 'from' : 'to';

  // Спец-кейс namespace/label:val
  let labels;
  const slashField = direction === 'ingress' ? sourceLabel : destLabel;
  if (slashField && slashField.includes('/')) {
    const [nsPart, labPart] = slashField.split('/');
    labels = { 'io.kubernetes.pod.namespace': nsPart.trim(), ...splitLabels(labPart) };
  }

  // Селектор
  if (labels) {
    r[`${prefix}Endpoints`] = [{ matchLabels: labels }];
  } else {
    const keyField = direction === 'ingress' ? sourceLabel : destLabel;
    const keyList = String(keyField || '')
      .split(/[\n,]+/)    // разделяем по запятым и переносам строки
      .map(s => s.trim())
      .filter(Boolean);

    const [t0] = detectType(keyList[0] || '');
    if (t0 === 'label') {
      r[`${prefix}Endpoints`] = keyList.map(v => ({ matchLabels: splitLabels(v) }));
    } else if (t0 === 'fqdn') {
      r[`${prefix}FQDNs`] = keyList.map(v => ({ matchName: v }));
    } else {
      r[`${prefix}CIDRSet`] = keyList.map(v => ({ cidr: detectType(v)[1] }));
    }
  }

  // Порты → массив
  const portList = String(port)
    .split(/[\n,]+/)    // по запятым и переносам строки
    .map(s => s.trim())
    .filter(Boolean);
  const portsArray = portList.map(pv => {
    const po = { port: pv };
    if (protocol && protocol.toUpperCase() !== 'ANY') po.protocol = protocol.toUpperCase();
    return po;
  });
  const pb = { ports: portsArray };
  if (rules) pb.rules = rules;
  r.toPorts = [pb];

  return r;
};

// ---- Парсинг Excel и проверка номеров ----
function parseExcel(file) {
  const wb = XLSX.readFile(file);
  const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header:1, blankrows:false });
  if (!rows[1] || !rows[1][0]) throw new Error('❌ Не найден namespace в строке 2');
  const nsRaw = String(rows[1][0]).trim();
  if (!nsRaw.includes(':')) throw new Error('❌ Неверный формат namespace');
  const namespace = nsRaw.split(':').slice(1).join(':').trim();

  const groups = {};
  const entries = [];
  const missingNums = [];

  for (let i = 2; i < rows.length; i++) {
    const row = rows[i] || [];
    const hasData = row.slice(1,6).some(c=>c && String(c).trim());
    if (hasData && !row[0]) missingNums.push(i+1);
    if (!hasData) continue;

    const protocol = String(row[1]||'').trim();
    const groupKey = String(row[2]||'').trim();
    const direction = String(row[3]||'').toLowerCase().trim();
    const other = String(row[4]||'').trim();
    const port = String(row[5]||'').trim();

    let sourceLabel = '', destLabel = '';
    if (direction === 'ingress') {
      sourceLabel = other;
      destLabel = groupKey;
    } else {
      sourceLabel = groupKey;
      destLabel = other;
    }

    const entry = { protocol, sourceLabel, destLabel, direction, port, rowNum: i+1 };
    entries.push(entry);
    (groups[groupKey] ||= []).push(entry);
  }

  return { namespace, groups, entries, missingNums };
}

// ---- Валидация ----
function validate(entries) {
  const bad = entries.filter(e=>/[А-Яа-яЁё]/.test(e.sourceLabel+e.destLabel+e.protocol+e.direction+e.port));
  if (bad.length) { console.error('❌ Кириллица на строках: '+bad.map(e=>e.rowNum).join(', ')); process.exit(1); }
  const seen = {}, dups = [];
  entries.forEach(e=>{
    const key = [e.direction, e.sourceLabel, e.destLabel, e.port, (e.protocol||'ANY').toUpperCase()].join('|');
    if (seen[key]) dups.push({a:seen[key],b:e.rowNum}); else seen[key]=e.rowNum;
  });
  if (dups.length) { console.warn('⚠️ Дубликаты:'); dups.forEach(d=>console.warn(`  строки ${d.a} и ${d.b}`)); }
}

// ---- Генерация политик ----
const buildPolicy = (ns, groupKey, ents) => {
  const labels = splitLabels(groupKey);
  const suffix = Object.values(labels)[0] || 'default';
  const name = `${ns}-${suffix}`;
  const spec = { endpointSelector: Object.keys(labels).length ? { matchLabels: labels } : {} };
  const ingress = [], egress = [];
  ents.forEach(e=>{
    const rule = makeRule(e);
    e.direction === 'ingress' ? ingress.push(rule) : egress.push(rule);
  });
  if (ingress.length) spec.ingress = ingress;
  if (egress.length) spec.egress = egress;
  return { apiVersion:'cilium.io/v2', kind:'CiliumNetworkPolicy', metadata:{name,namespace:ns}, spec };
};

// ---- Main ----
function main() {
  const file = process.argv[2];
  if (!file || !/\.xlsx$/i.test(file)) { console.error('❌ Укажите .xlsx файл'); process.exit(1); }
  if (!fs.existsSync(file)) { console.error(`❌ ${file} не найден`); process.exit(1); }

  const { namespace, groups, entries, missingNums } = parseExcel(file);
  if (missingNums.length) { console.error('⚠️ Нет номеров правил в строках: '+missingNums.join(', ')); console.error('❌ Отменено.'); process.exit(1); }

  validate(entries);

  const hasAll = DEFAULT_RULES.every(cfg =>
    entries.some(e => e.direction === cfg.direction && e.port === cfg.port && (cfg.protocol==='ANY'|| e.protocol.toUpperCase()===cfg.protocol))
  );
  console.log(hasAll ? '⚠️ Базовые есть' : '⚠️ Базовых нет');

  const defaultPolicies = defaultDocs.map(doc => ({
    ...doc,
    metadata: { name:`${namespace}-default`, namespace }
  }));

  const excelPolicies = Object.entries(groups).map(([k,ents]) => buildPolicy(namespace, k, ents));

  const allDocs = [...defaultPolicies, ...excelPolicies]
    .map(p => yaml.dump(p, { sortKeys:false, noRefs:true, indent:2, lineWidth:-1 }));

  const out = `${namespace}.yaml`;
  const write = () => { fs.writeFileSync(out, allDocs.join('---\n'),'utf8'); console.log(`✅ ${out} создан`); };

  if (fs.existsSync(out)) readline.createInterface({input:process.stdin,output:process.stdout})
    .question(`⚠️ ${out} уже существует. Перезаписать? (y/n): `, a=>{ a.toLowerCase().startsWith('y')?write():console.log('❌ Отменено.'); process.exit(0); });
  else write();
}

if (require.main===module) main();
