#!/usr/bin/env node

/**
 * Конвертация Excel → CiliumNetworkPolicy YAML с:
 * - чтением базовых правил из default.yaml
 * - переименованием и переназначением namespace для дефолтных политик
 * - валидацией (без кириллицы, поиск дубликатов)
 * - подтверждением перезаписи выходного файла
 * Использует: npm install xlsx js-yaml
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const XLSX = require('xlsx');
const yaml = require('js-yaml');

// ---- Загрузка базовых политик из default.yaml ----
const defaultYamlPath = path.join(__dirname, 'default.yaml');
if (!fs.existsSync(defaultYamlPath)) throw new Error('❌ Не найден default.yaml в директории скрипта');
const defaultDocs = yaml.loadAll(fs.readFileSync(defaultYamlPath, 'utf8'));
// Упрощённая конфигурация для проверки наличия базовых
const DEFAULT_RULES = defaultDocs.flatMap(doc => {
  const list = [];
  if (doc.spec.ingress) doc.spec.ingress.forEach(rule => {
    const p = rule.toPorts[0].ports[0];
    list.push({ direction: 'ingress', port: String(p.port), protocol: (p.protocol||'ANY').toUpperCase() });
  });
  if (doc.spec.egress) doc.spec.egress.forEach(rule => {
    const p = rule.toPorts[0].ports[0];
    list.push({ direction: 'egress', port: String(p.port), protocol: (p.protocol||'ANY').toUpperCase() });
  });
  return list;
});

// ---- Утилиты ----
const splitLabels = raw => raw.split(/[\n,]+/).map(s=>s.trim()).filter(s=>s.includes(':')).reduce((o,p)=>{ const [k,...v]=p.split(':'); o[k.trim()]=v.join(':').trim(); return o; }, {});
const detectType = v0 => { const v=(v0||'').trim(); if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(v)) return ['cidr',v]; if (v.includes('.')&&!v.includes(':')) return ['fqdn',v.toLowerCase()]; return ['label',v]; };
const makeRule = e => {
  const { direction, source, destination, port, protocol, labels, rules } = e;
  const r = {};
  const key = direction==='ingress'? source: destination;
  const prefix = direction==='ingress'? 'from': 'to';
  // селекторы
  if (labels) r[`${prefix}Endpoints`] = [{ matchLabels: labels }];
  else {
    const [t,v] = detectType(key);
    const field = prefix + (t==='label'? 'Endpoints': t==='fqdn'? 'FQDNs': 'CIDRSet');
    const obj = t==='label'? { matchLabels: splitLabels(v) }: t==='fqdn'? { matchName: v }: { cidr: v };
    r[field] = [obj];
  }
  // toPorts + вложенные rules
  const pItem = { port: String(port) };
  if (protocol && protocol.toUpperCase()!=='ANY') pItem.protocol = protocol.toUpperCase();
  const pb = { ports: [pItem] };
  if (rules) pb.rules = rules;
  r.toPorts = [pb];
  return r;
};

// ---- Парсинг Excel и валидация ----
function parseExcel(file) {
  const wb = XLSX.readFile(file);
  const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header:1, blankrows:false });
  if (!rows[1]||!rows[1][0]) throw new Error("❌ Не найден 'namespace:' во второй строке");
  const nsRaw = String(rows[1][0]).trim();
  if (!nsRaw.includes(':')) throw new Error("❌ Неверный формат namespace");
  const namespace = nsRaw.split(':').slice(1).join(':').trim();

  const groups = {};
  const entries = [];
  for (let i=2; i<rows.length; i++) {
    const row = rows[i]; if (!row||!row[0]) continue;
    const entry = {
      protocol: String(row[1]||'').trim(),
      source: String(row[2]||'').trim(),
      direction: String(row[3]||'').toLowerCase().trim(),
      destination: String(row[4]||'').trim(),
      port: String(row[5]||'').trim(),
      rowNum: i+1
    };
    entries.push(entry);
    const key = entry.source||'__excel__';
    (groups[key]||=(groups[key]=[])).push(entry);
  }
  return { namespace, groups, entries };
}

function validate(entries){
  const bad = entries.filter(e => /[А-Яа-яЁё]/.test(e.source+e.destination+e.protocol+e.direction+e.port));
  if (bad.length) { console.error('❌ Недопустимые символы на строках: '+bad.map(e=>e.rowNum).join(', ')); process.exit(1); }
  const seen = {}, dups = [];
  entries.forEach(e=>{ const k=[e.direction,e.source,e.destination,e.port,(e.protocol||'ANY').toUpperCase()].join('|'); if(seen[k]) dups.push({first:seen[k],dup:e.rowNum}); else seen[k]=e.rowNum; });
  if(dups.length){ console.warn('⚠️ Найден дубликат:'); dups.forEach(d=>console.warn(`строки ${d.first} и ${d.dup}`)); }
}

// ---- Сборка политик ----
const buildPolicy = (ns, key, ents) => {
  const labels = key==='__excel__'? {}: splitLabels(key);
  const suffix = Object.values(labels)[0]||'default';
  const name = `${ns}-${suffix}`;
  const spec = { endpointSelector: Object.keys(labels).length? { matchLabels: labels } : {} };
  const ingress = [], egress = [];
  ents.forEach(e=> (e.direction==='ingress'? ingress : egress).push(makeRule(e)));
  if(ingress.length) spec.ingress=ingress;
  if(egress.length) spec.egress=egress;
  return { apiVersion:'cilium.io/v2', kind:'CiliumNetworkPolicy', metadata:{name,namespace:ns}, spec };
};

// ---- Main ----
function main(){
  const file = process.argv[2]; if(!file) return console.error(`Usage: ${path.basename(process.argv[1])} <input.xlsx>`);
  const { namespace, groups, entries } = parseExcel(file);
  validate(entries);

  const hasAll = DEFAULT_RULES.every(cfg=> entries.some(e=> e.direction===cfg.direction && e.port===cfg.port && (cfg.protocol==='ANY'|| e.protocol.toUpperCase()===cfg.protocol)));
  console.log(hasAll ? '⚠️ Базовые политики из Excel переименованы и добавлены из default.yaml' : '⚠️ Базовые политики отсутствуют в Excel, добавлены из default.yaml');

  // Подменяем metadata для дефолтных политик
  const defaultPolicies = defaultDocs.map(doc => {
    return {
      ...doc,
      metadata: {
        name: `${namespace}-default`, // новое имя
        namespace: namespace         // новый namespace
      }
    };
  });

  const excelPolicies = Object.entries(groups)
    .filter(([k])=>k!=='__excel__')
    .map(([k,ents])=> buildPolicy(namespace,k,ents));
  if(groups['__excel__']) excelPolicies.push(buildPolicy(namespace,'__excel__',groups['__excel__']));

  const docs = [...defaultPolicies, ...excelPolicies]
    .map(p=> yaml.dump(p,{ sortKeys:false,noRefs:true,indent:2,lineWidth:-1 }));

  const out = `${namespace}.yaml`;
  const writeFile = ()=>{ fs.writeFileSync(out, docs.join('---\n'),'utf8'); console.log(`✅ Файл создан: ${out}`); };
  if(fs.existsSync(out)){
    readline.createInterface({input:process.stdin,output:process.stdout})
      .question(`⚠️ Файл ${out} уже существует. Перезаписать? (y/n): `,ans=>{ if(ans.toLowerCase().startsWith('y')) writeFile(); else console.log('❌ Отменено.'); process.exit(0); });
  } else writeFile();
}
if(require.main===module) main();
