"""Original Unlicense. Bounded read-only restore census, never restore/activation.

Caller must supply an already-open isolated PostgreSQL Django connection and a
reviewed runtime registry. Source/image/caller provenance is NOT self-attested.
Private manifests and keyed fingerprints must stay confidential. No CLI/output.
"""
from dataclasses import dataclass, field
import datetime
import decimal
import hashlib
import hmac
import inspect
import json
from pathlib import Path
import time

CONFIGURED = ('accounts', 'realms', 'compliance_checks', 'incidents', 'probes',
              'stores', 'terraform', 'inventory', 'santa')
DISPOSITIONS = frozenset(('preserve_inert', 'rewrap_preserve', 'disable_preserve',
                         'expire_preserve', 'revoke_preserve', 'reissue_separately'))

class CensusRejected(ValueError):
    pass

def need(ok):
    if not ok:
        raise CensusRejected('Restore census rejected; retain original inputs and inspect privately')

def canonical(value):
    """Typed canonical JSON values, without publishing raw hashes of secrets."""
    if value is None: return ['null']
    if type(value) is bool: return ['bool', value]
    if type(value) is str: return ['text', value]
    if type(value) is int: return ['number', str(value)]
    if type(value) is decimal.Decimal:
        need(value.is_finite() and len(value.as_tuple().digits) <= 100000)
        if not value: return ['number', '0']
        # Decimal.normalize uses the ambient precision context and can lose data.
        sign,digits,exponent=value.as_tuple();digits=list(digits)
        while digits[-1]==0:digits.pop();exponent+=1
        return ['decimal', sign, ''.join(map(str,digits)), exponent]
    if type(value) is list: return ['list', [canonical(v) for v in value]]
    need(type(value) is dict and all(type(k) is str for k in value))
    return ['map', [[k,canonical(value[k])] for k in sorted(value)]]

def encoded(value):
    return json.dumps(canonical(value),ensure_ascii=True,separators=(',',':')).encode()

def unique(items):
    result={}
    for key,value in items:
        need(key not in result);result[key]=value
    return result

def parse(raw):
    return json.loads(raw,parse_float=decimal.Decimal,object_pairs_hook=unique,
                      parse_constant=lambda value:need(False))

def keyed(key,kind,value):
    return hmac.new(key,kind.encode()+b'\0'+encoded(value),hashlib.sha256).hexdigest()

def relation_key(schema,table):return quote(schema)+'.'+quote(table)

def quote(value):
    need(type(value) is str and value and '\x00' not in value and len(value.encode())<=1024)
    return '"'+value.replace('"','""')+'"'

@dataclass(frozen=True)
class Limits:
    rows: int = 100000
    facts: int = 100000
    bytes: int = 64*1024**2
    value_bytes: int = 1024**2
    statement_ms: int = 10000
    lock_ms: int = 1000
    seconds: int = 120
    def __post_init__(self):
        for name,maximum in (('rows',1000000),('facts',200000),('bytes',256*1024**2),
                ('value_bytes',4*1024**2),('statement_ms',30000),('lock_ms',5000),('seconds',600)):
            value=getattr(self,name);need(type(value) is int and 0<value<=maximum)
        need(self.value_bytes<=self.bytes)

@dataclass(repr=False)
class Census:
    manifest: dict = field(repr=False)
    receipt: dict
    def __repr__(self): return '<private restore census; not authority>'

class Reader:
    def __init__(self,connection,limits,clock):
        self.connection=connection;self.limits=limits;self.clock=clock
        self.deadline=clock()+limits.seconds;self.bytes=0;self.facts=0;self.rows=0;self.serial=0
        self.cursor=connection.connection.cursor()
    def check(self): need(self.clock()<self.deadline)
    def execute(self,sql,params=None):
        self.check();self.cursor.execute(sql,params);self.check()
    def read(self,sql,*,data=False):
        self.serial+=1;name=quote('santa_census_'+str(self.serial))
        # The server does not send an oversized value to the client. A complete
        # scan must finish; limits reject, never truncate to a successful census.
        # Only a validated bounded integer is embedded. No read-query binds:
        # pyformat parsing would interpret literal '%' inside quoted identifiers.
        wrapped='SELECT octet_length(value), CASE WHEN octet_length(value)<='+str(self.limits.value_bytes)+' THEN value ELSE NULL END FROM ('+sql+') AS census_values(value)'
        self.execute('DECLARE '+name+' NO SCROLL CURSOR FOR '+wrapped)
        try:
            while True:
                self.execute('FETCH FORWARD 32 FROM '+name)
                batch=self.cursor.fetchall();need(type(batch) is list and len(batch)<=32)
                if not batch:break
                for size,raw in batch:
                    self.check();need(type(size) is int and 0<=size<=self.limits.value_bytes
                        and type(raw) is str and len(raw.encode())==size)
                    self.bytes+=size;need(self.bytes<=self.limits.bytes)
                    if data:self.rows+=1;need(self.rows<=self.limits.rows)
                    else:self.facts+=1;need(self.facts<=self.limits.facts)
                    yield parse(raw)
        finally:
            self.execute('CLOSE '+name)

# Names/definitions are private schema data. All queries enumerate every
# non-system namespace; no assumption that every object belongs to public.
NS="n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'"
CATALOG = {
 'schemas':"SELECT json_build_object('name',n.nspname,'owner',pg_get_userbyid(n.nspowner),'acl',n.nspacl)::text FROM pg_namespace n WHERE "+NS,
 'relations':"""SELECT json_build_object('schema',n.nspname,'name',c.relname,'kind',c.relkind,
 'owner',pg_get_userbyid(c.relowner),'persistence',c.relpersistence,'options',c.reloptions,'acl',c.relacl,
 'replica_identity',c.relreplident,'populated',c.relispopulated,
 'parents',ARRAY(SELECT json_build_array(pn.nspname,pc.relname) FROM pg_inherits h JOIN pg_class pc ON pc.oid=h.inhparent JOIN pg_namespace pn ON pn.oid=pc.relnamespace WHERE h.inhrelid=c.oid ORDER BY h.inhseqno),
 'tablespace',(SELECT spcname FROM pg_tablespace WHERE oid=c.reltablespace),
 'row_security',c.relrowsecurity,'force_row_security',c.relforcerowsecurity,'partition',c.relispartition,
 'partition_key',CASE WHEN c.relkind='p' THEN pg_get_partkeydef(c.oid) END,
 'bound',pg_get_expr(c.relpartbound,c.oid),'view',CASE WHEN c.relkind IN ('v','m') THEN pg_get_viewdef(c.oid,false) END)::text
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE """+NS,
 'columns':"""SELECT json_build_object('schema',n.nspname,'table',c.relname,'name',a.attname,'position',a.attnum,
 'dropped',a.attisdropped,'type_oid',a.atttypid::bigint,'type',format_type(a.atttypid,a.atttypmod),'type_schema',tn.nspname,'not_null',a.attnotnull,
 'acl',a.attacl,'options',a.attoptions,'fdw_options',a.attfdwoptions,'storage',a.attstorage,'compression',a.attcompression,'statistics',a.attstattarget,
 'identity',a.attidentity,'generated',a.attgenerated,'default',pg_get_expr(d.adbin,d.adrelid),
 'collation',CASE WHEN a.attcollation<>0 THEN json_build_array(cn.nspname,co.collname) END)::text
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 LEFT JOIN pg_type t ON t.oid=a.atttypid LEFT JOIN pg_namespace tn ON tn.oid=t.typnamespace
 LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 LEFT JOIN pg_collation co ON co.oid=a.attcollation LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace
 WHERE a.attnum>0 AND """+NS,
 'constraints':"""SELECT json_build_object('schema',n.nspname,'name',co.conname,'table',c.relname,
 'type',co.contype,'columns',ARRAY(SELECT a.attname FROM unnest(co.conkey) WITH ORDINALITY k(num,ord) JOIN pg_attribute a ON a.attrelid=co.conrelid AND a.attnum=k.num ORDER BY k.ord),
 'foreign_schema',fn.nspname,'foreign_table',fc.relname,'foreign_columns',ARRAY(SELECT a.attname FROM unnest(co.confkey) WITH ORDINALITY k(num,ord) JOIN pg_attribute a ON a.attrelid=co.confrelid AND a.attnum=k.num ORDER BY k.ord),
 'definition',pg_get_constraintdef(co.oid,false),'validated',co.convalidated,
 'deferrable',co.condeferrable,'deferred',co.condeferred)::text
 FROM pg_constraint co JOIN pg_namespace n ON n.oid=co.connamespace LEFT JOIN pg_class c ON c.oid=co.conrelid LEFT JOIN pg_class fc ON fc.oid=co.confrelid LEFT JOIN pg_namespace fn ON fn.oid=fc.relnamespace WHERE """+NS,
 'indexes':"""SELECT json_build_object('schema',n.nspname,'table',c.relname,'name',ic.relname,
 'definition',pg_get_indexdef(i.indexrelid),'valid',i.indisvalid,'ready',i.indisready,
 'unique',i.indisunique,'primary',i.indisprimary,'replica_identity',i.indisreplident)::text
 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_class ic ON ic.oid=i.indexrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE """+NS,
 'triggers':"""SELECT json_build_object('schema',n.nspname,'table',c.relname,'name',t.tgname,
 'enabled',t.tgenabled,'internal',t.tgisinternal,'definition',pg_get_triggerdef(t.oid,false))::text
 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE """+NS,
 'rules':"""SELECT json_build_object('schema',n.nspname,'table',c.relname,'name',r.rulename,
 'enabled',r.ev_enabled,'definition',pg_get_ruledef(r.oid,false))::text
 FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace WHERE """+NS,
 'policies':"""SELECT json_build_object('schema',n.nspname,'table',c.relname,'name',p.polname,
 'command',p.polcmd,'permissive',p.polpermissive,'roles',ARRAY(SELECT pg_get_userbyid(x) FROM unnest(p.polroles) x),
 'using',pg_get_expr(p.polqual,p.polrelid),'check',pg_get_expr(p.polwithcheck,p.polrelid))::text
 FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE """+NS,
 'types':"""SELECT json_build_object('schema',n.nspname,'name',t.typname,'kind',t.typtype,
 'owner',pg_get_userbyid(t.typowner),'element',CASE WHEN t.typelem<>0 THEN format_type(t.typelem,NULL) END,
 'input',t.typinput::regprocedure::text,'output',t.typoutput::regprocedure::text,'base',format_type(t.typbasetype,t.typtypmod),
 'not_null',t.typnotnull,'default',t.typdefault,'enum',ARRAY(SELECT e.enumlabel FROM pg_enum e WHERE e.enumtypid=t.oid ORDER BY e.enumsortorder))::text
 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE """+NS,
 'routines':"""SELECT json_build_object('schema',n.nspname,'name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),
 'kind',p.prokind,'owner',pg_get_userbyid(p.proowner),'acl',p.proacl,'security_definer',p.prosecdef,'config',p.proconfig,
 'definition',CASE WHEN p.prokind IN ('f','p','w') THEN pg_get_functiondef(p.oid) END)::text
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE """+NS,
 'sequences':"""SELECT json_build_object('schema',n.nspname,'name',c.relname,'type',format_type(s.seqtypid,NULL),
 'start',s.seqstart,'increment',s.seqincrement,'maximum',s.seqmax,'minimum',s.seqmin,'cache',s.seqcache,'cycle',s.seqcycle)::text
 FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE """+NS,
 'objects':"""WITH RECURSIVE objects(classid,objid,objsubid) AS (
 SELECT 'pg_namespace'::regclass::oid,n.oid,0 FROM pg_namespace n WHERE """+NS+"""
 UNION SELECT d.classid,d.objid,d.objsubid FROM pg_depend d JOIN objects o
 ON d.refclassid=o.classid AND d.refobjid=o.objid AND (o.objsubid=0 OR d.refobjsubid=o.objsubid))
 SELECT json_build_object('catalog',classid::regclass::text,'type',i.type,'schema',i.schema,'name',i.name,'identity',i.identity)::text
 FROM objects o CROSS JOIN LATERAL pg_identify_object(o.classid,o.objid,o.objsubid) i""",
 'extensions':"SELECT json_build_object('name',e.extname,'version',e.extversion,'relocatable',e.extrelocatable,'configuration',ARRAY(SELECT x::regclass::text FROM unnest(e.extconfig) x),'condition',e.extcondition,'schema',n.nspname,'owner',pg_get_userbyid(e.extowner))::text FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace",
 'global_blockers':"SELECT json_build_object('kind','large_objects','count',count(*))::text FROM pg_largeobject_metadata HAVING count(*)>0 UNION ALL SELECT json_build_object('kind','foreign_servers','count',count(*))::text FROM pg_foreign_server HAVING count(*)>0 UNION ALL SELECT json_build_object('kind','publications','count',count(*))::text FROM pg_publication HAVING count(*)>0 UNION ALL SELECT json_build_object('kind','subscriptions','count',count(*))::text FROM pg_subscription HAVING count(*)>0 UNION ALL SELECT json_build_object('kind','event_triggers','count',count(*))::text FROM pg_event_trigger HAVING count(*)>0 UNION ALL SELECT json_build_object('kind','custom_casts','count',count(*))::text FROM pg_cast WHERE oid>=16384 HAVING count(*)>0",
 'database':"SELECT json_build_object('version',current_setting('server_version_num'),'encoding',current_setting('server_encoding'),'database',current_database(),'user',current_user,'collation',d.datcollate,'ctype',d.datctype,'collation_provider',d.datlocprovider,'collation_version',d.datcollversion,'locale',to_jsonb(d)->>'datlocale','tablespace',sp.spcname,'read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'))::text FROM pg_database d JOIN pg_tablespace sp ON sp.oid=d.dattablespace WHERE d.datname=current_database()",
}
SUPPORTED_CATALOGS=frozenset(('pg_namespace','pg_class','pg_type','pg_proc','pg_constraint',
    'pg_attrdef','pg_trigger','pg_rewrite','pg_policy'))


def registry_manifest(registry,connection):
    need(registry.ready is True)
    apps=[];models=[]
    for app in registry.get_app_configs():
        apps.append(dict(label=app.label,name=app.name))
    for model in registry.get_models(include_auto_created=True,include_swapped=True):
        meta=model._meta;fields=[]
        for item in meta.get_fields(include_parents=True,include_hidden=True):
            remote=getattr(item,'related_model',None)
            through=getattr(getattr(item,'remote_field',None),'through',None) or getattr(item,'through',None)
            target=item.target_field.column if getattr(item,'concrete',False) and (getattr(item,'many_to_one',False) or getattr(item,'one_to_one',False)) else None
            fields.append(dict(name=item.name,column=getattr(item,'column',None),local=item in meta.local_fields,
                type=item.__class__.__module__+'.'+item.__class__.__name__,
                concrete=bool(getattr(item,'concrete',False)),auto_created=bool(item.auto_created),
                null=bool(getattr(item,'null',False)),primary_key=bool(getattr(item,'primary_key',False)),
                unique=bool(getattr(item,'unique',False)),many_to_many=bool(item.many_to_many),
                related=remote._meta.label_lower if remote is not None else None,
                source_field=getattr(getattr(item,'field',None),'name',None),
                source_column=getattr(getattr(item,'field',None),'column',None),
                through=through._meta.label_lower if through is not None else None,
                target=target,db_constraint=getattr(item,'db_constraint',None)))
        models.append(dict(label=meta.label_lower,table=meta.db_table,managed=bool(meta.managed),
            proxy=bool(meta.proxy),swapped=meta.swapped,auto_created=bool(meta.auto_created),
            concrete_model=meta.concrete_model._meta.label_lower,fields=sorted(fields,key=lambda f:f['name'])))
    need(len(apps)==len({a['label'] for a in apps}) and len(models)==len({m['label'] for m in models}))
    need(set(CONFIGURED)<={a['label'] for a in apps})
    return dict(apps=sorted(apps,key=lambda a:a['label']),models=sorted(models,key=lambda m:m['label']))


def migration_manifest(connection,applied_records):
    from django.db import connections
    from django.db.migrations.loader import MigrationLoader
    need(connections[connection.alias] is connection)
    # Complete records were already fetched under the same snapshot and limits;
    # loader SQL cannot see additional migration rows in this transaction.
    loader=MigrationLoader(connection,ignore_no_migrations=True)
    applied={(r['app'],r['name']) for r in applied_records}
    need(len(applied)==len(applied_records) and set(loader.applied_migrations)==applied)
    known=set(loader.disk_migrations)|{tuple(v) for m in loader.disk_migrations.values() for v in m.replaces}
    need(applied<=known);loader.check_consistent_history(connection)
    disk=[]
    for key,migration in sorted(loader.disk_migrations.items()):
        path=Path(inspect.getfile(type(migration)));need(path.is_file() and path.stat().st_size<=262144)
        raw=path.read_bytes();need(len(raw)<=262144)
        disk.append(dict(node=list(key),sha256=hashlib.sha256(raw).hexdigest(),
            dependencies=[list(v) for v in migration.dependencies],run_before=[list(v) for v in migration.run_before],
            replaces=[list(v) for v in migration.replaces]))
    nodes=[dict(node=list(key),parents=sorted([list(v.key) for v in node.parents]))
           for key,node in sorted(loader.graph.node_map.items())]
    return dict(disk=disk,graph=nodes,applied=applied_records,
        migrated_apps=sorted(loader.migrated_apps),unmigrated_apps=sorted(loader.unmigrated_apps))


def collect(connection,registry,*,fingerprint_key,limits=Limits(),clock=time.monotonic,
            migration_reader=migration_manifest):
    """Observe only; already-open connection prevents implicit connection/auth.

    Run inside an externally bounded, network-isolated trusted runtime. This
    function performs SQL reads; it does not construct credentials or connections.
    """
    reader=None;begun=False
    try:
        need(type(fingerprint_key) is bytes and len(fingerprint_key)==32 and isinstance(limits,Limits))
        need(connection.vendor=='postgresql' and connection.connection is not None
            and getattr(connection.connection,'closed',True)==0
            and (getattr(connection,'health_check_enabled',True) is False or getattr(connection,'health_check_done',False) is True)
            and connection.get_autocommit() is True and connection.in_atomic_block is False)
        reader=Reader(connection,limits,clock)
        begun=True;reader.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
        for name,value in (('statement_timeout',str(limits.statement_ms)),('lock_timeout',str(limits.lock_ms)),
            ('idle_in_transaction_session_timeout',str(limits.seconds*1000)),('row_security','off'),
            ('search_path','pg_catalog, public'),('TimeZone','UTC'),('DateStyle','ISO, YMD'),('IntervalStyle','iso_8601'),('bytea_output','hex'),('extra_float_digits','3')):
            reader.execute('SELECT set_config(%s,%s,true)',(name,value))
        before=registry_manifest(registry,connection);need(len(encoded(before))<=limits.bytes)
        catalog={key:list(reader.read(sql)) for key,sql in CATALOG.items()}
        need(len(catalog['database'])==1 and catalog['database'][0]['read_only']=='on'
             and catalog['database'][0]['isolation']=='repeatable read' and catalog['database'][0]['encoding']=='UTF8')
        need(len(catalog['relations'])==len({relation_key(r['schema'],r['name']) for r in catalog['relations']}))
        unsupported=[dict(category='catalog',identity=o['identity']) for o in catalog['objects'] if o['catalog'] not in SUPPORTED_CATALOGS]
        unsupported += [dict(category='global',identity=v['kind']) for v in catalog['global_blockers']]
        unsupported += [dict(category='routine',identity=relation_key(v['schema'],v['name'])) for v in catalog['routines'] if v['kind'] not in ('f','p','w')]
        unsupported += [dict(category='type',identity=relation_key(v['schema'],v['name'])) for v in catalog['types'] if v['kind']!='c' and not (v['kind']=='b' and v['element'] is not None)]
        unsupported += [dict(category='relation',identity=relation_key(r['schema'],r['name'])) for r in catalog['relations'] if r['kind'] not in ('r','p','S','v','m','i','I','c','t')]
        for relation in catalog['relations']:
            columns=[c for c in catalog['columns'] if c['schema']==relation['schema'] and c['table']==relation['name'] and not c['dropped']]
            if relation['row_security'] or any(c['type_schema']!='pg_catalog' or type(c['type_oid']) is not int or not 0<c['type_oid']<16384 or c['generated'] for c in columns):
                unsupported.append(dict(category='row_read',identity=relation_key(relation['schema'],relation['name'])))
        data={};applied=[]
        for relation in (() if unsupported else catalog['relations']):
            kind=relation['kind'];schema=relation['schema'];table=relation['name'];identity=relation_key(schema,table)
            if kind not in ('r','p','m','S'):continue
            # Never execute foreign-table wrappers, views, custom type output
            # functions or filtered RLS reads. Unknowns remain private blockers.
            columns=[c for c in catalog['columns'] if c['schema']==schema and c['table']==table and not c['dropped']]
            qualified=quote(schema)+'.'+quote(table)
            if kind=='S':sql="SELECT json_build_object('last_value',last_value,'is_called',is_called)::text FROM "+qualified
            else:sql='SELECT row_to_json(t)::text FROM '+('' if kind=='m' else 'ONLY ')+qualified+' t'
            digests=[]
            for row in reader.read(sql,data=True):
                need(type(row) is dict and set(row)==({'last_value','is_called'} if kind=='S' else {c['name'] for c in columns}))
                digests.append(keyed(fingerprint_key,'row:'+identity,row))
                if schema=='public' and table=='django_migrations':applied.append(row)
            data[identity]=dict(rows=len(digests),fingerprint=keyed(fingerprint_key,'table:'+identity,sorted(digests)))
        if unsupported:migrations=None
        else:
            need(relation_key('public','django_migrations') in data)
            migrations=migration_reader(connection,sorted(applied,key=lambda r:(r['app'],r['name'])))
        need(before==registry_manifest(registry,connection));reader.check()
        manifest=dict(scope='private-restore-census-v1',registry=before,migrations=migrations,
            catalog={k:sorted(v,key=lambda item:encoded(item)) for k,v in catalog.items()},data=data,unsupported=unsupported)
        need(len(encoded(manifest))<=limits.bytes)
        receipt=dict(scope='restore-census-observation-v1',tables=len(data),rows=reader.rows,
            schema_facts=reader.facts,observed_bytes=reader.bytes,unsupported_facts=len(unsupported),
            complete_supported_data=not unsupported,
            fingerprint=keyed(fingerprint_key,'census',manifest),read_only=True,
            provenance_authenticated=False,coverage_reviewed=False,sequence_quiescence_proven=False,
            restore_accepted=False,current_authority=False)
        return Census(manifest,receipt)
    except Exception:
        raise CensusRejected('Restore census rejected; retain original inputs and inspect privately') from None
    finally:
        if reader is not None:
            try:
                try:
                    if begun:reader.cursor.execute('ROLLBACK')
                finally:reader.cursor.close()
            except Exception:
                raise CensusRejected('Restore census rollback/close failed; discard connection and retain evidence') from None


def coverage_items(observed,*,fingerprint_key):
    """Private exhaustive review keys; never supplies default dispositions."""
    manifest=observed.manifest
    keys={'app:'+a['label'] for a in manifest['registry']['apps']}
    for model in manifest['registry']['models']:
        keys.add('model:'+model['label'])
        for item in model['fields']:keys.add('field:'+model['label']+':'+keyed(fingerprint_key,'model-field',item))
    keys.update('table:'+table for table in manifest['data'])
    for category,records in manifest['catalog'].items():
        keys.update('catalog:'+category+':'+keyed(fingerprint_key,'schema-fact',record) for record in records)
    migrations=manifest['migrations']
    if migrations is not None:
        for category,records in migrations.items():
            keys.update('migration:'+category+':'+keyed(fingerprint_key,'migration-fact',record) for record in records)
    return keys


def compare(observed,expected,dispositions,*,fingerprint_key):
    """Exact reviewed baseline and exhaustive model/physical-table mapping.

    expected/dispositions must come from independent review; agreement with
    caller input does not authenticate provenance or prove restored authority.
    """
    try:
        need(type(observed) is Census and type(expected) is Census and not observed.manifest['unsupported']
             and not expected.manifest['unsupported'] and type(dispositions) is dict
             and type(fingerprint_key) is bytes and len(fingerprint_key)==32)
        for value in (observed,expected):
            need(set(value.manifest)=={'scope','registry','migrations','catalog','data','unsupported'}
                and value.manifest['scope']=='private-restore-census-v1' and set(value.manifest['catalog'])==set(CATALOG)
                and value.receipt['fingerprint']==keyed(fingerprint_key,'census',value.manifest))
        need(encoded(observed.manifest)==encoded(expected.manifest))
        models=observed.manifest['registry']['models'];tables=observed.manifest['data']
        keys=coverage_items(observed,fingerprint_key=fingerprint_key)
        # No fallback disposition, including baseline, proxy and through models.
        need(set(dispositions)==keys and all(v in DISPOSITIONS for v in dispositions.values()))
        physical={relation_key(r['schema'],r['name']) for r in observed.manifest['catalog']['relations'] if r['kind'] in ('r','p','m','S')}
        need(physical==set(tables))
        all_relations={relation_key(r['schema'],r['name']):r['kind'] for r in observed.manifest['catalog']['relations']}
        by_label={m['label']:m for m in models}
        for model in models:
            if model['swapped']:continue
            table=relation_key('public',model['table']);need(table in all_relations
                and all_relations[table] in (('r','p') if model['managed'] else ('r','p','v','m')))
            if not model['proxy']:
                actual={c['name'] for c in observed.manifest['catalog']['columns'] if relation_key(c['schema'],c['table'])==table and not c['dropped']}
                need(actual=={f['column'] for f in model['fields'] if f['local'] and f['concrete'] and f['column'] is not None})
                constraints=[v for v in observed.manifest['catalog']['constraints'] if relation_key(v['schema'],v['table'])==table]
                for item in model['fields']:
                    if not (item['local'] and item['concrete'] and item['column'] is not None):continue
                    if item['primary_key'] or item['unique']:
                        need(any(v['type'] in ('p','u') and v['columns']==[item['column']] for v in constraints))
                    if item['target'] is not None and item['db_constraint'] is not False:
                        remote=by_label[item['related']]
                        need(any(v['type']=='f' and v['columns']==[item['column']]
                            and v['foreign_schema']=='public' and v['foreign_table']==remote['table']
                            and v['foreign_columns']==[item['target']] for v in constraints))
        return dict(scope='restore-census-comparison-v1',exact_match=True,mapped_items=len(keys),
            fingerprint=keyed(fingerprint_key,'comparison',observed.manifest),
            provenance_authenticated=False,current_authority=False,restore_accepted=False)
    except Exception:
        raise CensusRejected('Restore census comparison rejected; retain original inputs and inspect privately') from None
