"""Controlled SQL/Django adapter fixtures only; no actual PostgreSQL proof."""
import copy
import importlib.util
import json
import re
from pathlib import Path
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('restore_census',Path(__file__).resolve().parents[1]/'experiments/server/restore_census.py')
c=importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name]=c;spec.loader.exec_module(c)
KEY=b'k'*32

class Column:
    def __init__(self,name,column=None,related=None,through=None):
        self.name=name;self.column=column or name;self.related_model=related
        self.remote_field=NS(through=through);self.auto_created=False
        self.concrete=True;self.null=False;self.primary_key=name=='id';self.unique=False
        self.many_to_many=False;self.many_to_one=related is not None;self.one_to_one=False
        if related is not None:self.target_field=NS(column='id')

def model(label,table,columns=('id',),*,proxy=False,auto=False,managed=True):
    fields=[Column(name) for name in columns]
    meta=NS(label_lower=label,db_table=table,managed=managed,proxy=proxy,swapped=None,auto_created=auto,
        local_fields=fields,get_fields=lambda **kwargs:fields)
    value=NS(_meta=meta);meta.concrete_model=value;return value

class Registry:
    ready=True
    def __init__(self):
        self.apps=[NS(label=name,name=name) for name in c.CONFIGURED+('auth','contenttypes','sessions','django_celery_results','base')]
        self.models=[model('accounts.user','accounts_user',('id','secret')),
            model('auth.group','auth_group'),model('accounts.user_groups','accounts_user_groups',auto=True),
            model('accounts.userproxy','accounts_user',('id','secret'),proxy=True)]
        self.models[2]._meta.local_fields.append(Column('user_id',related=self.models[0]))
    def get_app_configs(self):return self.apps
    def get_models(self,**kwargs):
        assert kwargs==dict(include_auto_created=True,include_swapped=True)
        return self.models

class Cursor:
    def __init__(self,connection):self.connection=connection;self.stream=[];self.closed=False
    def execute(self,sql,params=None):
        db=self.connection;db.commands.append((sql,params))
        if params is not None:
            # Model driver pyformat parsing, including markers inside SQL quotes.
            assert len(re.findall(r'%s',sql.replace('%%','')))==len(params)
        if db.fail and db.fail in sql:raise RuntimeError('raw credential must never escape')
        if sql.startswith('DECLARE '):
            assert params is None
            db.maximum=int(re.search(r'octet_length\(value\)<=(\d+)',sql).group(1))
            body=sql.split(' FROM (',1)[1].rsplit(') AS census_values(value)',1)[0]
            key=next((name for name,query in c.CATALOG.items() if query==body),None)
            if key:
                self.stream=copy.deepcopy(db.catalog[key])
                # PG18 categorizes oid as OTHER (JSON text), bigint as NUMERIC.
                if key=='columns' and not re.search(r"'type_oid',\s*a\.atttypid::bigint",body):
                    for item in self.stream:item['type_oid']=str(item['type_oid'])
            else:
                table=next((name for name in db.data if c.quote('public')+'.'+c.quote(name) in body),None)
                assert table is not None,body
                self.stream=copy.deepcopy(db.data[table])
            db.reads.append(key or table)
        if sql.startswith('FETCH '):
            take=self.stream[:32];self.stream=self.stream[32:]
            self.batch=[]
            for row in take:
                raw=json.dumps(row,separators=(',',':'));size=len(raw.encode())
                self.batch.append((size,raw if size<=db.maximum else None))
    def fetchall(self):return self.batch
    def close(self):self.closed=True

class RawConnection:
    def __init__(self,owner):
        self.owner=owner;self.closed=False;self.autocommit=True;self.state=0
    def get_transaction_status(self):return self.state
    def cursor(self):
        self.owner.cursor_calls+=1
        return self.owner.cursor_instance

class Connection:
    vendor='postgresql';in_atomic_block=False;health_check_enabled=False;alias='default'
    def __init__(self):
        self.commands=[];self.reads=[];self.fail=None;self.cursor_instance=Cursor(self)
        self.connection=RawConnection(self);self.cursor_calls=0
        self.Database=NS(__name__='psycopg2',__version__='2.9.11 (dt dec pq3 ext lo64)',
            extensions=NS(connection=RawConnection,TRANSACTION_STATUS_IDLE=0))
        self.catalog={key:[] for key in c.CATALOG}
        self.catalog['database']=[dict(version='180000',encoding='UTF8',database='isolated',user='reader',read_only='on',isolation='repeatable read')]
        self.catalog['schemas']=[dict(name='public',owner='reader',acl=None)]
        self.data=dict(accounts_user=[dict(id=1,secret='confidential sentinel'),dict(id=2,secret='different')],auth_group=[],
            accounts_user_groups=[dict(id=1,user_id=1)],django_migrations=[dict(id=1,app='accounts',name='0001_initial',applied='2026-11-15T00:00:00')])
        for table,rows in self.data.items():
            self.catalog['relations'].append(dict(schema='public',name=table,kind='r',row_security=False))
            fields=list(rows[0]) if rows else ['id']
            for i,name in enumerate(fields):
                self.catalog['columns'].append(dict(schema='public',table=table,name=name,position=i+1,type='integer' if name=='id' else 'text',type_schema='pg_catalog',type_oid=23 if name=='id' else 25,generated='',dropped=False))
        self.catalog['constraints']=[dict(schema='public',table='accounts_user_groups',name='user_fk',type='f',columns=['user_id'],foreign_schema='public',foreign_table='accounts_user',foreign_columns=['id'],definition='FOREIGN KEY (user_id) REFERENCES accounts_user(id)')]
        self.catalog['constraints'] += [dict(schema='public',table=table,name=table+'_pkey',type='p',columns=['id'],definition='PRIMARY KEY (id)') for table in self.data]
        self.catalog['objects']=[dict(catalog='pg_class',type='table',schema='public',name=name,identity='public.'+name) for name in self.data]
    def cursor(self):return self.cursor_instance
    def get_autocommit(self):return True

def migrations(connection,records):
    return dict(disk=[dict(node=['accounts','0001_initial'],sha256='a'*64,dependencies=[],run_before=[],replaces=[])],
        graph=[dict(node=['accounts','0001_initial'],parents=[])],applied=records,migrated_apps=['accounts'],unmigrated_apps=[])

class CensusTests(unittest.TestCase):
    def setUp(self):self.db=Connection();self.registry=Registry()
    def collect(self,**kwargs):return c.collect(self.db,self.registry,fingerprint_key=KEY,migration_reader=migrations,**kwargs)
    def mapping(self,observation):
        return {key:'preserve_inert' for key in c.coverage_items(observation,fingerprint_key=KEY)}
    def test_complete_fixture_registry_through_proxy_schema_rows_and_readonly_rollback(self):
        observed=self.collect();receipt=c.compare(observed,copy.deepcopy(observed),self.mapping(observed),fingerprint_key=KEY)
        self.assertTrue(receipt['exact_match']);self.assertFalse(receipt['current_authority']);self.assertFalse(receipt['provenance_authenticated'])
        for result in (receipt,observed.receipt):
            self.assertFalse(result['schema_complete']);self.assertEqual(result['referenced_definitions'],'unproven')
        self.assertEqual(observed.receipt['rows'],4);self.assertTrue(observed.receipt['complete_supported_data'])
        self.assertEqual(len(observed.manifest['registry']['models']),4)
        self.assertEqual(observed.manifest['data'][c.relation_key('public','auth_group')]['rows'],0)
        self.assertEqual(self.db.commands[0][0],'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
        self.assertEqual(self.db.commands[-1][0],'ROLLBACK');self.assertTrue(self.db.cursor_instance.closed)
        self.assertEqual(sum(sql.startswith('BEGIN ') for sql,_ in self.db.commands),1)
        settings={params[0]:params[1] for sql,params in self.db.commands if sql.startswith('SELECT set_config')}
        self.assertEqual(settings['row_security'],'off');self.assertEqual(settings['search_path'],'pg_catalog, public')
        self.assertEqual(settings['lock_timeout'],'1000');self.assertEqual(settings['statement_timeout'],'10000')
        self.assertNotIn('confidential sentinel',repr(observed));self.assertNotIn('confidential sentinel',json.dumps(observed.receipt))
        self.assertNotIn('confidential sentinel',json.dumps(self.db.commands))
    def test_no_implicit_connect_nested_transaction_wrong_backend_or_bad_key(self):
        for field,value in (('connection',None),('vendor','sqlite'),('in_atomic_block',True)):
            db=Connection();setattr(db,field,value)
            with self.assertRaises(c.CensusRejected):c.collect(db,self.registry,fingerprint_key=KEY,migration_reader=migrations)
            self.assertEqual(db.commands,[])
        with self.assertRaises(c.CensusRejected):c.collect(self.db,self.registry,fingerprint_key=b'short')
    def test_raw_driver_must_be_idle_before_any_cursor_sql_or_rollback(self):
        for state in (1,2,3,4,None,'0',False,99):
            self.setUp();self.db.connection.state=state
            with self.subTest(state=state),self.assertRaises(c.CensusRejected):self.collect()
            self.assertEqual(self.db.commands,[]);self.assertEqual(self.db.cursor_calls,0)
        # Model raw BEGIN despite all Django/autocommit flags remaining true.
        self.setUp();self.db.connection.state=2;caller_work=['must preserve pending work']
        with self.assertRaises(c.CensusRejected):self.collect()
        self.assertEqual(caller_work,['must preserve pending work']);self.assertEqual(self.db.commands,[])
        self.assertEqual(self.db.connection.state,2)

    def test_unknown_driver_version_missing_status_api_or_non_autocommit_rejects(self):
        for change in ('driver','version','method','info-only','raw-class','autocommit'):
            self.setUp()
            if change=='driver':self.db.Database.__name__='psycopg'
            elif change=='version':self.db.Database.__version__='2.9.12'
            elif change=='method':self.db.connection.get_transaction_status=None
            elif change=='info-only':
                self.db.connection.get_transaction_status=None;self.db.connection.info=NS(transaction_status=0)
            elif change=='raw-class':self.db.Database.extensions.connection=dict
            else:self.db.connection.autocommit=False
            with self.subTest(change=change),self.assertRaises(c.CensusRejected):self.collect()
            self.assertEqual(self.db.commands,[]);self.assertEqual(self.db.cursor_calls,0)

    def test_missing_required_app_rejects_and_registry_drift_rejects(self):
        self.registry.apps.pop(0)
        with self.assertRaises(c.CensusRejected):self.collect()
        self.assertEqual(self.db.commands[-1][0],'ROLLBACK')
        self.setUp();original=c.registry_manifest;calls=[]
        def drift(*args):
            result=original(*args);calls.append(1)
            if len(calls)>1:result['apps'].pop()
            return result
        with patch.object(c,'registry_manifest',side_effect=drift),self.assertRaises(c.CensusRejected):self.collect()
    def test_schema_model_migration_relationship_row_and_empty_table_drift_reject(self):
        baseline=self.collect()
        for category in ('app','model','field','migration','graph','table','column','relationship','row','empty'):
            changed=copy.deepcopy(baseline)
            if category=='app':changed.manifest['registry']['apps'].pop()
            elif category=='model':changed.manifest['registry']['models'].pop()
            elif category=='field':changed.manifest['registry']['models'][0]['fields'].pop()
            elif category=='migration':changed.manifest['migrations']['applied'].pop()
            elif category=='graph':changed.manifest['migrations']['graph'][0]['parents']=[['unknown','0001']]
            elif category=='table':changed.manifest['data'].pop(c.relation_key('public','auth_group'))
            elif category=='column':changed.manifest['catalog']['columns'].pop()
            elif category=='relationship':changed.manifest['catalog']['constraints'][0]['definition']='changed foreign key'
            elif category=='row':changed.manifest['data'][c.relation_key('public','accounts_user')]['rows']+=1
            else:changed.manifest['data'][c.relation_key('public','auth_group')]['fingerprint']='0'*64
            with self.subTest(category=category),self.assertRaises(c.CensusRejected):c.compare(changed,baseline,self.mapping(baseline),fingerprint_key=KEY)
    def test_mapping_has_no_default_and_does_not_ignore_extra_or_unknown_categories(self):
        observed=self.collect();mapping=self.mapping(observed)
        for kind in ('missing','extra','unsupported'):
            changed=mapping.copy()
            if kind=='missing':changed.pop(next(iter(changed)))
            elif kind=='extra':changed['model:unknown.model']='preserve_inert'
            else:changed[next(iter(changed))]='activate'
            with self.assertRaises(c.CensusRejected):c.compare(observed,observed,changed,fingerprint_key=KEY)
    def test_coherence_rejects_model_missing_table_or_column_even_if_baseline_matches(self):
        observed=self.collect()
        for kind in ('model','column'):
            changed=copy.deepcopy(observed)
            if kind=='model':changed.manifest['registry']['models'][0]['table']='missing'
            else:changed.manifest['catalog']['columns'].pop()
            with self.assertRaises(c.CensusRejected):c.compare(changed,changed,self.mapping(changed),fingerprint_key=KEY)
    def test_unknown_objects_foreign_tables_rls_generated_custom_types_block_data_reads(self):
        for kind in ('catalog','foreign','rls','generated','type','catalog-type','global'):
            self.setUp()
            if kind=='catalog':self.db.catalog['objects'][0]['catalog']='pg_operator'
            elif kind=='foreign':self.db.catalog['relations'][0]['kind']='f'
            elif kind=='rls':self.db.catalog['relations'][0]['row_security']=True
            elif kind=='generated':self.db.catalog['columns'][0]['generated']='v'
            elif kind=='type':self.db.catalog['columns'][0]['type_schema']='unreviewed'
            elif kind=='catalog-type':self.db.catalog['columns'][0]['type_oid']=20000
            else:self.db.catalog['global_blockers']=[dict(kind='large_objects',count=1)]
            observed=self.collect()
            self.assertGreater(observed.receipt['unsupported_facts'],0);self.assertFalse(observed.receipt['complete_supported_data'])
            self.assertEqual(set(self.db.reads),set(c.CATALOG));self.assertEqual(observed.manifest['data'],{})
            with self.assertRaises(c.CensusRejected):c.compare(observed,observed,self.mapping(observed),fingerprint_key=KEY)
    def test_row_omission_shape_or_duplicate_json_is_not_accepted(self):
        self.db.data['accounts_user'][0].pop('secret')
        with self.assertRaises(c.CensusRejected):self.collect()
        with self.assertRaises(c.CensusRejected):c.parse('{"id":1,"id":2}')
    def test_fresh_valid_observations_detect_model_schema_row_and_relationship_drift(self):
        baseline=self.collect()
        for kind in ('app','model','column','relationship','row','missing-row','migration'):
            self.setUp()
            if kind=='app':self.registry.apps.append(NS(label='extra',name='unexpected.extra'))
            elif kind=='model':self.registry.models.pop()
            elif kind=='column':self.db.catalog['columns'][0]['type']='bigint'
            elif kind=='relationship':self.db.catalog['constraints'][0]['definition']='different FK target'
            elif kind=='row':self.db.data['accounts_user'][0]['secret']='changed secret'
            elif kind=='missing-row':self.db.data['accounts_user'].pop()
            else:self.db.data['django_migrations'][0]['name']='0002_unreviewed'
            observed=self.collect()
            self.assertEqual(observed.receipt['fingerprint'],c.keyed(KEY,'census',observed.manifest))
            with self.subTest(kind=kind),self.assertRaises(c.CensusRejected):
                c.compare(observed,baseline,self.mapping(baseline),fingerprint_key=KEY)

    def test_model_foreign_key_or_primary_key_mismatch_is_not_a_coherent_baseline(self):
        for kind in ('fk','pk'):
            self.setUp()
            if kind=='fk':self.db.catalog['constraints'][0]['foreign_table']='auth_group'
            else:self.db.catalog['constraints']=[v for v in self.db.catalog['constraints'] if v['type']!='p']
            observed=self.collect()
            with self.assertRaises(c.CensusRejected):c.compare(observed,observed,self.mapping(observed),fingerprint_key=KEY)

    def test_pg18_oid_wire_requires_numeric_cast_without_weakening_classifier(self):
        observed=self.collect();self.assertTrue(observed.receipt['complete_supported_data'])
        raw_query=c.CATALOG['columns'].replace('a.atttypid::bigint','a.atttypid')
        self.db=Connection()
        with patch.dict(c.CATALOG,{'columns':raw_query}):
            uncast=self.collect()
        self.assertIs(type(uncast.manifest['catalog']['columns'][0]['type_oid']),str)
        self.assertFalse(uncast.receipt['complete_supported_data']);self.assertEqual(uncast.manifest['data'],{})
        with self.assertRaises(c.CensusRejected):c.compare(uncast,uncast,self.mapping(uncast),fingerprint_key=KEY)

    def test_percent_identifiers_are_literal_on_parameter_free_read_wire(self):
        name='literal%s%table'
        self.db.data[name]=[dict(id=4)]
        self.db.catalog['relations'].append(dict(schema='public',name=name,kind='r',row_security=False))
        self.db.catalog['columns'].append(dict(schema='public',table=name,name='id',position=1,type='integer',
            type_schema='pg_catalog',type_oid=23,generated='',dropped=False))
        observed=self.collect()
        self.assertEqual(observed.manifest['data'][c.relation_key('public',name)]['rows'],1)
        query,params=next((sql,params) for sql,params in self.db.commands if sql.startswith('DECLARE') and c.quote(name) in sql)
        self.assertIsNone(params);self.assertIn(c.quote(name),query)
        c.compare(observed,copy.deepcopy(observed),self.mapping(observed),fingerprint_key=KEY)

    def test_parent_namespace_components_cannot_alias_in_schema_fingerprints(self):
        self.db.catalog['relations'][0]['parents']=[['a.b','c']]
        old=self.collect();self.db=Connection();self.db.catalog['relations'][0]['parents']=[['a','b.c']]
        new=self.collect()
        with self.assertRaises(c.CensusRejected):c.compare(new,old,self.mapping(old),fingerprint_key=KEY)

    def test_dropped_column_tombstones_are_facts_not_active_row_columns(self):
        self.db.catalog['columns'].append(dict(schema='public',table='accounts_user',name='....pg.dropped.3....',
            position=3,type='-',type_schema=None,type_oid=0,generated='',dropped=True))
        observed=self.collect()
        self.assertTrue(observed.receipt['complete_supported_data'])
        self.assertTrue(any(v['dropped'] for v in observed.manifest['catalog']['columns']))
        c.compare(observed,copy.deepcopy(observed),self.mapping(observed),fingerprint_key=KEY)

    def test_interruption_and_unknown_begin_result_always_attempt_rollback(self):
        original=copy.deepcopy(self.db.data)
        self.db.fail='BEGIN'
        with self.assertRaises(c.CensusRejected):self.collect()
        self.assertEqual(self.db.commands[-1][0],'ROLLBACK')
        self.setUp()
        with patch.object(self.db.cursor_instance,'fetchall',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.collect()
        self.assertEqual(self.db.commands[-1][0],'ROLLBACK');self.assertTrue(self.db.cursor_instance.closed)
        self.assertEqual(self.db.data,original)

    def test_ambiguous_qualified_relation_names_cannot_overwrite_each_other(self):
        self.assertNotEqual(c.relation_key('a.b','c'),c.relation_key('a','b.c'))
        self.db.catalog['relations'].append(copy.deepcopy(self.db.catalog['relations'][0]))
        with self.assertRaises(c.CensusRejected):self.collect()

    def test_migration_adapter_preserves_disk_graph_and_rejects_unmapped_applied_records(self):
        from types import ModuleType
        class Migration:
            dependencies=[];run_before=[];replaces=[]
        class Loader:
            checked=False
            def __init__(self,connection,ignore_no_migrations):
                self.applied_migrations={('accounts','0001_initial'):None}
                self.disk_migrations={('accounts','0001_initial'):Migration()}
                self.graph=NS(node_map={('accounts','0001_initial'):NS(parents=[])})
                self.migrated_apps={'accounts'};self.unmigrated_apps={'base'}
            def check_consistent_history(self,connection):Loader.checked=True
        mods={name:ModuleType(name) for name in ('django','django.db','django.db.migrations','django.db.migrations.loader')}
        mods['django.db.migrations.loader'].MigrationLoader=Loader
        mods['django.db'].connections={'default':self.db}
        records=self.db.data['django_migrations']
        with patch.dict(sys.modules,mods):
            manifest=c.migration_manifest(self.db,records)
            self.assertTrue(Loader.checked);self.assertEqual(manifest['graph'][0]['parents'],[])
            self.assertEqual(manifest['applied'],records);self.assertEqual(len(manifest['disk'][0]['sha256']),64)
            for bad in (records+records,[dict(records[0],name='unknown')]):
                with self.assertRaises(c.CensusRejected):c.migration_manifest(self.db,bad)

    def test_keyed_fingerprints_preserve_duplicates_and_ignore_only_row_order(self):
        before=self.collect();self.db=Connection();self.db.data['accounts_user'].reverse();after=self.collect()
        self.assertEqual(before.manifest,after.manifest)
        self.db=Connection();self.db.data['accounts_user'].append(copy.deepcopy(self.db.data['accounts_user'][0]));extra=self.collect()
        self.assertNotEqual(before.manifest['data'],extra.manifest['data'])
        self.assertNotEqual(c.keyed(KEY,'row',{'a':1}),c.keyed(b'x'*32,'row',{'a':1}))
    def test_limits_are_failure_not_truncation_and_rollback_redacts(self):
        for limits in (c.Limits(rows=1),c.Limits(facts=1),c.Limits(bytes=20,value_bytes=20),c.Limits(value_bytes=20)):
            self.setUp()
            with self.assertRaises(c.CensusRejected) as caught:self.collect(limits=limits)
            self.assertNotIn('confidential',str(caught.exception));self.assertEqual(self.db.commands[-1][0],'ROLLBACK')
        for field in ('rows','facts','bytes','value_bytes','seconds','statement_ms','lock_ms'):
            with self.assertRaises(c.CensusRejected):c.Limits(**{field:0})
        self.setUp();self.db.fail='FETCH'
        with self.assertRaises(c.CensusRejected) as caught:self.collect()
        self.assertNotIn('credential',str(caught.exception));self.assertEqual(self.db.commands[-1][0],'ROLLBACK')
    def test_deadline_or_rollback_error_never_returns_success_or_raw_diagnostics(self):
        ticks=iter([0,0,0,1000])
        with self.assertRaises(c.CensusRejected):self.collect(clock=lambda:next(ticks))
        self.setUp();self.db.fail='ROLLBACK'
        with self.assertRaises(c.CensusRejected) as caught:self.collect()
        self.assertNotIn('credential',str(caught.exception));self.assertTrue(self.db.cursor_instance.closed)
    def test_schema_identifiers_are_quoted_not_sql_interpolated_unsafely(self):
        self.assertEqual(c.quote('odd";DROP TABLE x;--'),'"odd"";DROP TABLE x;--"')
        with self.assertRaises(c.CensusRejected):c.quote('bad\0name')
    def test_canonical_precision_and_ambiguity_bounds(self):
        import decimal
        value=decimal.Decimal('123456789012345678901234567890.00001')
        self.assertNotEqual(c.encoded(value),c.encoded(decimal.Decimal('123456789012345678901234567890.00002')))
        self.assertNotEqual(c.encoded(True),c.encoded(1));self.assertNotEqual(c.encoded(None),c.encoded('null'))
        with self.assertRaises(c.CensusRejected):c.encoded(float('inf'))

if __name__=='__main__':unittest.main()
