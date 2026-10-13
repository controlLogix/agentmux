import json,pathlib,sqlite3
root=pathlib.Path(__file__).resolve().parent
fixture=json.loads((root/'fixture.json').read_text())
db=pathlib.Path(fixture['state'])/'hub/hub.db'
actor='calc-worker-codex_1009';task='W-20B5K44YJT'
connection=sqlite3.connect(db.as_uri()+'?mode=ro',uri=True)
connection.row_factory=sqlite3.Row
connection.execute('PRAGMA query_only=ON')
rows=connection.execute('SELECT seq,at,entity,entity_id,event,actor FROM events WHERE seq IN (12,13,15) ORDER BY seq').fetchall()
assert len(rows)==3
records=[]
for row in rows:
 item=dict(row)
 if row['seq']==12:
  assert row['entity']=='delivery' and row['event']=='acked' and row['entity_id'].endswith('>'+actor)
  item['recipient']=actor
 else:
  assert row['entity']=='work' and row['entity_id']==task and row['actor']==actor
  assert row['event']==('claimed' if row['seq']==13 else 'done')
 records.append(item)
work=connection.execute('SELECT id,state,claimed_by,result FROM work_items WHERE id=?',(task,)).fetchone()
assert work['state']=='done' and work['claimed_by']==actor
connection.close()
proof={'scope':'Read-only original hub delivery acknowledgment, task claim and completion for this exact calibration.','events':records,'done':dict(work)}
(root/'callback-evidence.json').write_text(json.dumps(proof,indent=2)+'\n')
print(json.dumps(proof,indent=2))